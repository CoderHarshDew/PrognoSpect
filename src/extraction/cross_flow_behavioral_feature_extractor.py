from __future__ import annotations
from collections import defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Deque, Dict, Iterable, Iterator, List, Optional, Sequence, Set, Tuple
import math
import time
from src.core.config import config_loader
from src.core.evaluator import bind_var_and_evaluate, compile_expr
from src.core.logger import logger

GroupKey = Tuple[Any, ...]
DEFAULT_CONFIG_PATH = "config/extraction/cross_flow_behavioral_feature_extractor.yaml"
PROGRESS_EVERY_OBSERVATIONS = 100_000
PROGRESS_EVERY_SECONDS = 60.0
ENTROPY_RECOMPUTE_EVERY = 100000
_STAGE_SECONDS: Dict[str, float] = defaultdict(float)


@dataclass
class _Formula:
    expr: Any
    requires: List[str]


@dataclass
class _HistoricalStream:
    name: str
    group_by: List[str]
    eligibility: _Formula
    value: Optional[_Formula]


@dataclass
class _Feature:
    name: str
    stream: str
    statistic: Dict[str, Any]
    missing_value: Optional[float]
    formula: _Formula


def _compile_formula(spec: Dict[str, Any]) -> _Formula:
    return _Formula(expr=compile_expr(spec["expression"]), requires=spec["requires"])


def _get_field(packet: Any, name: str) -> Optional[Any]:
    if isinstance(packet, dict):
        return packet.get(name)
    return getattr(packet, name, None)


def _derive_needs(specs: Iterable[Dict[str, Any]]) -> Set[str]:
    needs: Set[str] = set()
    for spec in specs:
        kind = spec["type"]
        if kind == "unique_count" or (kind == "span_rate" and spec["count_mode"] == "unique"):
            needs.add("counts")
        elif kind == "entropy":
            needs.update(("counts", "entropy"))
        elif kind == "sequentiality":
            needs.add("runs")
    return needs


def _state_new(needs: Set[str]) -> Dict[str, Any]:
    return {
        "counts": {} if "counts" in needs else None,
        "entropy": "entropy" in needs,
        "clogc": 0.0,
        "updates": 0,
        "runs": deque() if "runs" in needs else None,
        "t_sum": 0,
        "t_adj": 0,
        "r_sum": 0,
        "r_adj": 0,
    }


def _xlogx(c: int) -> float:
    return c * math.log(c) if c > 0 else 0.0


def _entropy_tick(state: Dict[str, Any]) -> None:
    state["updates"] += 1
    if state["updates"] >= ENTROPY_RECOMPUTE_EVERY:
        state["clogc"] = sum(_xlogx(c) for c in state["counts"].values())
        state["updates"] = 0


def _seq_contrib(runs: Sequence[List[Any]], min_run_edges: int) -> Tuple[int, int, int, int]:
    t_sum = t_adj = r_sum = r_adj = 0
    prev_valid = prev_qualifying = False
    for diff, edges in runs:
        valid = diff is not None
        qualifying = valid and edges >= min_run_edges
        if valid:
            t_sum += edges + 1
            if prev_valid:
                t_adj += 1
        if qualifying:
            r_sum += edges + 1
            if prev_qualifying:
                r_adj += 1
        prev_valid, prev_qualifying = valid, qualifying
    return t_sum, t_adj, r_sum, r_adj


def _seq_shift(state: Dict[str, Any], before: Tuple[int, int, int, int], after: Tuple[int, int, int, int]) -> None:
    state["t_sum"] += after[0] - before[0]
    state["t_adj"] += after[1] - before[1]
    state["r_sum"] += after[2] - before[2]
    state["r_adj"] += after[3] - before[3]


def _runs_append(state: Dict[str, Any], prev: Any, value: Any, min_run_edges: int) -> None:
    runs = state["runs"]
    try:
        diff = value - prev
    except TypeError:
        diff = None
    key = diff if diff is not None and abs(diff) == 1 else None
    start = max(0, len(runs) - 2)
    before = _seq_contrib([runs[i] for i in range(start, len(runs))], min_run_edges)
    if runs and runs[-1][0] == key:
        runs[-1][1] += 1
    else:
        runs.append([key, 1])
    after = _seq_contrib([runs[i] for i in range(start, len(runs))], min_run_edges)
    _seq_shift(state, before, after)


def _runs_pop_front(state: Dict[str, Any], min_run_edges: int) -> None:
    runs = state["runs"]
    width = min(2, len(runs))
    before = _seq_contrib([runs[i] for i in range(width)], min_run_edges)
    runs[0][1] -= 1
    if runs[0][1] == 0:
        runs.popleft()
        width -= 1
    after = _seq_contrib([runs[i] for i in range(width)], min_run_edges)
    _seq_shift(state, before, after)


def _state_add(state: Dict[str, Any], prev: Any, has_prev: bool, value: Any, min_run_edges: int) -> None:
    counts = state["counts"]
    if counts is not None:
        c = counts.get(value, 0)
        counts[value] = c + 1
        if state["entropy"]:
            state["clogc"] += _xlogx(c + 1) - _xlogx(c)
            _entropy_tick(state)
    if state["runs"] is not None and has_prev:
        _runs_append(state, prev, value, min_run_edges)


def _state_remove(state: Dict[str, Any], value: Any, has_next: bool, min_run_edges: int) -> None:
    counts = state["counts"]
    if counts is not None:
        c = counts[value]
        if c == 1:
            del counts[value]
        else:
            counts[value] = c - 1
        if state["entropy"]:
            if counts:
                state["clogc"] += _xlogx(c - 1) - _xlogx(c)
                _entropy_tick(state)
            else:
                state["clogc"] = 0.0
                state["updates"] = 0
    if state["runs"] is not None and has_next:
        _runs_pop_front(state, min_run_edges)


def _sequentiality_from_state(state: Dict[str, Any]) -> Optional[Dict[str, int]]:
    total_transitions = state["t_sum"] - state["t_adj"]
    if total_transitions == 0:
        return None
    return {"run_length": state["r_sum"] - state["r_adj"], "total_transitions": total_transitions}


def _longest_history(history: Dict[str, Dict[GroupKey, Deque[Tuple[float, Any]]]]) -> Tuple[int, Optional[str], Optional[GroupKey]]:
    longest: Tuple[int, Optional[str], Optional[GroupKey]] = (0, None, None)
    for stream_name, groups in history.items():
        for group_key, entries in groups.items():
            if len(entries) > longest[0]:
                longest = (len(entries), stream_name, group_key)
    return longest


def _stage_summary() -> str:
    summary = ", ".join(f"{name}={seconds:.2f}s" for name, seconds in sorted(_STAGE_SECONDS.items()))
    _STAGE_SECONDS.clear()
    return summary


def _compute_statistic(spec: Dict[str, Any], history: Sequence[Tuple[float, Any]], statistics: Dict[str, Any], state: Optional[Dict[str, Any]]) -> Optional[Dict[str, Any]]:
    if not history:
        return None
    kind = spec["type"]
    if kind == "unique_count":
        return {"count": len(state["counts"])}
    if kind == "span_rate":
        n = len(state["counts"]) if spec["count_mode"] == "unique" else len(history)
        t_first, t_last = history[0][0], history[-1][0]
        duration = max(t_last - t_first, statistics["minimum_duration_seconds"])
        return {"N": n, "duration": duration}
    if kind == "entropy":
        total = len(history)
        entropy_sum = (state["clogc"] - total * math.log(total)) / (total * math.log(statistics["entropy_log_base"]))
        return {"entropy_sum": entropy_sum}
    if kind == "sequentiality":
        return _sequentiality_from_state(state)
    logger.error("unknown statistic type: %s", kind)
    raise ValueError(f"unknown statistic type: {kind}")


class CrossFlowBehavioralFeatureExtractor:

    def __init__(self, config_path: str = DEFAULT_CONFIG_PATH):
        self.config = config_loader(config_path)
        self.field_mapping: Dict[str, str] = self.config["input_field_mapping"]
        self.window_seconds: float = self.config["temporal"]["window_seconds"]
        self.constants: Dict[str, Any] = self.config.get("constants", {})
        self.statistics: Dict[str, Any] = self.config["statistics"]
        self.streams: Dict[str, _HistoricalStream] = {s["name"]: self._load_stream(s) for s in self.config["historical_streams"]}
        self.features: List[_Feature] = [self._load_feature(f) for f in self.config["features"]]
        self.output_columns: List[str] = self.config["output_feature_columns"]
        self.flow_id_columns: List[str] = self.config["flow_identification_columns"]
        self._needs: Dict[str, Set[str]] = {name: _derive_needs([f.statistic for f in self.features if f.stream == name]) for name in self.streams}
        self._min_run_edges: int = self.statistics["sequentiality_min_run_edges"] if any("runs" in needs for needs in self._needs.values()) else 0
        self._history: Dict[str, Dict[GroupKey, Deque[Tuple[float, Any]]]] = {name: defaultdict(deque) for name in self.streams}
        self._state: Dict[str, Dict[GroupKey, Dict[str, Any]]] = {name: {} for name in self.streams}
        self._pending: List[Dict[str, Any]] = []
        self._pending_ts: Optional[float] = None
        logger.debug("loaded %d historical streams and %d features", len(self.streams), len(self.features))

    def _load_stream(self, spec: Dict[str, Any]) -> _HistoricalStream:
        return _HistoricalStream(
            name=spec["name"], group_by=spec["group_by"],
            eligibility=_compile_formula(spec["eligibility"]),
            value=_compile_formula(spec["value"]) if "value" in spec else None,
        )

    def _load_feature(self, spec: Dict[str, Any]) -> _Feature:
        return _Feature(
            name=spec["name"], stream=spec["stream"], statistic=spec["statistic"],
            missing_value=spec.get("missing_value"), formula=_compile_formula(spec["formula"]),
        )

    def _resolve_scalar_operands(self, requires: List[str], scalars: Dict[str, Any]) -> Dict[str, Any]:
        resolved: Dict[str, Any] = {}
        for name in requires:
            if name in scalars:
                resolved[name] = scalars[name]
            elif name in self.constants:
                resolved[name] = self.constants[name]
            else:
                logger.error("required operand '%s' is neither an observation field nor a configured constant", name)
                raise KeyError(f"required operand '{name}' is neither an observation field nor a configured constant")
        return resolved

    def _has_missing_operand(self, requires: List[str], obs: Dict[str, Any]) -> bool:
        for name in requires:
            if name in obs and obs[name] is None:
                return True
        return False

    def _build_observation(self, packet: Any) -> Dict[str, Any]:
        obs = {logical: _get_field(packet, source) for logical, source in self.field_mapping.items()}
        for logical, source in self.field_mapping.items():
            if obs[logical] is None:
                logger.warning("field_mapping produced None for logical=%r source=%r packet_type=%r", logical, source, type(packet).__name__)
        ts = obs.get("timestamp")
        if isinstance(ts, datetime):
            obs["timestamp"] = ts.timestamp()
        return obs

    def _flush_pending(self, current_ts: float) -> None:
        if self._pending_ts is not None and self._pending_ts < current_ts:
            for obs in self._pending:
                self._commit(obs)
            self._pending = []
            self._pending_ts = None

    def _commit(self, obs: Dict[str, Any]) -> None:
        for stream in self.streams.values():
            if self._has_missing_operand(stream.eligibility.requires, obs):
                continue
            eligible_ctx = self._resolve_scalar_operands(stream.eligibility.requires, obs)
            if not bool(bind_var_and_evaluate(stream.eligibility.expr, **eligible_ctx)):
                continue
            value = None
            if stream.value is not None:
                if self._has_missing_operand(stream.value.requires, obs):
                    continue
                value_ctx = self._resolve_scalar_operands(stream.value.requires, obs)
                value = bind_var_and_evaluate(stream.value.expr, **value_ctx)
            group_key = tuple(obs[field_name] for field_name in stream.group_by)
            if any(component is None for component in group_key):
                continue
            history = self._history[stream.name][group_key]
            state = self._state[stream.name].get(group_key)
            if state is None:
                state = self._state[stream.name][group_key] = _state_new(self._needs[stream.name])
            _state_add(state, history[-1][1] if history else None, bool(history), value, self._min_run_edges)
            history.append((obs["timestamp"], value))

    def _evict(self, stream_name: str, group_key: GroupKey, min_ts: float) -> None:
        history = self._history[stream_name].get(group_key)
        state = self._state[stream_name].get(group_key)
        while history and history[0][0] < min_ts:
            value = history.popleft()[1]
            _state_remove(state, value, bool(history), self._min_run_edges)

    def _compute_features(self, obs: Dict[str, Any]) -> Dict[str, Any]:
        min_ts = obs["timestamp"] - self.window_seconds
        histories: Dict[str, Sequence[Tuple[float, Any]]] = {}
        states: Dict[str, Optional[Dict[str, Any]]] = {}
        stage_started = time.perf_counter()
        for stream in self.streams.values():
            group_key = tuple(obs[field_name] for field_name in stream.group_by)
            self._evict(stream.name, group_key, min_ts)
            histories[stream.name] = self._history[stream.name].get(group_key, ())
            states[stream.name] = self._state[stream.name].get(group_key)
        _STAGE_SECONDS["evict_and_copy"] += time.perf_counter() - stage_started

        features: Dict[str, Any] = {}
        for feature in self.features:
            stage_started = time.perf_counter()
            stats = _compute_statistic(feature.statistic, histories[feature.stream], self.statistics, states[feature.stream])
            _STAGE_SECONDS[f"statistic_{feature.statistic['type']}"] += time.perf_counter() - stage_started
            if stats is None:
                features[feature.name] = feature.missing_value
                continue
            stage_started = time.perf_counter()
            formula_ctx = self._resolve_scalar_operands(feature.formula.requires, stats)
            features[feature.name] = bind_var_and_evaluate(feature.formula.expr, **formula_ctx)
            _STAGE_SECONDS["formula"] += time.perf_counter() - stage_started
        return features

    def extract(self, packets: Iterable[Any]) -> Iterator[Dict[str, Any]]:
        run_started = time.perf_counter()
        last_report = run_started
        last_report_count = 0
        count = 0
        logger.info("[cross-flow] extract started")
        for packet in packets:
            obs = self._build_observation(packet)
            ts = obs["timestamp"]
            if self._pending_ts is not None and ts < self._pending_ts:
                logger.error("non-monotonic timestamp encountered: %s is earlier than previously seen %s", ts, self._pending_ts)
                raise ValueError(
                    f"non-monotonic timestamp encountered: {ts} is earlier than "
                    f"the previously seen {self._pending_ts}; extract() requires "
                    f"packets in non-decreasing timestamp order"
                )
            stage_started = time.perf_counter()
            self._flush_pending(ts)
            _STAGE_SECONDS["commit_pending"] += time.perf_counter() - stage_started
            record = {field_name: obs[field_name] for field_name in self.flow_id_columns}
            record.update(self._compute_features(obs))
            yield record
            self._pending.append(obs)
            self._pending_ts = ts
            count += 1
            now = time.perf_counter()
            if count % PROGRESS_EVERY_OBSERVATIONS == 0 or now - last_report >= PROGRESS_EVERY_SECONDS:
                longest_size, longest_stream, longest_group = _longest_history(self._history)
                logger.info(
                    "[cross-flow] observations=%d block_rows=%d block_seconds=%.1f total_seconds=%.1f longest_history=%d stream=%s group=%s stages: %s",
                    count, count - last_report_count, now - last_report, now - run_started,
                    longest_size, longest_stream, longest_group, _stage_summary()
                )
                last_report = now
                last_report_count = count
        logger.info("[cross-flow] extract finished observations=%d total_seconds=%.1f stages: %s", count, time.perf_counter() - run_started, _stage_summary())