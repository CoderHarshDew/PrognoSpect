from __future__ import annotations
from collections import Counter, defaultdict, deque
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Deque, Dict, Iterable, Iterator, List, Optional, Tuple
import math
from src.core.config import config_loader
from src.core.evaluator import bind_var_and_evaluate, compile_expr
from src.core.logger import logger

GroupKey = Tuple[Any, ...]
DEFAULT_CONFIG_PATH = "config/extraction/cross_flow_behavioral_feature_extractor.yaml"


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


def _sequentiality_stats(values: List[Any], min_run_edges: int) -> Optional[Dict[str, int]]:
    if len(values) < 2:
        return None
    diffs = []
    for i in range(len(values) - 1):
        try:
            diffs.append(values[i + 1] - values[i])
        except TypeError:
            diffs.append(None)
    valid = [d is not None and abs(d) == 1 for d in diffs]

    transition_participants = set()
    for i, is_valid in enumerate(valid):
        if is_valid:
            transition_participants.add(i)
            transition_participants.add(i + 1)
    if not transition_participants:
        return None

    run_participants = set()
    i, n = 0, len(diffs)
    while i < n:
        if not valid[i]:
            i += 1
            continue
        j = i
        while j + 1 < n and valid[j + 1] and diffs[j + 1] == diffs[j]:
            j += 1
        if (j - i + 1) >= min_run_edges:
            for k in range(i, j + 2):
                run_participants.add(k)
        i = j + 1

    return {"run_length": len(run_participants), "total_transitions": len(transition_participants)}


def _compute_statistic(spec: Dict[str, Any], history: List[Tuple[float, Any]], statistics: Dict[str, Any]) -> Optional[Dict[str, Any]]:
    if not history:
        return None
    kind = spec["type"]
    values = [value for _, value in history]
    if kind == "unique_count":
        return {"count": len(set(values))}
    if kind == "span_rate":
        n = len(set(values)) if spec["count_mode"] == "unique" else len(values)
        t_first, t_last = history[0][0], history[-1][0]
        duration = max(t_last - t_first, statistics["minimum_duration_seconds"])
        return {"N": n, "duration": duration}
    if kind == "entropy":
        total = len(values)
        log_base = statistics["entropy_log_base"]
        entropy_sum = sum((c / total) * math.log(c / total, log_base) for c in Counter(values).values())
        return {"entropy_sum": entropy_sum}
    if kind == "sequentiality":
        return _sequentiality_stats(values, statistics["sequentiality_min_run_edges"])
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
        self._history: Dict[str, Dict[GroupKey, Deque[Tuple[float, Any]]]] = {name: defaultdict(deque) for name in self.streams}
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
            self._history[stream.name][group_key].append((obs["timestamp"], value))

    def _evict(self, stream_name: str, group_key: GroupKey, min_ts: float) -> None:
        history = self._history[stream_name].get(group_key)
        while history and history[0][0] < min_ts:
            history.popleft()

    def _compute_features(self, obs: Dict[str, Any]) -> Dict[str, Any]:
        min_ts = obs["timestamp"] - self.window_seconds
        histories: Dict[str, List[Tuple[float, Any]]] = {}
        for stream in self.streams.values():
            group_key = tuple(obs[field_name] for field_name in stream.group_by)
            self._evict(stream.name, group_key, min_ts)
            histories[stream.name] = list(self._history[stream.name].get(group_key, ()))

        features: Dict[str, Any] = {}
        for feature in self.features:
            stats = _compute_statistic(feature.statistic, histories[feature.stream], self.statistics)
            if stats is None:
                features[feature.name] = feature.missing_value
                continue
            formula_ctx = self._resolve_scalar_operands(feature.formula.requires, stats)
            features[feature.name] = bind_var_and_evaluate(feature.formula.expr, **formula_ctx)
        return features

    def extract(self, packets: Iterable[Any]) -> Iterator[Dict[str, Any]]:
        for packet in packets:
            obs = self._build_observation(packet)
            ts = obs["timestamp"]
            if self._pending_ts is not None and ts < self._pending_ts:
                raise ValueError(
                    f"non-monotonic timestamp encountered: {ts} is earlier than "
                    f"the previously seen {self._pending_ts}; extract() requires "
                    f"packets in non-decreasing timestamp order"
                )
            self._flush_pending(ts)
            record = {field_name: obs[field_name] for field_name in self.flow_id_columns}
            record.update(self._compute_features(obs))
            yield record
            self._pending.append(obs)
            self._pending_ts = ts