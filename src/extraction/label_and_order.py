import csv
import os
import sys
from datetime import datetime
from pathlib import Path

from src.core.config import config_loader
from src.extraction.schedule import load_schedule

GLOBAL_CFG_PATH = Path('config/global_configurations.yaml')

_global_cfg = config_loader(GLOBAL_CFG_PATH)
LABEL_AND_ORDER_CFG_PATH = Path(_global_cfg['config_paths']['label_and_order'])
_label_and_order_cfg = config_loader(LABEL_AND_ORDER_CFG_PATH)

TIMESTAMP_COL = _label_and_order_cfg['timestamp_col']
FLOW_ID_COL = _label_and_order_cfg['flow_id_col']
SRC_IP_COL = _label_and_order_cfg['src_ip_col']
DST_IP_COL = _label_and_order_cfg['dst_ip_col']
DST_PORT_COL = _label_and_order_cfg['dst_port_col']
PROTOCOL_COL = _label_and_order_cfg['protocol_col']
LABEL_COL = _label_and_order_cfg['label_col']
PAYLOAD_FWD_COL = _label_and_order_cfg['payload_length_fwd_col']

VALID_PROTOCOLS = set(_label_and_order_cfg['valid_protocols'])
TIMESTAMP_FORMAT = _label_and_order_cfg['timestamp_format']
DEFAULT_LABEL = _label_and_order_cfg['default_label']
ARTIFACT_FLOW_IDS = set(_label_and_order_cfg.get('artifact_flow_ids', []))


def read_header(csv_path: Path):
    with open(csv_path, "r", newline="") as f:
        return next(csv.reader(f))


def sort_merged_csv(input_path: Path, header: list) -> Path:
    ts_i = header.index(TIMESTAMP_COL)
    flow_i = header.index(FLOW_ID_COL)

    entries = []

    with open(input_path, "rb") as f:
        f.readline()

        offset = f.tell()
        line = f.readline()
        while line:
            length = len(line)
            row = next(csv.reader([line.decode("utf-8")]))
            entries.append((row[ts_i], row[flow_i], offset, length))

            offset += length
            line = f.readline()

    entries.sort(key=lambda entry: (entry[0], entry[1]))

    sorted_path = input_path.with_suffix(".sorted.tmp")

    with open(input_path, "rb") as src, open(sorted_path, "wb") as out:
        for _, _, offset, length in entries:
            src.seek(offset)
            out.write(src.read(length))

    return sorted_path


def _parse_timestamp(value: str, timestamp_format: str) -> datetime:
    try:
        return datetime.strptime(value, timestamp_format)
    except ValueError:
        if '.' in timestamp_format and '.' not in value:
            fallback_format = timestamp_format.split('.')[0]
            return datetime.strptime(value, fallback_format)
        raise


_OPS = {
    "eq": lambda a, b: a == b,
    "ne": lambda a, b: a != b,
    "gt": lambda a, b: a > b,
    "gte": lambda a, b: a >= b,
    "lt": lambda a, b: a < b,
    "lte": lambda a, b: a <= b,
    "in": lambda a, b: a in b,
    "not_in": lambda a, b: a not in b,
}


def _eval_condition(cond: dict, row: list, header_index: dict) -> bool:
    if "any_of" in cond:
        return any(_eval_condition(sub, row, header_index) for sub in cond["any_of"])
    if "all_of" in cond:
        return all(_eval_condition(sub, row, header_index) for sub in cond["all_of"])

    feature_i = header_index[cond["feature"]]
    op = _OPS[cond["op"]]
    value = cond["value"]
    raw = row[feature_i]

    try:
        actual = raw if isinstance(value, str) else float(raw)
    except (TypeError, ValueError):
        return False

    return op(actual, value)


def rule_matches(rule: dict, row: list, header_index: dict, src_ip: str, dst_ip: str,
                  dst_port: int, protocol: int, timestamp: datetime) -> bool:
    if not (rule["start_dt"] <= timestamp <= rule["finish_dt"]):
        return False
    if rule["src_ips"] is not None and src_ip not in rule["src_ips"]:
        return False
    if rule["dst_ips"] is not None and dst_ip not in rule["dst_ips"]:
        return False
    if rule["dst_ports"] is not None and dst_port not in rule["dst_ports"]:
        return False
    if rule["protocol"] is not None and protocol != rule["protocol"]:
        return False

    if rule["payload_filter"]:
        try:
            if float(row[header_index[PAYLOAD_FWD_COL]]) != 0:
                return False
        except (TypeError, ValueError):
            return False

    for cond in rule["extra_conditions"]:
        if not _eval_condition(cond, row, header_index):
            return False

    return True


def classify_flow(row: list, header_index: dict, rules: list, src_ip: str, dst_ip: str,
                   dst_port: int, protocol: int, timestamp: datetime) -> str:
    label = DEFAULT_LABEL
    for rule in rules:
        if rule_matches(rule, row, header_index, src_ip, dst_ip, dst_port, protocol, timestamp):
            label = rule["label"]
    return label


def label_and_order(input_path: Path, schedule_path: Path, output_path: Path):
    rules = load_schedule(schedule_path)

    header = read_header(input_path)
    header_index = {name: i for i, name in enumerate(header)}

    ts_i = header_index[TIMESTAMP_COL]
    flow_id_i = header_index[FLOW_ID_COL]
    src_i = header_index[SRC_IP_COL]
    dst_i = header_index[DST_IP_COL]
    dst_port_i = header_index[DST_PORT_COL]
    proto_i = header_index[PROTOCOL_COL]
    label_i = header_index.get(LABEL_COL)
    if label_i is None:
        header = header + [LABEL_COL]
        label_i = len(header) - 1

    sorted_path = sort_merged_csv(input_path, header)

    counts = {"protocol_dropped": 0}
    temp_output_path = output_path.with_name(output_path.name + '.tmp')

    try:
        with open(sorted_path, "r", newline="") as src_f, open(temp_output_path, "w", newline="") as out_f:
            reader = csv.reader(src_f)
            writer = csv.writer(out_f)
            writer.writerow(header)

            for row in reader:
                protocol_raw = row[proto_i]
                if protocol_raw not in VALID_PROTOCOLS:
                    counts["protocol_dropped"] += 1
                    continue

                if row[flow_id_i] in ARTIFACT_FLOW_IDS:
                    label = DEFAULT_LABEL
                else:
                    timestamp = _parse_timestamp(row[ts_i], TIMESTAMP_FORMAT)
                    dst_port = int(row[dst_port_i])
                    protocol = int(protocol_raw)
                    label = classify_flow(
                        row, header_index, rules,
                        row[src_i], row[dst_i], dst_port, protocol, timestamp,
                    )

                if label_i < len(row):
                    row[label_i] = label
                else:
                    row.append(label)
                counts[label] = counts.get(label, 0) + 1
                writer.writerow(row)

        os.replace(temp_output_path, output_path)

    finally:
        if temp_output_path.exists():
            temp_output_path.unlink()

    sorted_path.unlink()

    kept = sum(v for k, v in counts.items() if k != "protocol_dropped")
    print(f"Done. Kept: {kept}, Protocol-dropped: {counts['protocol_dropped']}", file=sys.stderr)
    for label, n in sorted(counts.items()):
        if label != "protocol_dropped":
            print(f"  {label}: {n}", file=sys.stderr)