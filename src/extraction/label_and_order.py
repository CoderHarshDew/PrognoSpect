import csv
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
PROTOCOL_COL = _label_and_order_cfg['protocol_col']

VALID_PROTOCOLS = set(_label_and_order_cfg['valid_protocols'])
TIMESTAMP_FORMAT = _label_and_order_cfg['timestamp_format']


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


def classify_flow(src_ip, dst_ip, protocol, timestamp, schedule):
    confident = []
    boundary = []
    ip_only = []

    for entry in schedule:
        is_pair = (
            (src_ip in entry["attacker_ips"] and dst_ip in entry["victim_ips"])
            or (dst_ip in entry["attacker_ips"] and src_ip in entry["victim_ips"])
        )
        if not is_pair:
            continue

        if entry["confidence"] in ("high", "medium") and entry["protocol_hint"] is not None:
            if protocol != entry["protocol_hint"]:
                continue

        if entry["start_dt"] <= timestamp <= entry["finish_dt"]:
            confident.append(entry)
        elif entry["boundary_start"] <= timestamp < entry["start_dt"] or entry["finish_dt"] < timestamp <= entry["boundary_finish"]:
            boundary.append(entry)
        else:
            ip_only.append(entry)

    if len(confident) == 1 and not boundary:
        return confident[0]["attack_name"], True

    if confident or boundary:
        return None, False

    if ip_only:
        return None, False

    return "Benign", True


def label_and_order(input_path: Path, schedule_path: Path, output_path: Path):
    schedule = load_schedule(schedule_path)
    header = read_header(input_path)

    ts_i = header.index(TIMESTAMP_COL)
    src_i = header.index(SRC_IP_COL)
    dst_i = header.index(DST_IP_COL)
    proto_i = header.index(PROTOCOL_COL)

    sorted_path = sort_merged_csv(input_path, header)

    counts = {"dropped": 0}

    with open(sorted_path, "r", newline="") as src_f, open(output_path, "w", newline="") as out_f:
        reader = csv.reader(src_f)
        writer = csv.writer(out_f)
        writer.writerow(header + ["Label"])

        for row in reader:
            protocol = row[proto_i]
            if protocol not in VALID_PROTOCOLS:
                counts["dropped"] += 1
                continue

            timestamp = datetime.strptime(row[ts_i], TIMESTAMP_FORMAT)
            label, keep = classify_flow(
                row[src_i], row[dst_i], int(protocol), timestamp, schedule
            )

            if not keep:
                counts["dropped"] += 1
                continue

            counts[label] = counts.get(label, 0) + 1
            writer.writerow(row + [label])

    sorted_path.unlink()

    kept = sum(v for k, v in counts.items() if k != "dropped")
    print(f"Done. Kept: {kept}, Dropped: {counts['dropped']}", file=sys.stderr)
    for label, n in sorted(counts.items()):
        if label != "dropped":
            print(f"  {label}: {n}", file=sys.stderr)