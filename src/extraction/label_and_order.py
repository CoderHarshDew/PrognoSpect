import csv
import os
import subprocess
import sys
from datetime import datetime
from pathlib import Path

from schedule import load_schedule

TIMESTAMP_COL = "Timestamp"
FLOW_ID_COL = "Flow ID"
SRC_IP_COL = "Source IP"
DST_IP_COL = "Destination IP"
PROTOCOL_COL = "Protocol"

VALID_PROTOCOLS = {"6", "17"}  # TCP, UDP only — everything else is dropped
TIMESTAMP_FORMAT = "%Y-%m-%d %H:%M:%S.%f"


def read_header(csv_path: Path):
    with open(csv_path, "r", newline="") as f:
        return next(csv.reader(f))


def sort_merged_csv(input_path: Path, header: list) -> Path:
    """Sorts the CSV body (header stripped) by Timestamp then Flow ID using
    GNU sort, so it scales to files far larger than available RAM. Returns
    the path to the sorted body (no header)."""
    ts_idx = header.index(TIMESTAMP_COL) + 1  # `sort -k` is 1-based
    flow_idx = header.index(FLOW_ID_COL) + 1

    body_path = input_path.with_suffix(".body.tmp")
    with open(input_path, "r") as src, open(body_path, "w") as dst:
        next(src)  # skip header
        dst.writelines(src)

    sorted_path = input_path.with_suffix(".sorted.tmp")
    env = dict(os.environ)
    env["LC_ALL"] = "C"  # byte-order sort: matches the sortable timestamp format

    with open(sorted_path, "w") as out:
        subprocess.run(
            [
                "sort",
                "-t,",
                f"-k{ts_idx},{ts_idx}",
                f"-k{flow_idx},{flow_idx}",
                str(body_path),
            ],
            stdout=out,
            check=True,
            env=env,
        )

    body_path.unlink()
    return sorted_path


def classify_flow(src_ip, dst_ip, protocol, timestamp, schedule):
    """Returns (label, keep). Strict binary: an ambiguous flow is always
    dropped (label=None, keep=False), never flagged-but-kept."""
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
        # multiple confident matches, or a confident+boundary overlap,
        # or boundary-only matches -> genuinely ambiguous
        return None, False

    if ip_only:
        # known attacker/victim pair, but at a time nowhere near any of
        # its scheduled windows -> too suspicious to call confidently benign
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