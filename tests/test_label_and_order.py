import csv
from pathlib import Path

from src.extraction.label_and_order import label_and_order

DEFAULT_INPUT_PATH = Path("dataset/extracted/merged/16-02-2018.csv")
DEFAULT_OUTPUT_PATH = Path("dataset/extracted/labelled_and_ordered/16-02-2018.csv")
DEFAULT_SCHEDULE_PATH = Path("config/extraction/schedule.yaml")


def count_data_rows(csv_path: Path) -> int:
    with open(csv_path, "r", newline="") as f:
        return sum(1 for _ in f) - 1  # minus header


def read_rows(csv_path: Path):
    with open(csv_path, "r", newline="") as f:
        reader = csv.reader(f)
        header = next(reader)
        rows = list(reader)
    return header, rows


def test_label_and_order(
    input_path: Path = DEFAULT_INPUT_PATH,
    output_path: Path = DEFAULT_OUTPUT_PATH,
    schedule_path: Path = DEFAULT_SCHEDULE_PATH,
):
    output_path.parent.mkdir(parents=True, exist_ok=True)

    label_and_order(input_path, schedule_path, output_path)

    assert output_path.exists(), f"Expected output file not created: {output_path}"

    input_row_count = count_data_rows(input_path)
    header, output_rows = read_rows(output_path)

    assert "Label" in header, "Output CSV is missing the Label column"
    assert len(output_rows) <= input_row_count, (
        f"Output has more rows ({len(output_rows)}) than input ({input_row_count}) — "
        "kept rows should never exceed input rows"
    )

    label_idx = header.index("Label")
    timestamp_idx = header.index("Timestamp")

    prev_ts = None
    for row in output_rows:
        ts = row[timestamp_idx]
        if prev_ts is not None:
            assert ts >= prev_ts, f"Output is not chronologically ordered: {prev_ts} -> {ts}"
        prev_ts = ts

    label_counts = {}
    for row in output_rows:
        label = row[label_idx]
        label_counts[label] = label_counts.get(label, 0) + 1

    dropped = input_row_count - len(output_rows)

    print(f"Input rows:  {input_row_count}")
    print(f"Kept rows:   {len(output_rows)}")
    print(f"Dropped:     {dropped}")
    for label, n in sorted(label_counts.items()):
        print(f"  {label}: {n}")

    return {
        "input_rows": input_row_count,
        "output_rows": len(output_rows),
        "dropped": dropped,
        "label_counts": label_counts,
    }