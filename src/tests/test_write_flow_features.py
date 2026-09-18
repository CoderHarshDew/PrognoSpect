from __future__ import annotations
import csv
from pathlib import Path
from src.core.config import config_loader
from src.extraction import write_flow_features_csv


def test_write_flow_features_csv(pcap_path: Path, config_path: Path, output_path: Path = Path("out/sample/test_write_flow_features_csv_output.txt"), sample_size: int = 10) -> Path:
    pcap_path = Path(pcap_path)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    config = config_loader(config_path)
    result_csv_path = write_flow_features_csv.run(pcap_path, config)

    with result_csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        fieldnames = reader.fieldnames or []
        rows = []
        row_count = 0
        for row in reader:
            row_count += 1
            if len(rows) < sample_size:
                rows.append(row)

    lines = [
        "module: write_flow_features_csv.write_flow_features_csv (drives cicflowmeter.py internally)",
        f"source_pcap: {pcap_path}",
        f"result_csv_path: {result_csv_path}",
        f"row_count: {row_count}",
        f"sample_size: {len(rows)}",
        "",
        "output columns:",
    ]
    lines += [f"  {name}" for name in fieldnames]
    lines.append("")
    lines.append("sample records:")
    for i, row in enumerate(rows):
        lines.append(f"[{i}]")
        lines += [f"  {name}: {value!r}" for name, value in row.items()]

    output_path.write_text("\n".join(lines) + "\n")
    return output_path