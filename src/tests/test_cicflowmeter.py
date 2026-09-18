from __future__ import annotations
from pathlib import Path
from src.core.config import config_loader
from src.extraction.providers import cicflowmeter


def test_cicflowmeter(pcap_path: Path, executable: Path, work_dir: Path, config_path: Path, output_path: Path = Path("out/sample/test_cicflowmeter_output.txt"), sample_size: int = 10, preserve_intermediate_csv: bool = True) -> Path:
    pcap_path = Path(pcap_path)
    executable = Path(executable)
    work_dir = Path(work_dir)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    work_dir.mkdir(parents=True, exist_ok=True)

    schema = config_loader(config_path)["schema"]

    raw_csv_path = cicflowmeter.run_cicflowmeter(pcap_path, executable, work_dir)

    rows = []
    row_count = 0
    for row in cicflowmeter.remap_rows(raw_csv_path, schema):
        row_count += 1
        if len(rows) < sample_size:
            rows.append(row)

    if not preserve_intermediate_csv and raw_csv_path.exists():
        raw_csv_path.unlink()

    lines = [
        "module: cicflowmeter.run_cicflowmeter, cicflowmeter.remap_rows",
        f"source_pcap: {pcap_path}",
        f"raw_csv_path: {raw_csv_path}",
        f"row_count: {row_count}",
        f"sample_size: {len(rows)}",
        "",
        "remap_rows() output fields:",
    ]
    if rows:
        lines += [f"  {name}: {type(value).__name__}" for name, value in rows[0].items()]
    lines.append("")
    lines.append("sample records:")
    for i, row in enumerate(rows):
        lines.append(f"[{i}]")
        lines += [f"  {name}: {value!r}" for name, value in row.items()]

    output_path.write_text("\n".join(lines) + "\n")
    return output_path