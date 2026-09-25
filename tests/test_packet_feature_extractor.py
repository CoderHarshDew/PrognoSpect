from __future__ import annotations
from pathlib import Path
from src.extraction.packet_feature_extractor import extract_all, DEFAULT_JOINER_CONFIG_PATH, DEFAULT_EXTRACTOR_CONFIG_PATH


def test_packet_feature_extractor(pcap_path: Path, cicflowmeter_csv_path: Path, tshark_path: str, joiner_config_path: Path = DEFAULT_JOINER_CONFIG_PATH, extractor_config_path: Path = DEFAULT_EXTRACTOR_CONFIG_PATH, output_path: Path = Path("out/sample/test_packet_feature_extractor_output.txt"), sample_size: int = 10) -> Path:
    pcap_path = Path(pcap_path)
    cicflowmeter_csv_path = Path(cicflowmeter_csv_path)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    records = []
    record_count = 0
    for record in extract_all(pcap_path, cicflowmeter_csv_path, tshark_path, joiner_config_path=joiner_config_path, extractor_config_path=extractor_config_path):
        record_count += 1
        if len(records) < sample_size:
            records.append(record)

    lines = [
        "module: packet_feature_extractor.extract_all (drives pcap_reader.py and pcap_frame_parser.py internally)",
        f"source_pcap: {pcap_path}",
        f"cicflowmeter_csv_path: {cicflowmeter_csv_path}",
        f"record_count: {record_count}",
        f"sample_size: {len(records)}",
        "",
        "output fields:",
    ]
    if records:
        lines += [f"  {name}: {type(value).__name__}" for name, value in records[0].items()]
    lines.append("")
    lines.append("sample records:")
    for i, record in enumerate(records):
        lines.append(f"[{i}]")
        lines += [f"  {name}: {value!r}" for name, value in record.items()]

    output_path.write_text("\n".join(lines) + "\n")
    return output_path