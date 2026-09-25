from __future__ import annotations
from pathlib import Path
from src.database.pcap_reader import PCAPReader
from src.extraction.pcap_frame_parser import PCAPFrameParser
from src.extraction.cross_flow_behavioral_feature_extractor import CrossFlowBehavioralFeatureExtractor, DEFAULT_CONFIG_PATH


def test_cross_flow_behavioral_feature_extractor(pcap_path: Path, tshark_path: Path, config_path: str = DEFAULT_CONFIG_PATH, output_path: Path = Path("out/sample/test_cross_flow_behavioral_feature_extractor_output.txt"), sample_size: int = 10) -> Path:
    pcap_path = Path(pcap_path)
    tshark_path = Path(tshark_path)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    extractor = CrossFlowBehavioralFeatureExtractor(config_path=config_path)
    frame_parser = PCAPFrameParser()

    records = []
    record_count = 0
    with PCAPReader(pcap_path, tshark_path=tshark_path) as reader:
        parsed_frames = (frame_parser.parse(packet) for packet in reader)
        for record in extractor.extract(parsed_frames):
            record_count += 1
            if len(records) < sample_size:
                records.append(record)

    lines = [
        "module: cross_flow_behavioral_feature_extractor.CrossFlowBehavioralFeatureExtractor.extract (drives pcap_reader.py internally)",
        f"source_pcap: {pcap_path}",
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