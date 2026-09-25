from __future__ import annotations
from pathlib import Path
from src.database.pcap_reader import PCAPReader
from src.extraction.pcap_frame_parser import PCAPFrameParser, PCAPPacketLevelParser


def _describe_sample(record: dict) -> list[str]:
    return [f"  {name}: {type(value).__name__} = {value!r}" for name, value in record.items()]


def test_pcap_frame_parser(pcap_path: Path, tshark_path: Path, frame_parser_config_path: Path | None = None, packet_level_config_path: Path | None = None, output_path: Path = Path("out/sample/test_pcap_frame_parser_output.txt"), sample_size: int = 10) -> Path:
    pcap_path = Path(pcap_path)
    tshark_path = Path(tshark_path)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    frame_parser = PCAPFrameParser() if frame_parser_config_path is None else PCAPFrameParser(config_path=frame_parser_config_path)
    packet_level_parser = PCAPPacketLevelParser() if packet_level_config_path is None else PCAPPacketLevelParser(config_path=packet_level_config_path)

    frame_samples = []
    packet_level_samples = []
    packet_count = 0

    with PCAPReader(pcap_path, tshark_path=tshark_path) as reader:
        for packet in reader:
            frame_record = frame_parser.parse(packet)
            packet_level_record = packet_level_parser.parse(packet)
            packet_count += 1
            if len(frame_samples) < sample_size:
                frame_samples.append(frame_record)
                packet_level_samples.append(packet_level_record)

    lines = [
        "module: pcap_frame_parser.PCAPFrameParser, pcap_frame_parser.PCAPPacketLevelParser",
        f"source_pcap: {pcap_path}",
        f"packet_count: {packet_count}",
        f"sample_size: {len(frame_samples)}",
        "",
        "PCAPFrameParser.parse() output fields:",
    ]
    if frame_samples:
        lines += [f"  {name}: {type(value).__name__}" for name, value in frame_samples[0].items()]
    lines.append("")
    lines.append("PCAPFrameParser sample records:")
    for i, record in enumerate(frame_samples):
        lines.append(f"[{i}]")
        lines += _describe_sample(record)

    lines.append("")
    lines.append("PCAPPacketLevelParser.parse() output fields:")
    if packet_level_samples:
        lines += [f"  {name}: {type(value).__name__}" for name, value in packet_level_samples[0].items()]
    lines.append("")
    lines.append("PCAPPacketLevelParser sample records:")
    for i, record in enumerate(packet_level_samples):
        lines.append(f"[{i}]")
        lines += _describe_sample(record)

    output_path.write_text("\n".join(lines) + "\n")
    return output_path