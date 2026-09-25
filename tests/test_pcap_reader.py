from __future__ import annotations
from pathlib import Path
from src.database.pcap_reader import PCAPReader


def test_pcap_reader(pcap_path: Path, tshark_path: Path, output_path: Path = Path("out/sample/test_pcap_reader_output.txt"), sample_size: int = 10) -> Path:
    pcap_path = Path(pcap_path)
    tshark_path = Path(tshark_path)
    output_path = Path(output_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    samples = []
    with PCAPReader(pcap_path, tshark_path=tshark_path) as reader:
        for packet in reader:
            if len(samples) < sample_size:
                samples.append(packet)
        packet_count = reader.packet_count
        byte_order = reader.byte_order
        version_major = reader.version_major
        version_minor = reader.version_minor
        snaplen = reader.snaplen
        link_type = reader.link_type

    lines = [
        "module: pcap_reader.PCAPReader",
        f"source_pcap: {pcap_path}",
        f"byte_order: {byte_order}",
        f"pcap_version: {version_major}.{version_minor}",
        f"snaplen: {snaplen}",
        f"link_type: {link_type}",
        f"packet_count: {packet_count}",
        "",
        "output_type: Packet(timestamp: datetime, captured_length: int, original_length: int, data: bytes)",
        f"sample_size: {len(samples)}",
        "",
    ]
    for i, packet in enumerate(samples):
        preview = packet.data[:16].hex()
        lines.append(f"[{i}] timestamp={packet.timestamp.isoformat()} captured_length={packet.captured_length} original_length={packet.original_length} data_preview={preview}")

    output_path.write_text("\n".join(lines) + "\n")
    return output_path