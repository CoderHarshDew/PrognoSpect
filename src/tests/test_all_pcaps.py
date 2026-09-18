from pathlib import Path

from src.database.pcap_reader import PCAPReader


PCAP_DIRECTORY = Path("dataset/pcap/test")


def test_pcap(pcap_path):
    try:
        with PCAPReader(pcap_path) as reader:
            for _ in reader:
                pass

        print(f"    Packets processed: {reader.packet_count}")
        print("    Status: OK")

    except Exception as error:
        print(f"    Packets processed: {getattr(reader, 'packet_count', 0)}")
        print("    Status: FAILED")
        print(f"    Error: {error}")


def test_all_pcap():
    pcap_files = list(PCAP_DIRECTORY.glob("*.pcap"))

    if not pcap_files:
        print(f"No PCAP files found in: {PCAP_DIRECTORY}")
        return

    print(f"Found {len(pcap_files)} PCAP files.\n")

    for index, pcap_path in enumerate(pcap_files, 1):
        print(f"[{index}/{len(pcap_files)}] {pcap_path.name}")
        test_pcap(pcap_path)
        print()


if __name__ == "__main__":
    test_all_pcap()