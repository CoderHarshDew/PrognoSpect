
from collections import Counter

from src.database.pcap_reader import PCAPReader


def fingerprint_pcap(pcap_path):
    fingerprints = Counter()
    first_timestamp = None
    last_timestamp = None

    with PCAPReader(pcap_path) as reader:
        for packet in reader:
            fingerprints[hash((packet.timestamp, packet.data))] += 1

            if first_timestamp is None or packet.timestamp < first_timestamp:
                first_timestamp = packet.timestamp

            if last_timestamp is None or packet.timestamp > last_timestamp:
                last_timestamp = packet.timestamp

    return fingerprints, first_timestamp, last_timestamp


def time_overlap(first_a, last_a, first_b, last_b):
    if first_a is None or first_b is None:
        return 0.0

    overlap = (min(last_a, last_b) - max(first_a, first_b)).total_seconds()
    union = (max(last_a, last_b) - min(first_a, first_b)).total_seconds()

    if union == 0:
        return 1.0

    return max(overlap, 0.0) / union


def compare_pcaps(path_a, path_b):
    fingerprints_a, first_a, last_a = fingerprint_pcap(path_a)
    fingerprints_b, first_b, last_b = fingerprint_pcap(path_b)

    shared = sum((fingerprints_a & fingerprints_b).values())
    total = sum((fingerprints_a | fingerprints_b).values())
    count_a = sum(fingerprints_a.values())
    count_b = sum(fingerprints_b.values())

    similarity = shared / total if total else 1.0
    a_in_b = shared / count_a if count_a else 1.0
    b_in_a = shared / count_b if count_b else 1.0

    return {"similarity": similarity, "a_in_b": a_in_b, "b_in_a": b_in_a, "time_overlap": time_overlap(first_a, last_a, first_b, last_b), "shared_packets": shared, "packets_a": count_a, "packets_b": count_b}


def test_pcap_similarity(path_a, path_b):
    for name, value in compare_pcaps(path_a, path_b).items():
        print(f"{name}: {value:.4f}" if isinstance(value, float) else f"{name}: {value:,}")



if __name__ == "__main__":
    pass