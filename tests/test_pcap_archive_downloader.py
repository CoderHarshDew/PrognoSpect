import argparse
import sys

from src. database import pcap_archive_downloader

TEST_FAIL_AT = 2
TEST_STATE = {"i": 0}


def process_archive(day, files):
    # TODO: processing is not implemented yet; this stub only simulates success/failure for testing
    if TEST_STATE["i"] == TEST_FAIL_AT:
        raise RuntimeError(f"Simulated processing failure for {day} (i={TEST_STATE['i']})")
    else:
        print(f"  Processing successfully finished for {day} (i={TEST_STATE['i']})")
        TEST_STATE["i"] += 1


def list_days():
    days = []
    for row in pcap_archive_downloader.read_csv(pcap_archive_downloader.ALL_LIST):
        if row["day"] not in days:
            days.append(row["day"])
    return days


def run_archive(day, process=process_archive, limit=pcap_archive_downloader.LIMIT):
    print(f"=== {day} ===")
    files = pcap_archive_downloader.download(day, limit)
    if files is None:
        pcap_archive_downloader.delete(day)
        print(f"  {day}: already done, skipping")
        return
    print(f"  processing {len(files)} PCAPs")
    process(day, files)
    pcap_archive_downloader.delete(day)
    print(f"  {day}: PCAPs removed, archive done")


def run_all(process=process_archive, limit=pcap_archive_downloader.LIMIT):
    for day in list_days():
        run_archive(day, process, limit)


def test_pcap_archive_downloader():
    parser = argparse.ArgumentParser()
    parser.add_argument("day", nargs="?", help="archive day, e.g. Friday-02-03-2018 (default: all archives)")
    parser.add_argument("--limit", type=int, default=pcap_archive_downloader.LIMIT, help="max PCAPs per archive, 0 = all")
    args = parser.parse_args()
    limit = args.limit if args.limit > 0 else None
    try:
        if args.day:
            run_archive(args.day, process_archive, limit)
        else:
            run_all(process_archive, limit)
    except Exception as error:
        print(f"\nStopped: {type(error).__name__}: {error}")
        print("Fix the issue and run the same command again to resume.")
        sys.exit(1)


if __name__ == "__main__":
    test_pcap_archive_downloader()