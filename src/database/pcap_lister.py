import csv
import json
import struct
import subprocess
import tempfile
import zlib
from pathlib import Path

BUCKET = "cse-cic-ids2018"
REGION = "ca-central-1"
PREFIX = "Original Network Traffic and Log data/"
OUTPUT_DIR = Path("dataset/pcap/lists")
NON_PCAP_EXTENSIONS = {".lnk", ".txt", ".csv", ".log", ".zip", ".db", ".ini"}
FIELDS = ["day", "archive", "entry", "compressed_size", "uncompressed_size", "method"]


def run(command):
    result = subprocess.run(command, capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Command failed")
    return result.stdout


def get_archives():
    output = run([
        "aws", "s3api", "list-objects-v2",
        "--no-sign-request",
        "--region", REGION,
        "--bucket", BUCKET,
        "--prefix", PREFIX,
        "--query", "Contents[?ends_with(Key, 'pcap.zip')].Key",
        "--output", "json"
    ])
    return json.loads(output)


def get_size(key):
    return int(run([
        "aws", "s3api", "head-object",
        "--no-sign-request",
        "--region", REGION,
        "--bucket", BUCKET,
        "--key", key,
        "--query", "ContentLength",
        "--output", "text"
    ]).strip())


def download_range(url, start, end, output):
    subprocess.run([
        "curl.exe", "-L", "--fail",
        "--range", f"{start}-{end}",
        "-o", str(output),
        url
    ], check=True)


def make_reader(url):
    def reader(start, end):
        with tempfile.TemporaryDirectory() as temp:
            output = Path(temp) / "range.bin"
            download_range(url, start, end, output)
            return output.read_bytes()
    return reader


def find_central_directory_from_tail(data, zip_size, tail_size):
    tail_start = zip_size - tail_size

    eocd = data.rfind(b"PK\x05\x06")
    if eocd == -1:
        raise ValueError("ZIP EOCD not found")

    entries16 = struct.unpack_from("<H", data, eocd + 10)[0]
    cd_size32 = struct.unpack_from("<I", data, eocd + 12)[0]
    cd_offset32 = struct.unpack_from("<I", data, eocd + 16)[0]

    if entries16 != 0xFFFF and cd_offset32 != 0xFFFFFFFF:
        return cd_offset32, cd_size32, entries16

    locator = data.rfind(b"PK\x06\x07", 0, eocd)
    if locator == -1:
        raise ValueError("ZIP64 locator not found")

    zip64_offset = struct.unpack_from("<Q", data, locator + 8)[0]
    local = zip64_offset - tail_start

    if local < 0 or data[local:local + 4] != b"PK\x06\x06":
        raise ValueError("ZIP64 EOCD is outside downloaded tail")

    entries = struct.unpack_from("<Q", data, local + 32)[0]
    cd_size = struct.unpack_from("<Q", data, local + 40)[0]
    cd_offset = struct.unpack_from("<Q", data, local + 48)[0]

    return cd_offset, cd_size, entries


def apply_zip64_extra(extra, compressed_size, uncompressed_size, local_offset):
    position = 0
    while position + 4 <= len(extra):
        header_id, data_size = struct.unpack_from("<HH", extra, position)
        if header_id == 0x0001:
            cursor = position + 4
            if uncompressed_size == 0xFFFFFFFF:
                uncompressed_size = struct.unpack_from("<Q", extra, cursor)[0]
                cursor += 8
            if compressed_size == 0xFFFFFFFF:
                compressed_size = struct.unpack_from("<Q", extra, cursor)[0]
                cursor += 8
            if local_offset == 0xFFFFFFFF:
                local_offset = struct.unpack_from("<Q", extra, cursor)[0]
            break
        position += 4 + data_size
    return compressed_size, uncompressed_size, local_offset


def parse_entries(central):
    rows = []
    offset = 0
    while offset < len(central):
        if central[offset:offset + 4] != b"PK\x01\x02":
            raise ValueError(f"Invalid central-directory entry at offset {offset}")

        flags, method = struct.unpack_from("<HH", central, offset + 8)
        compressed_size, uncompressed_size = struct.unpack_from("<II", central, offset + 20)
        name_length, extra_length, comment_length = struct.unpack_from("<HHH", central, offset + 28)
        local_offset = struct.unpack_from("<I", central, offset + 42)[0]

        name_start = offset + 46
        name = central[name_start:name_start + name_length].decode("utf-8" if flags & 0x800 else "cp437")
        extra_start = name_start + name_length
        extra = central[extra_start:extra_start + extra_length]
        compressed_size, uncompressed_size, local_offset = apply_zip64_extra(extra, compressed_size, uncompressed_size, local_offset)

        rows.append({
            "name": name,
            "method": method,
            "compressed_size": compressed_size,
            "uncompressed_size": uncompressed_size,
            "local_offset": local_offset
        })

        offset += 46 + name_length + extra_length + comment_length
    return rows


def member_reader(reader, row):
    local_offset = row["local_offset"]
    header = reader(local_offset, local_offset + 29)

    if header[:4] != b"PK\x03\x04":
        raise ValueError("Invalid local ZIP header")

    name_length, extra_length = struct.unpack_from("<HH", header, 26)
    data_start = local_offset + 30 + name_length + extra_length

    if row["method"] == 0:
        return (lambda start, end: reader(data_start + start, data_start + end)), row["uncompressed_size"]

    if row["method"] == 8:
        raw = reader(data_start, data_start + row["compressed_size"] - 1)
        data = zlib.decompress(raw, -15)
        return (lambda start, end: data[start:end + 1]), len(data)

    raise ValueError(f"Unsupported compression method {row['method']} for {row['name']}")


def list_zip(reader, size, chain=""):
    tail_size = min(size, 1_000_000)
    tail = reader(size - tail_size, size - 1)
    cd_offset, cd_size, entries = find_central_directory_from_tail(tail, size, tail_size)
    central = reader(cd_offset, cd_offset + cd_size - 1)

    rows = []
    for row in parse_entries(central):
        row["entry"] = chain + row["name"]
        rows.append(row)
        if row["name"].lower().endswith(".zip"):
            print(f"  Nested archive: {row['entry']}")
            nested_reader, nested_size = member_reader(reader, row)
            rows.extend(list_zip(nested_reader, nested_size, row["entry"] + "!"))
    return rows


def is_pcap(row):
    name = row["entry"].split("!")[-1]
    if not name.startswith("pcap/") or name.endswith("/"):
        return False
    return Path(name).suffix.lower() not in NON_PCAP_EXTENSIONS


def write_rows(path, rows):
    with path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=FIELDS, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)


def build_lists(output_dir, all_name="all_entries", pcaps_name="pcaps", combined_name="all"):
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    archives = get_archives()
    print(f"Found {len(archives)} PCAP archives.")
    print()

    combined_all = []
    combined_pcaps = []

    for index, key in enumerate(archives, 1):
        day = Path(key).parent.name
        url = f"https://{BUCKET}.s3.{REGION}.amazonaws.com/{key.replace(' ', '%20')}"

        print(f"[{index}/{len(archives)}] {day}")

        rows = list_zip(make_reader(url), get_size(key))
        for row in rows:
            row["day"] = day
            row["archive"] = key

        pcaps = [row for row in rows if is_pcap(row)]

        write_rows(output_dir / f"{all_name}_{day}.csv", rows)
        write_rows(output_dir / f"{pcaps_name}_{day}.csv", pcaps)

        print(f"  Entries: {len(rows)}  PCAPs: {len(pcaps)}")
        print()

        combined_all.extend(rows)
        combined_pcaps.extend(pcaps)

    write_rows(output_dir / f"{all_name}_{combined_name}.csv", combined_all)
    write_rows(output_dir / f"{pcaps_name}_{combined_name}.csv", combined_pcaps)

    print(f"Total entries: {len(combined_all)}  Total PCAPs: {len(combined_pcaps)}")



if __name__ == "__main__":
    build_lists(OUTPUT_DIR)