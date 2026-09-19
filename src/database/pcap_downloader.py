import os
import json
import struct
import subprocess
import tempfile
import zipfile
import zlib
from pathlib import Path

BUCKET = "cse-cic-ids2018"
REGION = "ca-central-1"
PREFIX = "Original Network Traffic and Log data/"
COUNT = 5
OUTPUT_DIR = Path("dataset/pcap/test")


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


def download_range(url, start, end, output):
    subprocess.run([
        "curl.exe", "-L", "--fail",
        "--range", f"{start}-{end}",
        "-o", str(output),
        url
    ], check=True)


def find_central_directory(zip_path, tail_size):
    size = zip_path.stat().st_size
    tail_start = size - tail_size
    data = zip_path.read_bytes()

    eocd = data.rfind(b"PK\x05\x06")
    if eocd == -1:
        raise ValueError("ZIP EOCD not found")

    fields = struct.unpack_from("<4s4H2IH", data, eocd)
    entries = fields[4]
    cd_size = fields[5]
    cd_offset = fields[6]

    if entries != 0xFFFF and cd_offset != 0xFFFFFFFF:
        return cd_offset, cd_size, entries

    locator = data.rfind(b"PK\x06\x07", 0, eocd)
    if locator == -1:
        raise ValueError("ZIP64 locator not found")

    zip64_offset = struct.unpack_from("<Q", data, locator + 8)[0]
    zip64_eocd = data[zip64_offset - tail_start:]

    if zip64_eocd[:4] != b"PK\x06\x06":
        raise ValueError("ZIP64 EOCD not found")

    entries = struct.unpack_from("<Q", zip64_eocd, 32)[0]
    cd_size = struct.unpack_from("<Q", zip64_eocd, 40)[0]
    cd_offset = struct.unpack_from("<Q", zip64_eocd, 48)[0]

    return cd_offset, cd_size, entries


def parse_first_pcap(central_directory):
    offset = 0
    while offset < len(central_directory):
        if central_directory[offset:offset + 4] != b"PK\x01\x02":
            raise ValueError(f"Invalid central-directory entry at offset {offset}")

        compressed_size = struct.unpack_from("<I", central_directory, offset + 20)[0]
        filename_length = struct.unpack_from("<H", central_directory, offset + 28)[0]
        extra_length = struct.unpack_from("<H", central_directory, offset + 30)[0]
        comment_length = struct.unpack_from("<H", central_directory, offset + 32)[0]
        local_offset = struct.unpack_from("<I", central_directory, offset + 42)[0]

        name_start = offset + 46
        name = central_directory[name_start:name_start + filename_length].decode("utf-8")

        if name.startswith("pcap/") and not name.endswith("/"):
            return name, compressed_size, local_offset

        offset += 46 + filename_length + extra_length + comment_length

    raise ValueError("No PCAP entry found")


def extract_member(url, zip_size, entry_name, compressed_size, local_offset, output):
    local_header_start = local_offset
    local_header_end = local_offset + 29

    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)

        local_header = temp / "local-header.bin"
        download_range(url, local_header_start, local_header_end, local_header)
        header = local_header.read_bytes()

        if header[:4] != b"PK\x03\x04":
            raise ValueError("Invalid local ZIP header")

        filename_length, extra_length = struct.unpack_from("<HH", header, 26)
        data_start = local_offset + 30 + filename_length + extra_length
        data_end = data_start + compressed_size - 1

        compressed = temp / "compressed.bin"
        download_range(url, data_start, data_end, compressed)

        raw = compressed.read_bytes()
        output.write_bytes(zlib.decompress(raw, -15))


def main():
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    archives = get_archives()
    selected = archives[:COUNT]

    print(f"Found {len(archives)} PCAP archives.")
    print(f"Using {len(selected)} archives.")
    print()

    for index, key in enumerate(selected, 1):
        day = Path(key).parent.name
        url = f"https://{BUCKET}.s3.{REGION}.amazonaws.com/{key.replace(' ', '%20')}"

        print(f"[{index}/{len(selected)}] {day}")

        with tempfile.TemporaryDirectory() as temp:
            temp = Path(temp)
            tail = temp / "zip-tail.bin"

            size = int(run([
                "aws", "s3api", "head-object",
                "--no-sign-request",
                "--region", REGION,
                "--bucket", BUCKET,
                "--key", key,
                "--query", "ContentLength",
                "--output", "text"
            ]).strip())

            tail_size = min(size, 1_000_000)
            download_range(url, size - tail_size, size - 1, tail)

            cd_offset, cd_size, entries = find_central_directory_from_tail(tail.read_bytes(), size, tail_size)

            central = temp / "central.bin"
            download_range(url, cd_offset, cd_offset + cd_size - 1, central)

            entry_name, compressed_size, local_offset = parse_first_pcap(central.read_bytes())

            output = OUTPUT_DIR / f"{day}-{Path(entry_name).name}.pcap"

            print(f"  Selected: {entry_name}")
            print(f"  Output:   {output}")
            extract_member(url, size, entry_name, compressed_size, local_offset, output)
            print(f"  Saved:    {output.stat().st_size:,} bytes")
            print()


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

def fetch_central_directory(key):
    url = f"https://{BUCKET}.s3.{REGION}.amazonaws.com/{key.replace(' ', '%20')}"
    size = int(run(["aws", "s3api", "head-object", "--no-sign-request", "--region", REGION, "--bucket", BUCKET, "--key", key, "--query", "ContentLength", "--output", "text"]).strip())
    with tempfile.TemporaryDirectory() as temp:
        temp = Path(temp)
        tail = temp / "zip-tail.bin"
        tail_size = min(size, 1_000_000)
        download_range(url, size - tail_size, size - 1, tail)
        cd_offset, cd_size, entries = find_central_directory_from_tail(tail.read_bytes(), size, tail_size)
        central = temp / "central.bin"
        download_range(url, cd_offset, cd_offset + cd_size - 1, central)
        return size, entries, central.read_bytes()


def parse_entries(central):
    rows = []
    offset = 0
    while offset < len(central):
        if central[offset:offset + 4] != b"PK\x01\x02":
            raise ValueError(f"Invalid central-directory entry at offset {offset}")
        flags, method = struct.unpack_from("<HH", central, offset + 8)
        compressed_size, uncompressed_size = struct.unpack_from("<II", central, offset + 20)
        name_length, extra_length, comment_length = struct.unpack_from("<HHH", central, offset + 28)
        name = central[offset + 46:offset + 46 + name_length].decode("utf-8" if flags & 0x800 else "cp437")
        rows.append((name, method, compressed_size, uncompressed_size))
        offset += 46 + name_length + extra_length + comment_length
    return rows


def probe():
    archives = get_archives()
    print(len(archives))
    for key in archives:
        print(key)
    size, entries, central = fetch_central_directory(archives[0])
    print(size, entries)
    for row in parse_entries(central):
        print(row)


def read_zip64_extra(central, extra_start, extra_length, uncompressed_size, compressed_size, local_offset):
    position = extra_start
    while position + 4 <= extra_start + extra_length:
        header_id, data_size = struct.unpack_from("<HH", central, position)
        if header_id == 1:
            cursor = position + 4
            if uncompressed_size == 0xFFFFFFFF:
                cursor += 8
            if compressed_size == 0xFFFFFFFF:
                compressed_size = struct.unpack_from("<Q", central, cursor)[0]
                cursor += 8
            if local_offset == 0xFFFFFFFF:
                local_offset = struct.unpack_from("<Q", central, cursor)[0]
            break
        position += 4 + data_size
    return compressed_size, local_offset


def find_entry(central, entry_name):
    offset = 0
    while offset < len(central):
        if central[offset:offset + 4] != b"PK\x01\x02":
            raise ValueError(f"Invalid central-directory entry at offset {offset}")
        compressed_size, uncompressed_size = struct.unpack_from("<II", central, offset + 20)
        name_length, extra_length, comment_length = struct.unpack_from("<HHH", central, offset + 28)
        local_offset = struct.unpack_from("<I", central, offset + 42)[0]
        name = central[offset + 46:offset + 46 + name_length].decode("utf-8")
        if name == entry_name:
            compressed_size, local_offset = read_zip64_extra(central, offset + 46 + name_length, extra_length, uncompressed_size, compressed_size, local_offset)
            return name, compressed_size, local_offset
        offset += 46 + name_length + extra_length + comment_length
    raise ValueError(f"Entry not found: {entry_name}")


def download_entry(day, entry_name):
    key = f"{PREFIX}{day}/pcap.zip"
    url = f"https://{BUCKET}.s3.{REGION}.amazonaws.com/{key.replace(' ', '%20')}"
    size, entries, central = fetch_central_directory(key)
    name, compressed_size, local_offset = find_entry(central, entry_name)
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)
    output = OUTPUT_DIR / f"{day}-{Path(name).name}.pcap"
    extract_member(url, size, name, compressed_size, local_offset, output)
    print(f"Saved: {output} ({output.stat().st_size:,} bytes)")


if __name__ == "__main__":
    probe()
