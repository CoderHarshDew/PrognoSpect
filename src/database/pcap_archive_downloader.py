import csv
import json
import os
import re
import shutil
import struct
import subprocess
import time
import zlib
from pathlib import Path

from src.database.pcap_downloader import BUCKET, REGION, fetch_central_directory, find_entry

BASE_DIR = Path("dataset/pcap")
LISTS_DIR = BASE_DIR / "lists"
STATE_DIR = BASE_DIR / "state"
ALL_LIST = LISTS_DIR / "pcaps_all.csv"
LIMIT = 5
CHUNK_SIZE = 256 * 1024
RETRIES = 5
PROGRESS_INTERVAL = 1.0
CURL_LIMITS = ["--connect-timeout", "30", "--speed-limit", "1024", "--speed-time", "60"]


def pcap_dir(day):
    return BASE_DIR / day


def state_path(day):
    return STATE_DIR / f"{day}.json"


def archive_url(key):
    return f"https://{BUCKET}.s3.{REGION}.amazonaws.com/{key.replace(' ', '%20')}"


def output_name(day, entry):
    stem = Path(entry).name
    stem = re.sub(r"(?i)\.pcap$", "", stem)
    stem = re.sub(r"(?i)part\s+(\d)", r"part\1", stem)
    stem = re.sub(r"\s+", "-", stem)
    stem = re.sub(r"-{2,}", "-", stem)
    stem = stem.rstrip("-")
    return f"{day}-{stem}.pcap"


def read_csv(path):
    with open(path, newline="", encoding="utf-8-sig") as handle:
        return list(csv.DictReader(handle))


def load_rows(day):
    per_day = LISTS_DIR / f"pcaps_{day}.csv"
    if per_day.exists():
        rows = read_csv(per_day)
    else:
        rows = [row for row in read_csv(ALL_LIST) if row["day"] == day]
    if not rows:
        raise ValueError(f"No PCAPs listed for {day}")
    return rows


def new_state():
    return {"downloaded": [], "downloading": [], "to_download": [], "deleted": False}


def load_state(day):
    path = state_path(day)
    if not path.exists():
        return new_state()
    return json.loads(path.read_text(encoding="utf-8"))


def save_state(day, state):
    STATE_DIR.mkdir(parents=True, exist_ok=True)
    path = state_path(day)
    temp = path.with_name(path.name + ".tmp")
    temp.write_text(json.dumps(state, indent=2), encoding="utf-8")
    os.replace(temp, path)


def is_complete(day, row):
    path = pcap_dir(day) / output_name(day, row["entry"])
    return path.exists() and path.stat().st_size == int(row["uncompressed_size"])


def entry_crc(central, entry_name):
    offset = 0
    while offset < len(central):
        if central[offset:offset + 4] != b"PK\x01\x02":
            raise ValueError(f"Invalid central-directory entry at offset {offset}")
        crc = struct.unpack_from("<I", central, offset + 16)[0]
        name_length, extra_length, comment_length = struct.unpack_from("<HHH", central, offset + 28)
        name = central[offset + 46:offset + 46 + name_length].decode("utf-8")
        if name == entry_name:
            return crc
        offset += 46 + name_length + extra_length + comment_length
    raise ValueError(f"Entry not found: {entry_name}")


def curl_range(url, start, end):
    command = ["curl.exe", "-L", "--fail", "--silent", "--show-error", *CURL_LIMITS, "--range", f"{start}-{end}", url]
    curl = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    try:
        while True:
            chunk = curl.stdout.read(CHUNK_SIZE)
            if not chunk:
                break
            yield chunk
        error = curl.stderr.read().decode(errors="replace").strip()
        if curl.wait() != 0:
            raise RuntimeError(error or "curl failed")
    finally:
        if curl.poll() is None:
            curl.kill()
        curl.stdout.close()
        curl.stderr.close()


def stream_range(url, start, end):
    position = start
    failures = 0
    while position <= end:
        before = position
        problem = None
        try:
            for chunk in curl_range(url, position, end):
                position += len(chunk)
                yield chunk
        except RuntimeError as error:
            problem = str(error)
        if position > end:
            return
        problem = problem or "stream ended early"
        failures = failures + 1 if position == before else 1
        if failures > RETRIES:
            raise RuntimeError(problem)
        print(f"\n  connection problem ({problem}); retry {failures}/{RETRIES} from byte {position:,}")
        time.sleep(min(5 * failures, 30))


def show_progress(received, total, seconds):
    speed = received / seconds / 1e6 if seconds > 0 else 0.0
    print(f"\r      {received / total:6.1%}  {received / 1e6:,.1f} / {total / 1e6:,.1f} MB compressed  {speed:.2f} MB/s", end="", flush=True)


def extract_entry(url, compressed_size, local_offset, expected_crc, expected_size, output):
    header = b"".join(stream_range(url, local_offset, local_offset + 29))
    if header[:4] != b"PK\x03\x04":
        raise ValueError("Invalid local ZIP header")
    filename_length, extra_length = struct.unpack_from("<HH", header, 26)
    data_start = local_offset + 30 + filename_length + extra_length
    decompressor = zlib.decompressobj(-15)
    crc = 0
    received = 0
    written = 0
    started = time.monotonic()
    last_shown = started
    with open(output, "wb") as handle:
        for chunk in stream_range(url, data_start, data_start + compressed_size - 1):
            received += len(chunk)
            data = decompressor.decompress(chunk)
            crc = zlib.crc32(data, crc)
            written += len(data)
            handle.write(data)
            now = time.monotonic()
            if now - last_shown >= PROGRESS_INTERVAL:
                last_shown = now
                show_progress(received, compressed_size, now - started)
        data = decompressor.flush()
        crc = zlib.crc32(data, crc)
        written += len(data)
        handle.write(data)
    show_progress(received, compressed_size, time.monotonic() - started)
    print()
    if received != compressed_size or not decompressor.eof:
        raise ValueError(f"Incomplete download: received {received:,} of {compressed_size:,} compressed bytes")
    if written != expected_size:
        raise ValueError(f"Size mismatch: wrote {written:,}, expected {expected_size:,}")
    if crc != expected_crc:
        raise ValueError(f"CRC32 mismatch: got {crc:08x}, expected {expected_crc:08x}")
    return written


def reconcile(day, rows, state, limit):
    pcap_dir(day).mkdir(parents=True, exist_ok=True)
    for part in pcap_dir(day).glob("*.part"):
        part.unlink()
    for entry in state["downloading"]:
        (pcap_dir(day) / output_name(day, entry)).unlink(missing_ok=True)
    by_entry = {row["entry"]: row for row in rows}
    downloaded = [entry for entry in state["downloaded"] if entry in by_entry and is_complete(day, by_entry[entry])]
    wanted = [row["entry"] for row in rows[:limit]]
    state["downloaded"] = downloaded
    state["downloading"] = []
    state["to_download"] = [entry for entry in wanted if entry not in downloaded]
    save_state(day, state)


def download_entries(day, rows, state):
    by_entry = {row["entry"]: row for row in rows}
    key = rows[0]["archive"]
    url = archive_url(key)
    total = len(state["downloaded"]) + len(state["to_download"])
    size, entries, central = fetch_central_directory(key)
    for entry in list(state["to_download"]):
        output = pcap_dir(day) / output_name(day, entry)
        part = output.with_name(output.name + ".part")
        state["to_download"].remove(entry)
        state["downloading"].append(entry)
        save_state(day, state)
        print(f"  [{len(state['downloaded']) + 1}/{total}] {entry} -> {output.name}")
        name, compressed_size, local_offset = find_entry(central, entry)
        crc = entry_crc(central, entry)
        expected = int(by_entry[entry]["uncompressed_size"])
        written = extract_entry(url, compressed_size, local_offset, crc, expected, part)
        os.replace(part, output)
        state["downloading"].remove(entry)
        state["downloaded"].append(entry)
        save_state(day, state)
        print(f"      saved {written:,} bytes")


def download(day, limit=LIMIT):
    state = load_state(day)
    if state["deleted"]:
        return None
    rows = load_rows(day)
    reconcile(day, rows, state, limit)
    print(f"  {len(state['downloaded'])} downloaded, {len(state['to_download'])} to download")
    if state["to_download"]:
        download_entries(day, rows, state)
    return [pcap_dir(day) / output_name(day, entry) for entry in state["downloaded"]]


def delete(day):
    state = load_state(day)
    state["deleted"] = True
    save_state(day, state)
    if pcap_dir(day).exists():
        shutil.rmtree(pcap_dir(day))