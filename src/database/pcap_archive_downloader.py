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
BATCH_BYTES = 20 * 10**9
SPLIT_BYTES = 10**9
DISK_RESERVE_BYTES = 10 * 10**9
GLOBAL_HEADER_SIZE = 24
RECORD_HEADER_SIZE = 16
MAX_RECORD_BYTES = 16 * 1024 * 1024
SPLIT_BUFFER_SIZE = 8 * 1024 * 1024
PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}


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


def ensure_free_space(path, needed, reserve=None):
    reserve = DISK_RESERVE_BYTES if reserve is None else reserve
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(path).free
    required = needed + reserve
    if free < required:
        raise RuntimeError(f"Not enough disk space at {path.resolve()}: need {required / 1e9:,.1f} GB free ({needed / 1e9:,.1f} GB for the next step plus a {reserve / 1e9:,.1f} GB reserve) but only {free / 1e9:,.1f} GB is available. Free some space (for example move finished CSVs to another drive) and run the same command again.")


def piece_files(day, entry):
    directory = pcap_dir(day)
    if not directory.exists():
        return []
    prefix = f"{Path(output_name(day, entry)).stem}-p"
    return sorted(path for path in directory.iterdir() if path.name.startswith(prefix) and re.fullmatch(r"\d{3}\.pcap(\.part)?", path.name[len(prefix):]))


def open_piece(header, final):
    part = final.with_name(final.name + ".part")
    handle = open(part, "wb")
    handle.write(header)
    return handle, part


def close_piece(handle, part, final):
    handle.close()
    os.replace(part, final)
    return final


def split_pcap(source, max_bytes):
    source = Path(source)
    pieces = []
    output = None
    part = None
    final = None
    output_size = 0
    pending = 0
    position = 0
    consumed = GLOBAL_HEADER_SIZE
    buffer = bytearray()
    try:
        with open(source, "rb") as handle:
            header = handle.read(GLOBAL_HEADER_SIZE)
            if len(header) < GLOBAL_HEADER_SIZE or header[:4] not in PCAP_MAGICS:
                raise ValueError(f"Unsupported capture format (first bytes: {header[:4].hex() or 'none'}) in {source.name}; only classic pcap files can be split")
            endian = PCAP_MAGICS[header[:4]]
            while True:
                chunk = handle.read(SPLIT_BUFFER_SIZE)
                buffer += chunk
                while len(buffer) - position >= RECORD_HEADER_SIZE:
                    included = struct.unpack_from(endian + "I", buffer, position + 8)[0]
                    if included > MAX_RECORD_BYTES:
                        raise ValueError(f"Corrupt record header at byte {consumed + position:,} of {source.name}")
                    total = RECORD_HEADER_SIZE + included
                    if len(buffer) - position < total:
                        break
                    if output is None or (output_size + total > max_bytes and output_size > GLOBAL_HEADER_SIZE):
                        if output is not None:
                            output.write(buffer[pending:position])
                            pieces.append(close_piece(output, part, final))
                        final = source.with_name(f"{source.stem}-p{len(pieces) + 1:03d}.pcap")
                        output, part = open_piece(header, final)
                        output_size = GLOBAL_HEADER_SIZE
                        pending = position
                    output_size += total
                    position += total
                if output is not None:
                    output.write(buffer[pending:position])
                consumed += position
                del buffer[:position]
                position = 0
                pending = 0
                if not chunk:
                    break
            if buffer:
                print(f"      warning: dropped {len(buffer):,} trailing bytes of an incomplete record in {source.name}")
            if output is None:
                final = source.with_name(f"{source.stem}-p001.pcap")
                output, part = open_piece(header, final)
            pieces.append(close_piece(output, part, final))
            output = None
    finally:
        if output is not None and not output.closed:
            output.close()
    return pieces


def plan_batches(rows, batch_bytes):
    batches = []
    current = []
    current_bytes = 0
    for row in rows:
        size = int(row["uncompressed_size"])
        if current and current_bytes + size > batch_bytes:
            batches.append(current)
            current = []
            current_bytes = 0
        current.append(row["entry"])
        current_bytes += size
    if current:
        batches.append(current)
    return batches


def plan(day, limit=None):
    state = load_state(day)
    if state["deleted"]:
        return 0
    if "batches" not in state:
        rows = load_rows(day)[:limit]
        state["batches"] = [{"entries": entries, "downloaded": [], "downloading": [], "deleted": False} for entries in plan_batches(rows, BATCH_BYTES)]
        state["pieces"] = {}
        save_state(day, state)
        print(f"  planned {len(state['batches'])} batch(es) for {day}")
    return len(state["batches"])


def pieces_complete(day, state, entry):
    pieces = state.get("pieces", {}).get(entry)
    if not pieces:
        return False
    for piece in pieces:
        path = pcap_dir(day) / piece["name"]
        if not path.exists() or path.stat().st_size != piece["size"]:
            return False
    return True


def remove_entry_files(day, entry, keep_original=False):
    output = pcap_dir(day) / output_name(day, entry)
    if not keep_original:
        output.unlink(missing_ok=True)
    output.with_name(output.name + ".part").unlink(missing_ok=True)
    for path in piece_files(day, entry):
        path.unlink(missing_ok=True)


def reconcile_batch(day, state, batch, by_entry):
    pcap_dir(day).mkdir(parents=True, exist_ok=True)
    for part in pcap_dir(day).glob("*.part"):
        part.unlink()
    for entry in batch["downloading"]:
        if pieces_complete(day, state, entry):
            original = pcap_dir(day) / output_name(day, entry)
            if original.name not in [piece["name"] for piece in state["pieces"][entry]]:
                original.unlink(missing_ok=True)
            batch["downloaded"].append(entry)
        else:
            remove_entry_files(day, entry, keep_original=is_complete(day, by_entry[entry]))
    kept = []
    for entry in batch["downloaded"]:
        if pieces_complete(day, state, entry):
            kept.append(entry)
        else:
            remove_entry_files(day, entry)
    batch["downloaded"] = kept
    batch["downloading"] = []
    save_state(day, state)
    return [entry for entry in batch["entries"] if entry not in kept]


def download_batch_entries(day, state, batch, by_entry, todo):
    key = by_entry[todo[0]]["archive"]
    url = archive_url(key)
    size, entries, central = fetch_central_directory(key)
    total = len(batch["entries"])
    for entry in todo:
        row = by_entry[entry]
        expected = int(row["uncompressed_size"])
        output = pcap_dir(day) / output_name(day, entry)
        part = output.with_name(output.name + ".part")
        will_split = expected > SPLIT_BYTES
        have_original = is_complete(day, row)
        ensure_free_space(pcap_dir(day), (0 if have_original else expected) + (expected if will_split else 0))
        batch["downloading"].append(entry)
        save_state(day, state)
        print(f"  [{len(batch['downloaded']) + 1}/{total}] {entry} -> {output.name}")
        if not have_original:
            name, compressed_size, local_offset = find_entry(central, entry)
            crc = entry_crc(central, entry)
            written = extract_entry(url, compressed_size, local_offset, crc, expected, part)
            os.replace(part, output)
            print(f"      saved {written:,} bytes")
        if will_split:
            pieces = split_pcap(output, SPLIT_BYTES)
            print(f"      split into {len(pieces)} piece(s)")
        else:
            pieces = [output]
        state["pieces"][entry] = [{"name": path.name, "size": path.stat().st_size} for path in pieces]
        save_state(day, state)
        if will_split:
            output.unlink()
        batch["downloading"].remove(entry)
        batch["downloaded"].append(entry)
        save_state(day, state)


def download_batch(day, index):
    state = load_state(day)
    if state["deleted"]:
        return None
    if "batches" not in state:
        raise ValueError(f"No batch plan for {day}; call plan(day) first")
    batch = state["batches"][index]
    if batch["deleted"]:
        return None
    by_entry = {row["entry"]: row for row in load_rows(day)}
    todo = reconcile_batch(day, state, batch, by_entry)
    print(f"  batch {index + 1}/{len(state['batches'])}: {len(batch['downloaded'])} downloaded, {len(todo)} to download")
    if todo:
        download_batch_entries(day, state, batch, by_entry, todo)
    return [[pcap_dir(day) / piece["name"] for piece in state["pieces"][entry]] for entry in batch["entries"]]


def delete_batch(day, index):
    state = load_state(day)
    batch = state["batches"][index]
    batch["deleted"] = True
    if all(item["deleted"] for item in state["batches"]):
        state["deleted"] = True
    save_state(day, state)
    for entry in batch["entries"]:
        remove_entry_files(day, entry)
    if state["deleted"] and pcap_dir(day).exists():
        shutil.rmtree(pcap_dir(day))