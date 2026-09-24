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
from src.core.logger import logger

BASE_DIR = Path("dataset/pcap")
LISTS_DIR = BASE_DIR / "lists"
STATE_DIR = BASE_DIR / "state"
ALL_LIST = LISTS_DIR / "pcaps_all.csv"
LIMIT = 5
CHUNK_SIZE = 256 * 1024
RETRIES = 5
PROGRESS_INTERVAL = 1.0
LOG_PROGRESS_INTERVAL = 60.0
LOG_CLOCK_CHECK_PACKETS = 100_000
CURL_LIMITS = ["--connect-timeout", "30", "--speed-limit", "1024", "--speed-time", "60"]
BATCH_BYTES = 20 * 10**9
SPLIT_BYTES = 10**9
DISK_RESERVE_BYTES = 10 * 10**9
GLOBAL_HEADER_SIZE = 24
RECORD_HEADER_SIZE = 16
MAX_RECORD_BYTES = 16 * 1024 * 1024
SPLIT_BUFFER_SIZE = 8 * 1024 * 1024
PCAP_MAGICS = {b"\xd4\xc3\xb2\xa1": "<", b"\xa1\xb2\xc3\xd4": ">", b"\x4d\x3c\xb2\xa1": "<", b"\xa1\xb2\x3c\x4d": ">"}
PCAPNG_SHB_MAGIC = b"\x0a\x0d\x0d\x0a"
PCAPNG_BOM = 0x1A2B3C4D
PCAPNG_SHB_TYPE = 0x0A0D0D0A
PCAPNG_IDB_TYPE = 0x00000001
PCAPNG_PB_TYPE = 0x00000002
PCAPNG_SPB_TYPE = 0x00000003
PCAPNG_EPB_TYPE = 0x00000006


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
        logger.error("No PCAPs listed for %s in %s or %s.", day, per_day, ALL_LIST)
        raise ValueError(f"No PCAPs listed for {day}")
    logger.info("Loaded %d listed PCAP(s) for %s.", len(rows), day)
    return rows


def new_state():
    return {"downloaded": [], "downloading": [], "to_download": [], "deleted": False}


def load_state(day):
    path = state_path(day)
    if not path.exists():
        logger.info("No saved state for %s at %s; starting with a new state.", day, path)
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
            logger.error("Invalid central-directory entry at offset %d while looking for %s.", offset, entry_name)
            raise ValueError(f"Invalid central-directory entry at offset {offset}")
        crc = struct.unpack_from("<I", central, offset + 16)[0]
        name_length, extra_length, comment_length = struct.unpack_from("<HHH", central, offset + 28)
        name = central[offset + 46:offset + 46 + name_length].decode("utf-8")
        if name == entry_name:
            return crc
        offset += 46 + name_length + extra_length + comment_length
    logger.error("Entry not found in central directory: %s", entry_name)
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
            logger.error("Giving up on bytes %d-%d of %s after %d retries: %s", start, end, url, RETRIES, problem)
            raise RuntimeError(problem)
        logger.warning("Connection problem (%s); retry %d/%d from byte %d of range %d-%d.", problem, failures, RETRIES, position, start, end)
        print(f"\n  connection problem ({problem}); retry {failures}/{RETRIES} from byte {position:,}")
        time.sleep(min(5 * failures, 30))


def show_progress(received, total, seconds):
    speed = received / seconds / 1e6 if seconds > 0 else 0.0
    print(f"\r      {received / total:6.1%}  {received / 1e6:,.1f} / {total / 1e6:,.1f} MB compressed  {speed:.2f} MB/s", end="", flush=True)


def extract_entry(url, compressed_size, local_offset, expected_crc, expected_size, output):
    logger.info("Extracting to %s | Compressed: %d bytes | Expected: %d bytes", output, compressed_size, expected_size)
    header = b"".join(stream_range(url, local_offset, local_offset + 29))
    if header[:4] != b"PK\x03\x04":
        logger.error("Invalid local ZIP header at offset %d for %s (first bytes: %s).", local_offset, output, header[:4].hex())
        raise ValueError("Invalid local ZIP header")
    filename_length, extra_length = struct.unpack_from("<HH", header, 26)
    data_start = local_offset + 30 + filename_length + extra_length
    decompressor = zlib.decompressobj(-15)
    crc = 0
    received = 0
    written = 0
    started = time.monotonic()
    last_shown = started
    last_logged = started
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
                if now - last_logged >= LOG_PROGRESS_INTERVAL:
                    last_logged = now
                    logger.info("Download progress: %s | %.1f%% of %.1f MB compressed | %.2f MB/s", output.name, received / compressed_size * 100, compressed_size / 1e6, received / (now - started) / 1e6)
        data = decompressor.flush()
        crc = zlib.crc32(data, crc)
        written += len(data)
        handle.write(data)
    show_progress(received, compressed_size, time.monotonic() - started)
    print()
    if received != compressed_size or not decompressor.eof:
        logger.error("Incomplete download of %s: received %d of %d compressed bytes.", output, received, compressed_size)
        raise ValueError(f"Incomplete download: received {received:,} of {compressed_size:,} compressed bytes")
    if written != expected_size:
        logger.error("Size mismatch for %s: wrote %d bytes, expected %d.", output, written, expected_size)
        raise ValueError(f"Size mismatch: wrote {written:,}, expected {expected_size:,}")
    if crc != expected_crc:
        logger.error("CRC32 mismatch for %s: got %08x, expected %08x.", output, crc, expected_crc)
        raise ValueError(f"CRC32 mismatch: got {crc:08x}, expected {expected_crc:08x}")
    logger.info("Extracted %s | Bytes: %d | Elapsed: %.1f s", output, written, time.monotonic() - started)
    return written


def reconcile(day, rows, state, limit):
    pcap_dir(day).mkdir(parents=True, exist_ok=True)
    for part in pcap_dir(day).glob("*.part"):
        logger.debug("Removing stale partial file: %s", part)
        part.unlink()
    for entry in state["downloading"]:
        logger.info("Discarding interrupted download: %s", entry)
        (pcap_dir(day) / output_name(day, entry)).unlink(missing_ok=True)
    by_entry = {row["entry"]: row for row in rows}
    downloaded = [entry for entry in state["downloaded"] if entry in by_entry and is_complete(day, by_entry[entry])]
    wanted = [row["entry"] for row in rows[:limit]]
    state["downloaded"] = downloaded
    state["downloading"] = []
    state["to_download"] = [entry for entry in wanted if entry not in downloaded]
    save_state(day, state)
    logger.info("Reconciled %s | Downloaded: %d | To download: %d", day, len(downloaded), len(state["to_download"]))


def download_entries(day, rows, state):
    by_entry = {row["entry"]: row for row in rows}
    key = rows[0]["archive"]
    url = archive_url(key)
    total = len(state["downloaded"]) + len(state["to_download"])
    size, entries, central = fetch_central_directory(key)
    logger.info("Fetched central directory for %s | Central directory: %d bytes", key, len(central))
    for entry in list(state["to_download"]):
        output = pcap_dir(day) / output_name(day, entry)
        part = output.with_name(output.name + ".part")
        state["to_download"].remove(entry)
        state["downloading"].append(entry)
        save_state(day, state)
        print(f"  [{len(state['downloaded']) + 1}/{total}] {entry} -> {output.name}")
        logger.info("Downloading [%d/%d]: %s -> %s", len(state["downloaded"]) + 1, total, entry, output.name)
        name, compressed_size, local_offset = find_entry(central, entry)
        crc = entry_crc(central, entry)
        expected = int(by_entry[entry]["uncompressed_size"])
        written = extract_entry(url, compressed_size, local_offset, crc, expected, part)
        os.replace(part, output)
        state["downloading"].remove(entry)
        state["downloaded"].append(entry)
        save_state(day, state)
        print(f"      saved {written:,} bytes")
        logger.info("Saved %s | Bytes: %d | Downloaded: %d/%d", output.name, written, len(state["downloaded"]), total)


def download(day, limit=LIMIT):
    state = load_state(day)
    if state["deleted"]:
        logger.info("Skipping download for %s: data already deleted.", day)
        return None
    rows = load_rows(day)
    logger.info("Starting download for %s | Limit: %s", day, limit)
    reconcile(day, rows, state, limit)
    print(f"  {len(state['downloaded'])} downloaded, {len(state['to_download'])} to download")
    if state["to_download"]:
        download_entries(day, rows, state)
    logger.info("Finished download for %s | Files: %d", day, len(state["downloaded"]))
    return [pcap_dir(day) / output_name(day, entry) for entry in state["downloaded"]]


def delete(day):
    logger.info("Deleting data for %s.", day)
    state = load_state(day)
    state["deleted"] = True
    save_state(day, state)
    if pcap_dir(day).exists():
        shutil.rmtree(pcap_dir(day))
        logger.info("Removed directory %s.", pcap_dir(day))


def ensure_free_space(path, needed, reserve=None):
    reserve = DISK_RESERVE_BYTES if reserve is None else reserve
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    free = shutil.disk_usage(path).free
    required = needed + reserve
    if free < required:
        logger.error("Not enough disk space at %s | Required: %.1f GB | Free: %.1f GB", path.resolve(), required / 1e9, free / 1e9)
        raise RuntimeError(f"Not enough disk space at {path.resolve()}: need {required / 1e9:,.1f} GB free ({needed / 1e9:,.1f} GB for the next step plus a {reserve / 1e9:,.1f} GB reserve) but only {free / 1e9:,.1f} GB is available. Free some space (for example move finished CSVs to another drive) and run the same command again.")
    logger.debug("Disk space OK at %s | Required: %.1f GB | Free: %.1f GB", path, required / 1e9, free / 1e9)


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
    logger.debug("Opened piece %s.", final.name)
    return handle, part


def close_piece(handle, part, final):
    handle.close()
    os.replace(part, final)
    logger.info("Closed piece %s | Size: %d bytes", final.name, final.stat().st_size)
    return final


def pcapng_endian(bom_bytes):
    if struct.unpack("<I", bom_bytes)[0] == PCAPNG_BOM:
        return "<"
    if struct.unpack(">I", bom_bytes)[0] == PCAPNG_BOM:
        return ">"
    logger.error("Invalid pcapng byte-order magic: %s", bom_bytes.hex())
    raise ValueError("Invalid pcapng byte-order magic")


def read_pcapng_block(handle, endian):
    head = handle.read(8)
    if not head:
        return None, b"", endian
    if len(head) < 8:
        logger.error("Truncated pcapng block header in %s at byte %d.", handle.name, handle.tell())
        raise ValueError("Truncated pcapng block header")
    if endian is None:
        if head[:4] != PCAPNG_SHB_MAGIC:
            logger.error("Expected a pcapng section header block in %s but found %s.", handle.name, head[:4].hex())
            raise ValueError("Expected a pcapng section header block")
        bom = handle.read(4)
        if len(bom) < 4:
            logger.error("Truncated pcapng section header block in %s: byte-order magic incomplete.", handle.name)
            raise ValueError("Truncated pcapng section header block")
        endian = pcapng_endian(bom)
        length = struct.unpack(endian + "I", head[4:8])[0]
        rest = handle.read(length - 12)
        if len(rest) < length - 12:
            logger.error("Truncated pcapng section header block in %s: block length %d, read %d bytes.", handle.name, length, 12 + len(rest))
            raise ValueError("Truncated pcapng section header block")
        block_type = struct.unpack(endian + "I", head[:4])[0]
        return block_type, head + bom + rest, endian
    block_type = struct.unpack(endian + "I", head[:4])[0]
    length = struct.unpack(endian + "I", head[4:8])[0]
    if length < 12:
        logger.error("Corrupt pcapng block length %d in %s at byte %d.", length, handle.name, handle.tell())
        raise ValueError("Corrupt pcapng block length")
    rest = handle.read(length - 8)
    if len(rest) < length - 8:
        logger.error("Truncated pcapng block in %s: block length %d, read %d bytes.", handle.name, length, 8 + len(rest))
        raise ValueError("Truncated pcapng block")
    return block_type, head + rest, endian


def is_pcapng(path):
    with open(path, "rb") as handle:
        return handle.read(4) == PCAPNG_SHB_MAGIC


def parse_idb(raw, endian):
    body = raw[8:-4]
    linktype = struct.unpack_from(endian + "H", body, 0)[0]
    snaplen = struct.unpack_from(endian + "I", body, 4)[0] or 262144
    tsresol = 1e-6
    offset = 8
    while offset + 4 <= len(body):
        opt_code, opt_len = struct.unpack_from(endian + "HH", body, offset)
        offset += 4
        if opt_code == 0:
            break
        value = body[offset:offset + opt_len]
        if opt_code == 9 and value:
            byte = value[0]
            tsresol = 2.0 ** -(byte & 0x7F) if byte & 0x80 else 10.0 ** -byte
        offset += opt_len + ((-opt_len) % 4)
    return linktype, snaplen, tsresol


def convert_pcapng_to_pcap(source, dest):
    """CICFlowMeter (and the classic-pcap splitter below) only understand classic pcap,
    so any pcapng capture is rewritten into a classic pcap file before it's used further."""
    source = Path(source)
    dest = Path(dest)
    part = dest.with_name(dest.name + ".part")
    linktype, snaplen, tsresol = 1, 262144, 1e-6
    wrote_header = False
    packets = 0
    source_size = source.stat().st_size
    started = time.monotonic()
    last_logged = started
    logger.info("Converting pcapng to classic pcap: %s -> %s | Size: %d bytes", source, dest, source_size)
    try:
        with open(source, "rb") as handle, open(part, "wb") as out:
            block_type, raw, endian = read_pcapng_block(handle, None)
            if block_type != PCAPNG_SHB_TYPE:
                logger.error("Unsupported capture format in %s; expected a pcapng section header block.", source.name)
                raise ValueError(f"Unsupported capture format in {source.name}; expected a pcapng section header block")
            while True:
                block_type, raw, endian = read_pcapng_block(handle, endian)
                if block_type is None:
                    break
                if block_type in (PCAPNG_SHB_TYPE, PCAPNG_IDB_TYPE):
                    if block_type == PCAPNG_IDB_TYPE and not wrote_header:
                        linktype, snaplen, tsresol = parse_idb(raw, endian)
                    continue
                if block_type in (PCAPNG_EPB_TYPE, PCAPNG_PB_TYPE):
                    body = raw[8:-4]
                    ts_high, ts_low, cap_len, orig_len = struct.unpack_from(endian + "IIII", body, 4)
                    data = body[20:20 + cap_len]
                    timestamp = ((ts_high << 32) | ts_low) * tsresol
                elif block_type == PCAPNG_SPB_TYPE:
                    body = raw[8:-4]
                    orig_len = struct.unpack_from(endian + "I", body, 0)[0]
                    cap_len = min(orig_len, snaplen)
                    data = body[4:4 + cap_len]
                    timestamp = 0.0
                else:
                    continue
                if not wrote_header:
                    out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
                    wrote_header = True
                ts_sec = int(timestamp)
                ts_usec = int(round((timestamp - ts_sec) * 1e6))
                if ts_usec >= 1_000_000:
                    ts_sec += 1
                    ts_usec -= 1_000_000
                out.write(struct.pack("<IIII", ts_sec, ts_usec, len(data), orig_len))
                out.write(data)
                packets += 1
                if packets % LOG_CLOCK_CHECK_PACKETS == 0 and time.monotonic() - last_logged >= LOG_PROGRESS_INTERVAL:
                    last_logged = time.monotonic()
                    logger.info("Conversion progress: %s | Packets: %d | %.1f%% of source read", source.name, packets, handle.tell() / source_size * 100)
            if not wrote_header:
                logger.warning("No packets found in %s; writing an empty classic pcap.", source.name)
                out.write(struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, snaplen, linktype))
        os.replace(part, dest)
        logger.info("Converted %s | Packets: %d | Elapsed: %.1f s", dest.name, packets, time.monotonic() - started)
    finally:
        part.unlink(missing_ok=True)
    return packets


def split_pcap(source, max_bytes):
    source = Path(source)
    logger.info("Splitting %s | Max piece size: %d bytes", source, max_bytes)
    with open(source, "rb") as probe:
        magic = probe.read(4)
    read_source = source
    converted = None
    if magic == PCAPNG_SHB_MAGIC:
        converted = source.with_name(source.stem + ".converting.pcap")
        convert_pcapng_to_pcap(source, converted)
        read_source = converted
    pieces = []
    output = None
    part = None
    final = None
    output_size = 0
    pending = 0
    position = 0
    consumed = GLOBAL_HEADER_SIZE
    buffer = bytearray()
    corrupt_at = None
    try:
        with open(read_source, "rb") as handle:
            header = handle.read(GLOBAL_HEADER_SIZE)
            if len(header) < GLOBAL_HEADER_SIZE or header[:4] not in PCAP_MAGICS:
                logger.error("Unsupported capture format in %s (first bytes: %s).", source.name, header[:4].hex() or "none")
                raise ValueError(f"Unsupported capture format (first bytes: {header[:4].hex() or 'none'}) in {source.name}; only classic pcap and pcapng files can be split")
            endian = PCAP_MAGICS[header[:4]]
            while True:
                chunk = handle.read(SPLIT_BUFFER_SIZE)
                buffer += chunk
                while len(buffer) - position >= RECORD_HEADER_SIZE:
                    included = struct.unpack_from(endian + "I", buffer, position + 8)[0]
                    if included > MAX_RECORD_BYTES:
                        corrupt_at = consumed + position
                        break
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
                if corrupt_at is not None:
                    logger.warning("Corrupt record header at byte %d of %s; truncating here, rest of file dropped.", corrupt_at, source.name)
                    print(f"      warning: corrupt record header at byte {corrupt_at:,} of {source.name}; truncating here, rest of file dropped")
                    buffer = bytearray()
                    break
                if not chunk:
                    break
            if buffer:
                logger.warning("Dropped %d trailing bytes of an incomplete record in %s.", len(buffer), source.name)
                print(f"      warning: dropped {len(buffer):,} trailing bytes of an incomplete record in {source.name}")
            if output is None and corrupt_at is None:
                final = source.with_name(f"{source.stem}-p001.pcap")
                output, part = open_piece(header, final)
            if output is not None:
                pieces.append(close_piece(output, part, final))
                output = None
    finally:
        if output is not None and not output.closed:
            output.close()
        if converted is not None:
            converted.unlink(missing_ok=True)
    logger.info("Split %s into %d piece(s).", source.name, len(pieces))
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
        logger.info("Skipping planning for %s: data already deleted.", day)
        return 0
    if "batches" not in state:
        rows = load_rows(day)[:limit]
        state["batches"] = [{"entries": entries, "downloaded": [], "downloading": [], "deleted": False} for entries in plan_batches(rows, BATCH_BYTES)]
        state["pieces"] = {}
        save_state(day, state)
        print(f"  planned {len(state['batches'])} batch(es) for {day}")
        logger.info("Planned %d batch(es) for %s | PCAPs: %d | Batch size: %d bytes", len(state["batches"]), day, len(rows), BATCH_BYTES)
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
    logger.debug("Removing files for %s (keep original: %s).", entry, keep_original)
    output = pcap_dir(day) / output_name(day, entry)
    if not keep_original:
        output.unlink(missing_ok=True)
    output.with_name(output.name + ".part").unlink(missing_ok=True)
    for path in piece_files(day, entry):
        path.unlink(missing_ok=True)


def reconcile_batch(day, state, batch, by_entry):
    pcap_dir(day).mkdir(parents=True, exist_ok=True)
    for part in pcap_dir(day).glob("*.part"):
        logger.debug("Removing stale partial file: %s", part)
        part.unlink()
    for entry in batch["downloading"]:
        if pieces_complete(day, state, entry):
            logger.info("Recovered interrupted entry with complete pieces: %s", entry)
            original = pcap_dir(day) / output_name(day, entry)
            if original.name not in [piece["name"] for piece in state["pieces"][entry]]:
                original.unlink(missing_ok=True)
            batch["downloaded"].append(entry)
        else:
            logger.info("Discarding incomplete interrupted entry; it will be redone: %s", entry)
            remove_entry_files(day, entry, keep_original=is_complete(day, by_entry[entry]))
    kept = []
    for entry in batch["downloaded"]:
        if pieces_complete(day, state, entry):
            kept.append(entry)
        else:
            logger.warning("Downloaded entry has missing or mismatched pieces; it will be downloaded again: %s", entry)
            remove_entry_files(day, entry)
    batch["downloaded"] = kept
    batch["downloading"] = []
    save_state(day, state)
    logger.info("Reconciled batch for %s | Kept: %d | To download: %d", day, len(kept), len(batch["entries"]) - len(kept))
    return [entry for entry in batch["entries"] if entry not in kept]


def download_batch_entries(day, state, batch, by_entry, todo):
    key = by_entry[todo[0]]["archive"]
    url = archive_url(key)
    size, entries, central = fetch_central_directory(key)
    logger.info("Fetched central directory for %s | Central directory: %d bytes", key, len(central))
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
        logger.info("Downloading [%d/%d]: %s -> %s | Expected: %d bytes | Original on disk: %s | Split: %s", len(batch["downloaded"]) + 1, total, entry, output.name, expected, have_original, will_split)
        if not have_original:
            name, compressed_size, local_offset = find_entry(central, entry)
            crc = entry_crc(central, entry)
            written = extract_entry(url, compressed_size, local_offset, crc, expected, part)
            os.replace(part, output)
            print(f"      saved {written:,} bytes")
        pcapng_source = is_pcapng(output)
        if will_split:
            pieces = split_pcap(output, SPLIT_BYTES)
            print(f"      split into {len(pieces)} piece(s)")
        elif pcapng_source:
            converted = output.with_name(f"{output.stem}-p001.pcap")
            convert_pcapng_to_pcap(output, converted)
            pieces = [converted]
            print("      converted to classic pcap")
        else:
            pieces = [output]
        state["pieces"][entry] = [{"name": path.name, "size": path.stat().st_size} for path in pieces]
        save_state(day, state)
        if will_split or pcapng_source:
            output.unlink()
        batch["downloading"].remove(entry)
        batch["downloaded"].append(entry)
        save_state(day, state)
        logger.info("Completed %s | Pieces: %d | Downloaded: %d/%d", entry, len(pieces), len(batch["downloaded"]), total)


def download_batch(day, index):
    state = load_state(day)
    if state["deleted"]:
        logger.info("Skipping batch %d for %s: data already deleted.", index + 1, day)
        return None
    if "batches" not in state:
        logger.error("No batch plan for %s; call plan(day) first.", day)
        raise ValueError(f"No batch plan for {day}; call plan(day) first")
    batch = state["batches"][index]
    if batch["deleted"]:
        logger.info("Skipping batch %d/%d for %s: batch already deleted.", index + 1, len(state["batches"]), day)
        return None
    by_entry = {row["entry"]: row for row in load_rows(day)}
    todo = reconcile_batch(day, state, batch, by_entry)
    print(f"  batch {index + 1}/{len(state['batches'])}: {len(batch['downloaded'])} downloaded, {len(todo)} to download")
    logger.info("Batch %d/%d for %s | Downloaded: %d | To download: %d", index + 1, len(state["batches"]), day, len(batch["downloaded"]), len(todo))
    if todo:
        download_batch_entries(day, state, batch, by_entry, todo)
    logger.info("Batch %d/%d for %s ready | PCAPs: %d", index + 1, len(state["batches"]), day, len(batch["entries"]))
    return [[pcap_dir(day) / piece["name"] for piece in state["pieces"][entry]] for entry in batch["entries"]]


def delete_batch(day, index):
    state = load_state(day)
    batch = state["batches"][index]
    logger.info("Deleting batch %d/%d for %s | PCAPs: %d", index + 1, len(state["batches"]), day, len(batch["entries"]))
    batch["deleted"] = True
    if all(item["deleted"] for item in state["batches"]):
        state["deleted"] = True
    save_state(day, state)
    for entry in batch["entries"]:
        remove_entry_files(day, entry)
    if state["deleted"] and pcap_dir(day).exists():
        shutil.rmtree(pcap_dir(day))
        logger.info("All batches deleted for %s; removed directory %s.", day, pcap_dir(day))