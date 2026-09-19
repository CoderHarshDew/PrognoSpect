import csv
from itertools import islice
from pathlib import Path
from typing import Dict, Iterable, List
from src.core.logger import logger


DEFAULT_CHUNK_SIZE = 100_000


def _existing_header(output_path: Path) -> List[str]:
    with output_path.open('r', encoding='utf-8', newline='') as f:
        return next(csv.reader(f), [])


def write_csv_in_chunks(output_path: str | Path, fieldnames: List[str], rows: Iterable[Dict], chunk_size: int = DEFAULT_CHUNK_SIZE, append: bool = False) -> int:
    output_path = Path(output_path)
    fieldnames = list(fieldnames)

    output_path.parent.mkdir(parents=True, exist_ok=True)

    has_content = output_path.exists() and output_path.stat().st_size > 0
    write_header = not (append and has_content)

    if not write_header:
        existing_header = _existing_header(output_path)

        if existing_header != fieldnames:
            logger.error("Cannot append to %s: existing header %s does not match %s.", output_path, existing_header, fieldnames)
            raise ValueError(f"Header mismatch while appending to {output_path}")

    logger.info("Writing CSV in chunks of %d row(s): %s | Mode: %s", chunk_size, output_path, 'append' if append else 'write')

    rows = iter(rows)
    total_rows = 0
    total_chunks = 0

    with output_path.open('a' if append else 'w', encoding='utf-8', newline='') as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)

        if write_header:
            writer.writeheader()

        while chunk := list(islice(rows, chunk_size)):
            writer.writerows(chunk)
            total_rows += len(chunk)
            total_chunks += 1

            logger.debug("Wrote chunk %d to %s. Rows: %d | Total rows: %d", total_chunks, output_path, len(chunk), total_rows)

    logger.info("Finished writing %s. Chunks: %d | Rows: %d", output_path, total_chunks, total_rows)

    return total_rows