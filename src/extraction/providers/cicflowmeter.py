from __future__ import annotations

import csv
import logging
import subprocess
from pathlib import Path
from typing import Dict, Iterator, List, Tuple

logger = logging.getLogger(__name__)


def _build_rename_and_duplicate_maps(schema: List[Dict[str, str]]) -> Tuple[Dict[str, str], List[Tuple[str, str]]]:
    renames: Dict[str, str] = {}
    duplicates: List[Tuple[str, str]] = []
    for entry in schema:
        target = entry["target"]
        if "source" in entry:
            renames[entry["source"]] = target
        elif "duplicate_of" in entry:
            duplicates.append((target, entry["duplicate_of"]))
    return renames, duplicates


def run_cicflowmeter(pcap_path: Path, executable: Path, work_dir: Path) -> Path:
    if not pcap_path.is_file():
        raise FileNotFoundError(f"PCAP not found: {pcap_path}")
    if not executable.is_file():
        raise FileNotFoundError(f"CICFlowMeter executable not found: {executable}")
    logger.info("Running CICFlowMeter on %s", pcap_path)
    result = subprocess.run([str(executable), str(pcap_path), str(work_dir)], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(f"CICFlowMeter exited with code {result.returncode} while processing {pcap_path}.\n--- stdout ---\n{result.stdout}\n--- stderr ---\n{result.stderr}")
    raw_csv_path = work_dir / f"{pcap_path.name}_Flow.csv"
    if not raw_csv_path.is_file():
        raise RuntimeError(f"CICFlowMeter reported success but its expected output was not found at {raw_csv_path}.\n--- stdout ---\n{result.stdout}")
    return raw_csv_path


def remap_rows(raw_csv_path: Path, schema: List[Dict[str, str]]) -> Iterator[Dict[str, str]]:
    renames, duplicates = _build_rename_and_duplicate_maps(schema)
    with raw_csv_path.open("r", encoding="utf-8", newline="") as f:
        reader = csv.DictReader(f)
        available = set(reader.fieldnames or [])
        missing = sorted(set(renames) - available)
        if missing:
            raise RuntimeError(f"CICFlowMeter output at {raw_csv_path} is missing expected column(s): {missing}. The build's output schema may have changed -- update the YAML schema mapping in flow_extraction.yaml.")
        row_count = 0
        for row in reader:
            mapped: Dict[str, str] = {target: row[source] for source, target in renames.items()}
            for target, copy_of in duplicates:
                mapped[target] = mapped.get(copy_of, "")
            row_count += 1
            yield mapped
        logger.info("Parsed %d flow row(s) from %s", row_count, raw_csv_path)


def extract(pcap_path: Path, cicflowmeter_config: Dict, schema: List[Dict[str, str]]) -> Iterator[Dict[str, str]]:
    executable = Path(cicflowmeter_config["executable"])
    work_dir = Path(cicflowmeter_config["work_dir"])
    preserve_intermediate_csv = cicflowmeter_config.get("preserve_intermediate_csv", False)
    work_dir.mkdir(parents=True, exist_ok=True)
    raw_csv_path = run_cicflowmeter(pcap_path, executable, work_dir)
    try:
        yield from remap_rows(raw_csv_path, schema)
    finally:
        if not preserve_intermediate_csv and raw_csv_path.exists():
            raw_csv_path.unlink()