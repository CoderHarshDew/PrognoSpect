from __future__ import annotations

import csv
from pathlib import Path
from typing import Dict, Iterator, List, Set, Tuple

from src.core.logger import logger
from src.extraction.providers import cicflowmeter


def _run_provider(provider_name: str, pcap_path: Path, config: Dict, schema: List[Dict[str, str]]) -> Iterator[Dict[str, str]]:
    if provider_name == "cicflowmeter":
        cfg = config.get("cicflowmeter", {})
        if not cfg.get("enabled", True):
            return iter(())
        return cicflowmeter.extract(pcap_path, cfg, schema)
    logger.error("Unknown provider '%s' listed in config.", provider_name)
    raise ValueError(f"Unknown provider '{provider_name}' listed in config.")


def run(pcap_path: Path, config: Dict) -> Path:
    schema = config["schema"]
    target_columns = [entry["target"] for entry in schema]
    missing_value = config.get("output", {}).get("missing_value", "")

    flows: Dict[Tuple[str, str], Dict[str, str]] = {}
    for provider_name in config["providers"]:
        logger.info("Running provider: %s", provider_name)
        count = 0
        seen: Set[Tuple[str, str]] = set()
        for row in _run_provider(provider_name, pcap_path, config, schema):
            flow_id = row.get("Flow ID")
            if not flow_id:
                logger.error("Provider '%s' yielded a row with no Flow ID.", provider_name)
                raise ValueError(f"Provider '{provider_name}' yielded a row with no Flow ID.")
            timestamp = row.get("Timestamp")
            if not timestamp:
                logger.error("Provider '%s' yielded a row with no Timestamp.", provider_name)
                raise ValueError(f"Provider '{provider_name}' yielded a row with no Timestamp.")
            key = (flow_id, timestamp)
            if key in seen:
                logger.error("Provider '%s' yielded a duplicate (Flow ID, Timestamp) key: %s.", provider_name, key)
                raise ValueError(f"Provider '{provider_name}' yielded a duplicate (Flow ID, Timestamp) key: {key}.")
            seen.add(key)
            flows.setdefault(key, {}).update(row)
            count += 1
        logger.info("Provider '%s' produced %d flow(s).", provider_name, count)

    output_path = Path(config["output"]["path"])
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", encoding="utf-8", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=target_columns)
        writer.writeheader()
        for row in flows.values():
            writer.writerow({col: row.get(col, missing_value) for col in target_columns})
    logger.info("Wrote %d flow(s) to %s", len(flows), output_path)
    return output_path