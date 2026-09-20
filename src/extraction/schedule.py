from datetime import datetime, timedelta
from pathlib import Path

from src.core.config import config_loader

# Ambiguity margin around each attack's official start/finish time.
# A flow landing inside this band (but outside the raw window) is treated
# as boundary-ambiguous, never as a confident match either way.
BOUNDARY_MARGIN = timedelta(seconds=60)

PROTOCOL_CODES = {"tcp": 6, "udp": 17}


def protocol_code(hint):
    if hint is None:
        return None
    return PROTOCOL_CODES.get(hint.lower())


def parse_schedule_datetime(date_str, time_str):
    return datetime.strptime(f"{date_str} {time_str}", "%Y-%m-%d %H:%M")


def load_schedule(path: Path):
    raw = config_loader(path)

    entries = []
    for item in raw["schedule"]:
        start_dt = parse_schedule_datetime(item["date"], item["start_time"])
        finish_dt = parse_schedule_datetime(item["date"], item["finish_time"])

        entries.append({
            "id": item["id"],
            "attack_name": item["attack_name"],
            "start_dt": start_dt,
            "finish_dt": finish_dt,
            "boundary_start": start_dt - BOUNDARY_MARGIN,
            "boundary_finish": finish_dt + BOUNDARY_MARGIN,
            "attacker_ips": set(item["attacker_ips"]),
            "victim_ips": set(item["victim_ips"]),
            "protocol_hint": protocol_code(item.get("protocol_hint")),
            "port_hint": item.get("port_hint"),  # parsed but not enforced (by request)
            "confidence": item.get("confidence", "low"),
        })

    return entries