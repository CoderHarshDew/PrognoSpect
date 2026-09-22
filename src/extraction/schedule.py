from datetime import datetime
from pathlib import Path

from src.core.config import config_loader

PROTOCOL_CODES = {"tcp": 6, "udp": 17, "icmp": 1}


def parse_schedule_datetime(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00")).replace(tzinfo=None)


def protocol_code(value):
    if value is None or isinstance(value, int):
        return value
    return PROTOCOL_CODES[value.lower()]


def load_schedule(path: Path):
    raw = config_loader(path)

    rules = []
    for day in raw["days"]:
        for attack in day["attacks"]:
            for rule in attack["rules"]:
                src_ips = rule.get("src_ips")
                dst_ips = rule.get("dst_ips")
                dst_ports = rule.get("dst_ports")

                rules.append({
                    "label": rule["label"],
                    "start_dt": parse_schedule_datetime(rule["start"]),
                    "finish_dt": parse_schedule_datetime(rule["finish"]),
                    "src_ips": set(src_ips) if src_ips is not None else None,
                    "dst_ips": set(dst_ips) if dst_ips is not None else None,
                    "dst_ports": set(dst_ports) if dst_ports is not None else None,
                    "protocol": protocol_code(rule.get("protocol")),
                    "payload_filter": rule.get("payload_filter", False),
                    "extra_conditions": rule.get("extra_conditions", []),
                })

    return rules