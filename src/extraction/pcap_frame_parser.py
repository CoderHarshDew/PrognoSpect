from __future__ import annotations
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Tuple
import struct
from src.core.config import config_loader

DEFAULT_CONFIG_PATH = Path("config/extraction/pcap_frame_parser.yaml")
DEFAULT_PACKET_LEVEL_CONFIG_PATH = Path("config/extraction/pcap_packet_level_parser.yaml")


@dataclass(slots=True)
class ParsedFrame:
    timestamp: Any
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]


@dataclass(slots=True)
class ParsedPacketLevelFrame:
    timestamp: Any
    src_ip: Optional[str]
    dst_ip: Optional[str]
    src_port: Optional[int]
    dst_port: Optional[int]
    protocol: Optional[str]
    ip_version: Optional[int]
    ttl: Optional[int]
    is_fragmented: Optional[bool]
    fragment_offset: Optional[int]
    payload_length: Optional[int]
    tcp_window: Optional[int]
    tcp_seq: Optional[int]
    tcp_ack: Optional[int]
    tcp_flags: Optional[int]


@dataclass(slots=True)
class _IPHeaderLocation:
    ip_version: int
    ip_start: int
    ip_header_length: int
    l4_start: int
    protocol_number: int
    protocol_label: Optional[str]
    src_ip: str
    dst_ip: str


def _format_ipv6(raw: bytes) -> str:
    groups = struct.unpack(">8H", raw)
    return ":".join(f"{g:x}" for g in groups)


def _locate_ip_header(data: bytes, eth: Dict[str, Any], ipv4: Dict[str, Any], ipv6: Dict[str, Any], protocol_number_to_label: Dict[int, str]) -> Optional[_IPHeaderLocation]:
    eth_header_length = eth["header_length"]
    if len(data) < eth_header_length:
        return None

    ethertype_offset = eth["ethertype_offset"]
    ethertype = struct.unpack(">H", data[ethertype_offset:ethertype_offset + 2])[0]
    ip_start = eth_header_length

    if ethertype == eth["ipv4_ethertype"]:
        min_ip_header_length = ipv4["min_header_length"]
        if len(data) < ip_start + min_ip_header_length:
            return None
        version_ihl_byte = data[ip_start + ipv4["version_ihl_offset"]]
        ihl = version_ihl_byte & ipv4["ihl_low_nibble_mask"]
        ip_header_length = ihl * ipv4["ihl_word_size"]
        if ip_header_length < min_ip_header_length or len(data) < ip_start + ip_header_length:
            return None
        protocol_number = data[ip_start + ipv4["protocol_offset"]]
        src_ip_offset = ip_start + ipv4["src_ip_offset"]
        dst_ip_offset = ip_start + ipv4["dst_ip_offset"]
        src_ip = ".".join(str(b) for b in data[src_ip_offset:src_ip_offset + 4])
        dst_ip = ".".join(str(b) for b in data[dst_ip_offset:dst_ip_offset + 4])
        return _IPHeaderLocation(
            ip_version=4, ip_start=ip_start, ip_header_length=ip_header_length,
            l4_start=ip_start + ip_header_length, protocol_number=protocol_number,
            protocol_label=protocol_number_to_label.get(protocol_number),
            src_ip=src_ip, dst_ip=dst_ip,
        )

    if ethertype == eth["ipv6_ethertype"]:
        ip_header_length = ipv6["header_length"]
        if len(data) < ip_start + ip_header_length:
            return None
        protocol_number = data[ip_start + ipv6["next_header_offset"]]
        src_ip_offset = ip_start + ipv6["src_ip_offset"]
        dst_ip_offset = ip_start + ipv6["dst_ip_offset"]
        src_ip = _format_ipv6(data[src_ip_offset:src_ip_offset + 16])
        dst_ip = _format_ipv6(data[dst_ip_offset:dst_ip_offset + 16])
        return _IPHeaderLocation(
            ip_version=6, ip_start=ip_start, ip_header_length=ip_header_length,
            l4_start=ip_start + ip_header_length, protocol_number=protocol_number,
            protocol_label=protocol_number_to_label.get(protocol_number),
            src_ip=src_ip, dst_ip=dst_ip,
        )

    return None


def _locate_l4_ports(data: bytes, location: _IPHeaderLocation, tcp: Dict[str, Any], udp: Dict[str, Any], protocol_labels: Dict[str, str]) -> Tuple[Optional[int], Optional[int]]:
    if location.protocol_label is None:
        return None, None
    l4_config = tcp if location.protocol_label == protocol_labels["tcp"] else udp
    if len(data) < location.l4_start + l4_config["min_header_length"]:
        return None, None
    src_port_offset = location.l4_start + l4_config["src_port_offset"]
    dst_port_offset = location.l4_start + l4_config["dst_port_offset"]
    src_port = int.from_bytes(data[src_port_offset:src_port_offset + l4_config["src_port_length"]], "big")
    dst_port = int.from_bytes(data[dst_port_offset:dst_port_offset + l4_config["dst_port_length"]], "big")
    return src_port, dst_port


class PCAPFrameParser:

    def __init__(self, config_path: Path = DEFAULT_CONFIG_PATH):
        self.config = config_loader(config_path)
        self.eth = self.config["ethernet"]
        self.ipv4 = self.config["ipv4"]
        self.ipv6 = self.config["ipv6"]
        self.tcp = self.config["tcp"]
        self.udp = self.config["udp"]
        self.protocol_labels = self.config["protocol_labels"]
        self.output_field_names = self.config["output_field_names"]
        self._protocol_number_to_label = {
            self.ipv4["protocol_numbers"]["tcp"]: self.protocol_labels["tcp"],
            self.ipv4["protocol_numbers"]["udp"]: self.protocol_labels["udp"],
        }

    def parse(self, packet: Any) -> Dict[str, Any]:
        data = packet.data
        names = self.output_field_names
        result = {
            names["timestamp"]: packet.timestamp, names["src_ip"]: None, names["dst_ip"]: None,
            names["src_port"]: None, names["dst_port"]: None, names["protocol"]: None,
        }

        location = _locate_ip_header(data, self.eth, self.ipv4, self.ipv6, self._protocol_number_to_label)
        if location is None:
            return result

        result[names["src_ip"]] = location.src_ip
        result[names["dst_ip"]] = location.dst_ip
        result[names["protocol"]] = location.protocol_label

        if location.protocol_label is None:
            return result

        src_port, dst_port = _locate_l4_ports(data, location, self.tcp, self.udp, self.protocol_labels)
        result[names["src_port"]] = src_port
        result[names["dst_port"]] = dst_port
        return result


class PCAPPacketLevelParser:

    def __init__(self, config_path: Path = DEFAULT_PACKET_LEVEL_CONFIG_PATH):
        self.config = config_loader(config_path)
        self.eth = self.config["ethernet"]
        self.ipv4 = self.config["ipv4"]
        self.ipv6 = self.config["ipv6"]
        self.tcp = self.config["tcp"]
        self.udp = self.config["udp"]
        self.protocol_labels = self.config["protocol_labels"]
        self.output_field_names = self.config["output_field_names"]
        self._protocol_number_to_label = {
            self.ipv4["protocol_numbers"]["tcp"]: self.protocol_labels["tcp"],
            self.ipv4["protocol_numbers"]["udp"]: self.protocol_labels["udp"],
        }

    def parse(self, packet: Any) -> Dict[str, Any]:
        data = packet.data
        names = self.output_field_names
        result = {name: None for name in names.values()}
        result[names["timestamp"]] = packet.timestamp

        location = _locate_ip_header(data, self.eth, self.ipv4, self.ipv6, self._protocol_number_to_label)
        if location is None:
            return result

        result[names["src_ip"]] = location.src_ip
        result[names["dst_ip"]] = location.dst_ip
        result[names["protocol"]] = location.protocol_label
        result[names["ip_version"]] = location.ip_version

        if location.ip_version == 4:
            result[names["ttl"]] = data[location.ip_start + self.ipv4["ttl_offset"]]
            flags_fragment_offset = location.ip_start + self.ipv4["flags_fragment_offset"]
            flags_fragment = struct.unpack(">H", data[flags_fragment_offset:flags_fragment_offset + 2])[0]
            fragment_offset = flags_fragment & self.ipv4["fragment_offset_mask"]
            more_fragments = bool(flags_fragment & self.ipv4["more_fragments_flag_mask"])
            result[names["fragment_offset"]] = fragment_offset
            result[names["is_fragmented"]] = more_fragments or fragment_offset > 0
            total_length_offset = location.ip_start + self.ipv4["total_length_offset"]
            total_length = struct.unpack(">H", data[total_length_offset:total_length_offset + 2])[0]
            l4_total_length = total_length - location.ip_header_length
        else:
            result[names["ttl"]] = data[location.ip_start + self.ipv6["hop_limit_offset"]]
            payload_length_offset = location.ip_start + self.ipv6["payload_length_offset"]
            l4_total_length = struct.unpack(">H", data[payload_length_offset:payload_length_offset + 2])[0]

        if location.protocol_label is None:
            return result

        l4_config = self.tcp if location.protocol_label == self.protocol_labels["tcp"] else self.udp
        if len(data) < location.l4_start + l4_config["min_header_length"]:
            return result

        src_port, dst_port = _locate_l4_ports(data, location, self.tcp, self.udp, self.protocol_labels)
        result[names["src_port"]] = src_port
        result[names["dst_port"]] = dst_port

        if location.protocol_label == self.protocol_labels["tcp"]:
            data_offset_byte = data[location.l4_start + self.tcp["data_offset_offset"]]
            words = (data_offset_byte & self.tcp["data_offset_high_nibble_mask"]) >> self.tcp["data_offset_shift"]
            tcp_header_length = words * self.tcp["data_offset_word_size"]
            if len(data) < location.l4_start + tcp_header_length:
                return result
            result[names["payload_length"]] = l4_total_length - tcp_header_length
            window_offset = location.l4_start + self.tcp["window_offset"]
            seq_offset = location.l4_start + self.tcp["seq_offset"]
            ack_offset = location.l4_start + self.tcp["ack_offset"]
            result[names["tcp_window"]] = struct.unpack(">H", data[window_offset:window_offset + 2])[0]
            result[names["tcp_seq"]] = struct.unpack(">I", data[seq_offset:seq_offset + 4])[0]
            result[names["tcp_ack"]] = struct.unpack(">I", data[ack_offset:ack_offset + 4])[0]
            result[names["tcp_flags"]] = data[location.l4_start + self.tcp["flags_offset"]]
        else:
            result[names["payload_length"]] = l4_total_length - self.udp["min_header_length"]

        return result