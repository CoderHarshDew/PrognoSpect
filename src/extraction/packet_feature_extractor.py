from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional, Tuple
import csv
import math
import statistics
from src.core.config import config_loader
from src.core.logger import logger
from src.database.pcap_reader import PCAPReader
from src.extraction.pcap_frame_parser import PCAPPacketLevelParser

DEFAULT_JOINER_CONFIG_PATH = Path("config/extraction/flow_packet_joiner.yaml")
DEFAULT_EXTRACTOR_CONFIG_PATH = Path("config/extraction/packet_feature_extractor.yaml")


@dataclass(slots=True)
class JoinedFlow:
    flow_id: Optional[str]
    protocol: str
    forward_packets: List[Dict[str, Any]]
    backward_packets: List[Dict[str, Any]]
    packet_data_complete: bool
    retransmission_count: Optional[int]


def _canonical_key(src_ip: str, src_port: int, dst_ip: str, dst_port: int, protocol: str) -> Tuple[Any, ...]:
    endpoint_a = (src_ip, src_port)
    endpoint_b = (dst_ip, dst_port)
    ordered = tuple(sorted((endpoint_a, endpoint_b)))
    return (ordered[0], ordered[1], protocol)


class FlowPacketJoiner:

    def __init__(self, config_path: Path = DEFAULT_JOINER_CONFIG_PATH):
        self.config = config_loader(config_path)
        self.column_mapping: Dict[str, str] = self.config["cicflowmeter_csv"]["column_mapping"]
        self.timestamp_format: str = self.config["cicflowmeter_csv"]["timestamp_format"]
        self.protocol_number_to_label: Dict[int, str] = self.config["protocol_number_to_label"]
        self.debug_logging: bool = self.config["truncation_handling"]["debug_logging"]
        self.completeness_field_name: str = self.config["truncation_handling"]["completeness_field_name"]
        self.packet_parser = PCAPPacketLevelParser()

    def _index_packets(self, pcap_path: Path, tshark_path: str) -> Tuple[Dict[Tuple[Any, ...], List[Dict[str, Any]]], Optional[datetime], bool]:
        index: Dict[Tuple[Any, ...], List[Dict[str, Any]]] = defaultdict(list)
        last_successful_timestamp: Optional[datetime] = None
        file_complete = True

        try:
            with PCAPReader(str(pcap_path), tshark_path=tshark_path) as reader:
                for packet in reader:
                    record = self.packet_parser.parse(packet)
                    last_successful_timestamp = record["timestamp"]
                    if record["src_ip"] is None or record["dst_ip"] is None or record["protocol"] is None:
                        continue
                    key = _canonical_key(record["src_ip"], record["src_port"], record["dst_ip"], record["dst_port"], record["protocol"])
                    index[key].append(record)
        except RuntimeError as error:
            file_complete = False
            if self.debug_logging:
                logger.debug("pcap %s truncated after last successful timestamp %s: %s", pcap_path, last_successful_timestamp, error)

        logger.info("indexed %d packet(s) into %d key(s) from %s (complete=%s)", sum(len(v) for v in index.values()), len(index), pcap_path, file_complete)
        return index, last_successful_timestamp, file_complete

    def _parse_row(self, row: Dict[str, str]) -> Optional[Dict[str, Any]]:
        try:
            src_ip = row[self.column_mapping["src_ip"]]
            src_port = int(row[self.column_mapping["src_port"]])
            dst_ip = row[self.column_mapping["dst_ip"]]
            dst_port = int(row[self.column_mapping["dst_port"]])
            protocol_number = int(row[self.column_mapping["protocol"]])
            protocol = self.protocol_number_to_label.get(protocol_number)
            timestamp = datetime.strptime(row[self.column_mapping["timestamp"]], self.timestamp_format).replace(tzinfo=timezone.utc)
            flow_duration_microseconds = float(row[self.column_mapping["flow_duration"]])
        except (KeyError, ValueError) as error:
            logger.warning("could not parse CICFlowMeter row, skipping: %s", error)
            return None
        if protocol is None:
            return None
        try:
            retransmission_count = int(float(row[self.column_mapping["retransmission_count"]]))
        except (KeyError, ValueError):
            retransmission_count = None
        return {
            "flow_id": row.get(self.column_mapping["flow_id"]), "src_ip": src_ip, "src_port": src_port,
            "dst_ip": dst_ip, "dst_port": dst_port, "protocol": protocol, "window_start": timestamp,
            "window_end": timestamp + timedelta(microseconds=flow_duration_microseconds),
            "retransmission_count": retransmission_count,
        }

    def join(self, pcap_path: Path, cicflowmeter_csv_path: Path, tshark_path: str) -> List[JoinedFlow]:
        index, last_successful_timestamp, file_complete = self._index_packets(pcap_path, tshark_path)
        joined_flows: List[JoinedFlow] = []

        with open(cicflowmeter_csv_path, newline="") as csv_file:
            for row in csv.DictReader(csv_file):
                flow = self._parse_row(row)
                if flow is None:
                    continue

                key = _canonical_key(flow["src_ip"], flow["src_port"], flow["dst_ip"], flow["dst_port"], flow["protocol"])
                forward_packets: List[Dict[str, Any]] = []
                backward_packets: List[Dict[str, Any]] = []

                for candidate in index.get(key, ()):
                    if candidate["timestamp"] < flow["window_start"] or candidate["timestamp"] > flow["window_end"]:
                        continue
                    if candidate["src_ip"] == flow["src_ip"] and candidate["src_port"] == flow["src_port"]:
                        forward_packets.append(candidate)
                    elif candidate["src_ip"] == flow["dst_ip"] and candidate["src_port"] == flow["dst_port"]:
                        backward_packets.append(candidate)
                    elif self.debug_logging:
                        logger.debug("flow %s: packet in window matched neither direction: %s", flow["flow_id"], candidate)

                packet_data_complete = file_complete or (last_successful_timestamp is not None and flow["window_end"] <= last_successful_timestamp)
                if not packet_data_complete and self.debug_logging:
                    logger.debug("flow %s marked incomplete: window_end=%s last_successful_timestamp=%s", flow["flow_id"], flow["window_end"], last_successful_timestamp)

                joined_flows.append(JoinedFlow(
                    flow_id=flow["flow_id"], protocol=flow["protocol"], forward_packets=forward_packets,
                    backward_packets=backward_packets, packet_data_complete=packet_data_complete,
                    retransmission_count=flow["retransmission_count"],
                ))

        logger.info("joined %d flow(s) from %s against %s", len(joined_flows), cicflowmeter_csv_path, pcap_path)
        return joined_flows


def _percentile(sorted_values: List[float], q: float) -> float:
    if len(sorted_values) == 1:
        return sorted_values[0]
    position = (q / 100) * (len(sorted_values) - 1)
    lower_index = math.floor(position)
    upper_index = math.ceil(position)
    if lower_index == upper_index:
        return sorted_values[lower_index]
    fraction = position - lower_index
    return sorted_values[lower_index] + (sorted_values[upper_index] - sorted_values[lower_index]) * fraction


def _compute_statistic(values: List[float], statistic: str) -> float:
    if statistic == "mean":
        return statistics.fmean(values)
    if statistic == "std":
        return statistics.stdev(values) if len(values) > 1 else 0.0
    if statistic == "min":
        return min(values)
    if statistic == "max":
        return max(values)
    if statistic == "median":
        return _percentile(sorted(values), 50)
    if statistic == "p25":
        return _percentile(sorted(values), 25)
    if statistic == "p75":
        return _percentile(sorted(values), 75)
    logger.error("unknown statistic: %s", statistic)
    raise ValueError(f"unknown statistic: {statistic}")


def _stat_block(packets: List[Dict[str, Any]], source_field: str, prefix: str, statistics_list: List[str], sentinel: float, incomplete_flow: bool) -> Dict[str, float]:
    if incomplete_flow:
        return {f"{prefix}_{statistic}": float("nan") for statistic in statistics_list}
    if not packets:
        return {f"{prefix}_{statistic}": sentinel for statistic in statistics_list}
    values = [packet[source_field] for packet in packets]
    return {f"{prefix}_{statistic}": _compute_statistic(values, statistic) for statistic in statistics_list}


def extract_packet_features(config: Dict[str, Any], joined_flow: JoinedFlow) -> Dict[str, Any]:
    sentinel = config["constants"]["sentinel_value"]
    tcp_protocol = config["constants"]["tcp_protocol"]
    ttl_field = config["ttl"]["source_field"]
    ttl_statistics = config["ttl"]["statistics"]
    tcp_window_field = config["tcp_window"]["source_field"]
    tcp_window_statistics = config["tcp_window"]["statistics"]
    payload_field = config["payload"]["source_field"]
    payload_statistics = config["payload"]["statistics"]
    is_fragmented_field = config["fragmentation"]["is_fragmented_field"]
    fragment_offset_field = config["fragmentation"]["fragment_offset_field"]

    all_packets = joined_flow.forward_packets + joined_flow.backward_packets
    if not all_packets and joined_flow.packet_data_complete:
        logger.warning("flow %s: no packets matched during join despite a complete read", joined_flow.flow_id)

    incomplete_flow = (not joined_flow.packet_data_complete) or not all_packets

    features: Dict[str, Any] = {}
    features.update(_stat_block(joined_flow.forward_packets, ttl_field, "ttl_fwd", ttl_statistics, sentinel, incomplete_flow))
    features.update(_stat_block(joined_flow.backward_packets, ttl_field, "ttl_bwd", ttl_statistics, sentinel, incomplete_flow))

    if joined_flow.protocol != tcp_protocol:
        for direction in ("fwd", "bwd"):
            for statistic in tcp_window_statistics:
                features[f"tcp_window_{direction}_{statistic}"] = sentinel
    else:
        features.update(_stat_block(joined_flow.forward_packets, tcp_window_field, "tcp_window_fwd", tcp_window_statistics, sentinel, incomplete_flow))
        features.update(_stat_block(joined_flow.backward_packets, tcp_window_field, "tcp_window_bwd", tcp_window_statistics, sentinel, incomplete_flow))

    if incomplete_flow:
        features["fragmentation_count"] = float("nan")
        features["fragmentation_offset_mean"] = float("nan")
        features["fragmentation_offset_max"] = float("nan")
    else:
        fragmented_packets = [packet for packet in all_packets if packet[is_fragmented_field]]
        features["fragmentation_count"] = len(fragmented_packets)
        if not fragmented_packets:
            features["fragmentation_offset_mean"] = sentinel
            features["fragmentation_offset_max"] = sentinel
        else:
            offsets = [packet[fragment_offset_field] for packet in fragmented_packets]
            features["fragmentation_offset_mean"] = statistics.fmean(offsets)
            features["fragmentation_offset_max"] = max(offsets)

    if incomplete_flow:
        for statistic in payload_statistics:
            features[f"payload_{statistic}"] = float("nan")
    else:
        payload_values = [packet[payload_field] for packet in all_packets]
        for statistic in payload_statistics:
            features[f"payload_{statistic}"] = _compute_statistic(payload_values, statistic)

    features["retransmission_count"] = joined_flow.retransmission_count

    return features


def extract_all(pcap_path: Path, cicflowmeter_csv_path: Path, tshark_path: str, joiner_config_path: Path = DEFAULT_JOINER_CONFIG_PATH, extractor_config_path: Path = DEFAULT_EXTRACTOR_CONFIG_PATH) -> Iterator[Dict[str, Any]]:
    extractor_config = config_loader(extractor_config_path)
    joiner = FlowPacketJoiner(config_path=joiner_config_path)
    logger.info("starting packet feature extraction for %s", pcap_path)
    record_count = 0
    for joined_flow in joiner.join(pcap_path, cicflowmeter_csv_path, tshark_path):
        record = {"flow_id": joined_flow.flow_id, "packet_data_complete": joined_flow.packet_data_complete}
        record.update(extract_packet_features(extractor_config, joined_flow))
        record_count += 1
        yield record
    logger.info("finished packet feature extraction for %s: %d record(s)", pcap_path, record_count)