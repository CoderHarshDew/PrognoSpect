from __future__ import annotations

import argparse
import logging
from pathlib import Path

from src.core.config import config_loader
from src.extraction.write_flow_features_csv import run


def extract_flow_features() -> None:
    parser = argparse.ArgumentParser(description="Extract PrognoSpect flow-level features from a PCAP.")
    parser.add_argument("pcap", type=Path, help="Path to the input PCAP file.")
    parser.add_argument("--config", type=Path, default=Path("config/extraction/flow_extraction.yaml"), help="Path to the YAML configuration file.")
    parser.add_argument("--log-level", default="INFO", choices=["DEBUG", "INFO", "WARNING", "ERROR"])
    args = parser.parse_args()
    logging.basicConfig(level=getattr(logging, args.log_level), format="%(asctime)s %(levelname)s %(name)s: %(message)s")
    config = config_loader(args.config)
    output_path = run(args.pcap, config)
    print(f"Flow features written to: {output_path}")


if __name__ == "__main__":
    extract_flow_features()