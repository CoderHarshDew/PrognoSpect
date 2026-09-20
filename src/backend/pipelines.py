import csv
import json
import os
import re
import shutil
import pandas as pd
from datetime import datetime, timezone
from itertools import zip_longest
from pathlib import Path
import pyarrow as pa
import pyarrow.parquet as pq
from src.preprocessing.cleaning import initial_cleanup
from src.preprocessing.preprocessing import PreprocessingPipeline
from src.core.config import config_loader
from src.core.logger import logger
from src.database import pcap_archive_downloader
from src.database.chunked_writer import write_csv_in_chunks
from src.extraction.cross_flow_behavioral_feature_extractor import CrossFlowBehavioralFeatureExtractor
from src.extraction.packet_feature_extractor import FlowPacketJoiner, extract_all
from src.extraction.write_flow_features_csv import run as run_flow_extraction


VALIDATION_SCHEMA_CFG_PATH = Path('config/preprocessing/validation_schema.yaml')
VALIDATION_RULES_CFG_PATH = Path('config/preprocessing/validation_rules.yaml')
CLEANING_CFG_PATH = Path('config/preprocessing/cleaning.yaml')
PIPELINE_CFG_PATH = Path('config/preprocessing/pipeline.yaml')
STATE_BUILDER_CFG_PATH = Path('config/preprocessing/state_builder.yaml')
REPORT_PATH = Path('reports/')
GLOBAL_CFG_PATH = Path('config/global_configuration.yaml')

PCAP_DATASET_PATH = Path('dataset/pcap')
EXTRACTED_PATH = Path('dataset/extracted')
MERGED_OUTPUT_PATH = Path('dataset/extracted/merged')
FLOW_EXTRACTION_CFG_PATH = Path('config/extraction/flow_extraction.yaml')
FLOW_PACKET_JOINER_CFG_PATH = Path('config/extraction/flow_packet_joiner.yaml')
TSHARK_PATH = 'C:/Program Files/Wireshark/tshark.exe'
EXTRACTION_CHUNK_SIZE = 20_000
DAY_PATTERN = re.compile(r'\d{2}-\d{2}-\d{4}')
DAY_FORMAT = '%d-%m-%Y'
FLOW_ID_COLUMN = 'Flow ID'
TIMESTAMP_COLUMN = 'Timestamp'
KEY_COLUMNS = [FLOW_ID_COLUMN, TIMESTAMP_COLUMN]
CROSS_FLOW_COLUMNS = ['dst_port_unique_cnt', 'dst_port_scan_rate', 'dst_port_sequentiality', 'dst_port_entropy', 'src_dst_pair_flow_rate']
PACKET_LEVEL_COLUMNS = {
    'ttl_fwd_mean': 'TTL Fwd Mean',
    'ttl_fwd_std': 'TTL Fwd Std',
    'ttl_fwd_min': 'TTL Fwd Min',
    'ttl_fwd_max': 'TTL Fwd Max',
    'ttl_bwd_mean': 'TTL Bwd Mean',
    'ttl_bwd_std': 'TTL Bwd Std',
    'ttl_bwd_min': 'TTL Bwd Min',
    'ttl_bwd_max': 'TTL Bwd Max',
    'tcp_window_fwd_mean': 'TCP Window Fwd Mean',
    'tcp_window_fwd_std': 'TCP Window Fwd Std',
    'tcp_window_fwd_min': 'TCP Window Fwd Min',
    'tcp_window_fwd_max': 'TCP Window Fwd Max',
    'tcp_window_bwd_mean': 'TCP Window Bwd Mean',
    'tcp_window_bwd_std': 'TCP Window Bwd Std',
    'tcp_window_bwd_min': 'TCP Window Bwd Min',
    'tcp_window_bwd_max': 'TCP Window Bwd Max',
    'fragmentation_count': 'Fragmentation Count',
    'fragmentation_offset_mean': 'Fragmentation Offset Mean',
    'fragmentation_offset_max': 'Fragmentation Offset Max',
    'payload_mean': 'Payload Mean',
    'payload_std': 'Payload Std',
    'payload_min': 'Payload Min',
    'payload_max': 'Payload Max',
    'payload_median': 'Payload Median',
    'payload_p25': 'Payload P25',
    'payload_p75': 'Payload P75',
    'retransmission_count': 'Retransmission Count',
}
PACKET_LEVEL_FIELDNAMES = KEY_COLUMNS + list(PACKET_LEVEL_COLUMNS.values())
CROSS_FLOW_FIELDNAMES = KEY_COLUMNS + CROSS_FLOW_COLUMNS


def load_cleaning_configurations():
    """Loads all configurations."""

    logger.info("Loading preprocessing configurations.")

    try:
        schema_cfg = config_loader(VALIDATION_SCHEMA_CFG_PATH)
        rules_cfg = config_loader(VALIDATION_RULES_CFG_PATH)
        cleaning_cfg = config_loader(CLEANING_CFG_PATH)
        pipeline_cfg = config_loader(PIPELINE_CFG_PATH)

    except Exception:
        logger.exception("Failed to load preprocessing configurations.")
        raise

    logger.info("Preprocessing configurations loaded successfully.")

    return schema_cfg, rules_cfg, cleaning_cfg, pipeline_cfg


def clean_and_save(raw_dataset_path: str | Path = Path('../../dataset/raw'), output_path: str | Path = Path('../../dataset/cleaned/cleaned_dataset.parquet')):

    """Cleans the raw dataset and stores the result as a Parquet file."""

    raw_dataset_path = Path(raw_dataset_path)
    output_path = Path(output_path)

    logger.info("Starting dataset cleaning pipeline. Input: %s | Output: %s", raw_dataset_path, output_path)

    if raw_dataset_path.exists() and raw_dataset_path.is_file():
        logger.error("Raw dataset path is a file, but a directory was expected: %s", raw_dataset_path)
        raise ValueError(f"Raw dataset path must be a directory: {raw_dataset_path}")

    raw_dataset_path.mkdir(parents=True, exist_ok=True)

    if output_path.exists() and output_path.is_file():
        logger.info("Existing output file found. Removing: %s", output_path)
        output_path.unlink()

    elif output_path.exists() and output_path.is_dir():
        logger.info("Existing output directory found. Removing: %s", output_path)
        output_path.rmdir()

    output_path.parent.mkdir(exist_ok=True, parents=True)

    raw_dataset_files = os.listdir(raw_dataset_path)

    if not raw_dataset_files:
        logger.error("No dataset files found in raw dataset directory: %s", raw_dataset_path)
        raise FileNotFoundError('No dataset file found')

    logger.info("Found %d file(s) in raw dataset directory.", len(raw_dataset_files))

    for file in raw_dataset_files:
        if not file.endswith('.csv'):
            logger.error("Non-CSV file found in raw dataset directory: %s", file)
            raise ValueError(f'The provided file is not a CSV, {file}')

    logger.info("All discovered dataset files are valid CSV files.")

    writer = None

    try:
        schema_cfg, rules_cfg, cleaning_cfg, pipeline_cfg = load_cleaning_configurations()

        if not all([schema_cfg, rules_cfg, cleaning_cfg, pipeline_cfg]):
            logger.error("One or more preprocessing configurations are empty or failed to load.")
            raise Exception('Error loading configurations, check logs for more details.')

        dtype_map = {}

        expected_columns = schema_cfg['numeric_col'] + schema_cfg['non_numeric_col']

        logger.debug("Expected output columns: %s", expected_columns)

        for feature_group in schema_cfg['feature_groups'].values():
            dtype = feature_group['template']['dtype']

            for feature in feature_group['features']:
                dtype_map[feature] = dtype

        for feature, config in schema_cfg['features'].items():
            dtype_map[feature] = config['dtype']

        logger.info("Constructed dtype map for %d column(s).", len(dtype_map))
        logger.debug("Dtype map: %s", dtype_map)
        logger.info("Expected output schema contains %d column(s).", len(expected_columns))

        total_chunks = 0
        total_rows = 0

        for file in raw_dataset_files:
            dataset_file = Path(raw_dataset_path, file)

            if dataset_file.exists() and not dataset_file.is_file():
                logger.error("Dataset path is not a file: %s", dataset_file)
                raise ValueError(f"This dataset is not a file: {file}")

            logger.info("Starting processing of dataset file: %s", file)

            file_chunks = 0
            file_rows = 0


            logger.debug("Preprocessing pipeline initialized for file: %s", file)

            for chunk_number, chunk in enumerate(pd.read_csv(dataset_file, chunksize=1_000_000, low_memory=False), start=1):
                total_chunks += 1
                file_chunks += 1

                original_rows = len(chunk)
                total_rows += original_rows
                file_rows += original_rows

                preprocess = PreprocessingPipeline(schema_cfg, rules_cfg, cleaning_cfg)

                logger.info("Processing chunk %d from %s. Rows: %d", chunk_number, file, original_rows)

                try:
                    chunk = initial_cleanup(chunk, cleaning_cfg, schema_cfg)
                except Exception:
                    logger.exception("Initial cleanup failed for chunk %d of %s.", chunk_number, file)
                    raise

                logger.debug("Initial cleanup completed for chunk %d of %s. Rows remaining: %d | Columns: %d", chunk_number, file, len(chunk), len(chunk.columns))

                missing_columns = [column for column in expected_columns if column not in chunk.columns]

                if missing_columns:
                    logger.error("Required columns missing from chunk %d of %s: %s", chunk_number, file, missing_columns)
                    raise ValueError(f"Missing required columns in {file}: {missing_columns}")

                unexpected_columns = [column for column in chunk.columns if column not in expected_columns]

                if unexpected_columns:
                    logger.debug("Ignoring %d unexpected column(s) in chunk %d of %s: %s", len(unexpected_columns), chunk_number, file, unexpected_columns)

                chunk = chunk[expected_columns]

                logger.debug("Expected column schema enforced for chunk %d of %s.", chunk_number, file)

                try:
                    chunk = chunk.astype(dtype_map)
                except Exception:
                    logger.exception("Dtype conversion failed for chunk %d of %s.", chunk_number, file)
                    raise

                logger.debug("Dtype conversion completed for chunk %d of %s.", chunk_number, file)
                logger.debug("Chunk %d dtypes: %s", chunk_number, chunk.dtypes.to_dict())

                cycles = pipeline_cfg['cycles']

                logger.debug("Running %d validation/cleaning cycle(s) for chunk %d of %s.", cycles, chunk_number, file)

                for cycle in range(1, cycles + 1):
                    logger.debug("Starting validation cycle %d/%d for chunk %d of %s.", cycle, cycles, chunk_number, file)

                    try:
                        preprocess.validate(chunk)
                    except Exception:
                        logger.exception("Validation failed during cycle %d/%d for chunk %d of %s.", cycle, cycles, chunk_number, file)
                        raise

                    logger.debug("Validation cycle %d/%d completed for chunk %d of %s.", cycle, cycles, chunk_number, file)

                    rows_before_cleaning = len(chunk)

                    try:
                        chunk = preprocess.clean(chunk)
                    except Exception:
                        logger.exception("Cleaning failed during cycle %d/%d for chunk %d of %s.", cycle, cycles, chunk_number, file)
                        raise

                    rows_after_cleaning = len(chunk)

                    logger.debug("Cleaning cycle %d/%d completed for chunk %d of %s. Rows: %d -> %d | Removed: %d", cycle, cycles, chunk_number, file, rows_before_cleaning, rows_after_cleaning, rows_before_cleaning - rows_after_cleaning)

                try:
                    if pipeline_cfg['generate_report']:
                        curr_report_path = Path(REPORT_PATH, file)
                        curr_report_path.mkdir(parents=True, exist_ok=True)

                        file_count = len(os.listdir(curr_report_path))
                        report_file = Path(REPORT_PATH, f'validation_report_{file_count + 1}.txt')

                        with open(report_file, 'w') as r_file:
                            r_file.write(preprocess.validation_result[f'validation_result_{len(preprocess.validation_result)}'].__str__())

                        logger.debug("Validation report generated: %s", report_file)

                except Exception:
                    logger.exception("Failed to generate validation report for chunk %d of %s.", chunk_number, file)

                try:
                    table = pa.Table.from_pandas(df=chunk, preserve_index=False)
                except Exception:
                    logger.exception("Failed to convert chunk %d of %s to PyArrow table.", chunk_number, file)
                    raise

                logger.debug("Converted chunk %d of %s to PyArrow table.", chunk_number, file)

                if writer is None:
                    logger.info("Creating Parquet writer using schema from chunk %d of %s.", chunk_number, file)
                    logger.debug("Initial Parquet schema: %s", table.schema)

                    writer = pq.ParquetWriter(output_path, table.schema, compression="snappy")

                    logger.info("Parquet writer created: %s", output_path)

                try:
                    writer.write_table(table)
                except Exception:
                    logger.exception("Failed to write chunk %d of %s to Parquet. Rows: %d", chunk_number, file, len(chunk))
                    logger.error("Incoming table schema: %s", table.schema)
                    raise

                logger.debug("Chunk %d of %s successfully written to Parquet.", chunk_number, file)

            logger.info("Completed processing of %s. Chunks: %d | Rows read: %d", file, file_chunks, file_rows)

        logger.info("Dataset cleaning pipeline completed successfully. Files: %d | Chunks: %d | Rows read: %d | Output: %s", len(raw_dataset_files), total_chunks, total_rows, output_path)

    except Exception:
        logger.exception("Dataset cleaning pipeline failed.")
        raise

    finally:
        if writer is not None:
            try:
                writer.close()
                logger.info("Parquet writer closed successfully.")
            except Exception:
                logger.exception("Failed to close Parquet writer.")
                raise


def _iter_csv_rows(csv_path: Path):
    with csv_path.open('r', encoding='utf-8', newline='') as f:
        yield from csv.DictReader(f)


def _csv_header(csv_path: Path):
    with csv_path.open('r', encoding='utf-8', newline='') as f:
        return next(csv.reader(f))


def _row_key(row):
    return (row[FLOW_ID_COLUMN], row[TIMESTAMP_COLUMN])


def _group_pcaps_by_day(pcap_dataset_path: Path):
    pcap_files = sorted(pcap_dataset_path.glob('*.pcap'))

    if not pcap_files:
        logger.error("No PCAP files found in PCAP dataset directory: %s", pcap_dataset_path)
        raise FileNotFoundError('No PCAP file found')

    days = {}

    for pcap_file in pcap_files:
        match = DAY_PATTERN.search(pcap_file.name)

        if match is None:
            logger.error("Could not find a dd-mm-yyyy date in PCAP file name: %s", pcap_file.name)
            raise ValueError(f'PCAP file name has no dd-mm-yyyy date: {pcap_file.name}')

        days.setdefault(match.group(0), []).append(pcap_file)

    return dict(sorted(days.items(), key=lambda item: datetime.strptime(item[0], DAY_FORMAT)))


def _extract_packet_level_rows(pcap_file: Path, raw_flow_csv_path: Path, flow_csv_path: Path):
    joiner = FlowPacketJoiner(FLOW_PACKET_JOINER_CFG_PATH)

    all_flow_keys = [_row_key(row) for row in _iter_csv_rows(flow_csv_path)]
    flow_keys = []
    raw_row_count = 0

    for raw_row, flow_key in zip_longest(_iter_csv_rows(raw_flow_csv_path), all_flow_keys):
        if raw_row is None or flow_key is None:
            logger.error("Raw CICFlowMeter CSV and flow-level CSV row counts differ for %s.", pcap_file.name)
            raise RuntimeError(f'Raw CICFlowMeter CSV and flow-level CSV row counts differ for {pcap_file.name}')

        raw_row_count += 1

        if joiner._parse_row(raw_row) is not None:
            flow_keys.append(flow_key)

    if raw_row_count > 0 and not flow_keys:
        logger.error("None of the %d raw CICFlowMeter row(s) for %s could be parsed by the flow/packet joiner. Check column_mapping and timestamp_format in %s.", raw_row_count, pcap_file.name, FLOW_PACKET_JOINER_CFG_PATH)
        raise ValueError(f'No CICFlowMeter row could be parsed for {pcap_file.name}')

    packet_records = extract_all(pcap_file, raw_flow_csv_path, TSHARK_PATH, FLOW_PACKET_JOINER_CFG_PATH)

    row_count = 0

    for (flow_id, timestamp), record in zip(flow_keys, packet_records):
        if record['flow_id'] != flow_id:
            logger.error("Packet-level record for flow %s is misaligned with flow-level row %s.", record['flow_id'], flow_id)
            raise ValueError(f"Packet-level record misaligned with flow-level row: {record['flow_id']} != {flow_id}")

        row = {FLOW_ID_COLUMN: flow_id, TIMESTAMP_COLUMN: timestamp}
        row.update({display_name: record[raw_name] for raw_name, display_name in PACKET_LEVEL_COLUMNS.items()})

        row_count += 1

        yield row

    if row_count != len(flow_keys) or next(packet_records, None) is not None:
        logger.error("Packet-level record count does not match flow-level row count for %s. Expected: %d | Produced: %d", pcap_file.name, len(flow_keys), row_count)
        raise RuntimeError(f'Packet-level record count mismatch for {pcap_file.name}')


def _extract_cross_flow_rows(flow_csv_path: Path, timestamp_format: str, protocol_number_to_label: dict):
    extractor = CrossFlowBehavioralFeatureExtractor()

    required_labels = {extractor.constants['tcp_protocol'], extractor.constants['udp_protocol']}

    if not required_labels <= set(protocol_number_to_label.values()):
        logger.error("Protocol labels %s do not cover the cross-flow protocol constants %s.", sorted(protocol_number_to_label.values()), sorted(required_labels))
        raise ValueError('Protocol labels do not match the cross-flow protocol constants')

    flow_keys = []
    observations = []

    for index, row in enumerate(_iter_csv_rows(flow_csv_path)):
        timestamp = datetime.strptime(row[TIMESTAMP_COLUMN], timestamp_format).replace(tzinfo=timezone.utc)
        protocol_number = int(row['Protocol'])
        observation = {'timestamp': timestamp, 'src_ip': row['Source IP'], 'dst_ip': row['Destination IP'], 'dst_port': int(row['Destination Port']), 'protocol': protocol_number_to_label.get(protocol_number, str(protocol_number))}

        flow_keys.append(_row_key(row))
        observations.append((timestamp, index, observation))

    observations.sort(key=lambda item: (item[0], item[1]))

    features = [None] * len(flow_keys)

    for (_, index, _), record in zip(observations, extractor.extract(observation for _, _, observation in observations)):
        features[index] = {name: record[name] for name in CROSS_FLOW_COLUMNS}

    for (flow_id, timestamp), values in zip(flow_keys, features):
        yield {FLOW_ID_COLUMN: flow_id, TIMESTAMP_COLUMN: timestamp, **values}


def merge_pipeline(flow_path: str | Path, packet_path: str | Path, cross_flow_path: str | Path, output_path: str | Path, append: bool = False):

    flow_path = Path(flow_path)
    packet_path = Path(packet_path)
    cross_flow_path = Path(cross_flow_path)
    output_path = Path(output_path)

    logger.info("Starting merge pipeline. Flow: %s | Packet: %s | Cross-flow: %s | Output: %s", flow_path, packet_path, cross_flow_path, output_path)

    for path in (flow_path, packet_path, cross_flow_path):
        if not path.is_file():
            logger.error("Merge input file not found: %s", path)
            raise FileNotFoundError(f'Merge input file not found: {path}')

    if not append and output_path.is_file():
        logger.info("Existing output file found. Removing: %s", output_path)
        output_path.unlink()

    try:
        with flow_path.open('r', encoding='utf-8', newline='') as flow_file, packet_path.open('r', encoding='utf-8', newline='') as packet_file, cross_flow_path.open('r', encoding='utf-8', newline='') as cross_flow_file:
            flow_reader = csv.DictReader(flow_file)
            packet_reader = csv.DictReader(packet_file)
            cross_flow_reader = csv.DictReader(cross_flow_file)

            flow_fieldnames = list(flow_reader.fieldnames)
            packet_fieldnames = [name for name in packet_reader.fieldnames if name not in KEY_COLUMNS]
            cross_flow_fieldnames = [name for name in cross_flow_reader.fieldnames if name not in KEY_COLUMNS]
            merged_fieldnames = flow_fieldnames + cross_flow_fieldnames + packet_fieldnames

            if len(set(merged_fieldnames)) != len(merged_fieldnames):
                duplicated = sorted({name for name in merged_fieldnames if merged_fieldnames.count(name) > 1})
                logger.error("Column name(s) present in more than one extraction level: %s", duplicated)
                raise ValueError(f'Duplicate column names across extraction levels: {duplicated}')

            def merged_rows():
                packet_row = next(packet_reader, None)
                cross_flow_row = next(cross_flow_reader, None)

                for flow_row in flow_reader:
                    key = _row_key(flow_row)
                    merged = dict(flow_row)

                    if cross_flow_row is None or _row_key(cross_flow_row) != key:
                        logger.error("Cross-flow row missing or out of order at flow key %s.", key)
                        raise ValueError(f'Cross-flow row missing or out of order at flow key {key}')

                    merged.update({name: cross_flow_row[name] for name in cross_flow_fieldnames})
                    cross_flow_row = next(cross_flow_reader, None)

                    if packet_row is not None and _row_key(packet_row) == key:
                        merged.update({name: packet_row[name] for name in packet_fieldnames})
                        packet_row = next(packet_reader, None)
                    else:
                        merged.update({name: '' for name in packet_fieldnames})

                    yield merged

                if packet_row is not None or cross_flow_row is not None:
                    logger.error("Unmatched packet-level or cross-flow rows remain after merging all flow rows.")
                    raise ValueError('Packet-level or cross-flow rows could not be matched to any flow row')

            merged_row_count = write_csv_in_chunks(output_path, merged_fieldnames, merged_rows(), EXTRACTION_CHUNK_SIZE, append)

    except Exception:
        logger.exception("Merge pipeline failed.")
        raise

    logger.info("Merge pipeline completed successfully. Rows: %d | Columns: %d | Output: %s", merged_row_count, len(merged_fieldnames), output_path)

    return output_path


def _load_extraction_settings():
    try:
        flow_cfg = config_loader(FLOW_EXTRACTION_CFG_PATH)
        joiner_cfg = config_loader(FLOW_PACKET_JOINER_CFG_PATH)
    except Exception:
        logger.exception("Failed to load extraction configurations.")
        raise

    cicflowmeter_cfg = flow_cfg['cicflowmeter']

    return {'flow_cfg': flow_cfg, 'cicflowmeter_cfg': cicflowmeter_cfg, 'keep_raw_flow_csv': cicflowmeter_cfg.get('preserve_intermediate_csv', False), 'timestamp_format': joiner_cfg['cicflowmeter_csv']['timestamp_format'], 'protocol_number_to_label': joiner_cfg['protocol_number_to_label']}


def _extract_day(day: str, pcap_files: list, extracted_path: Path, merged_output_path: Path, settings: dict):

    flow_cfg = settings['flow_cfg']
    cicflowmeter_cfg = settings['cicflowmeter_cfg']
    keep_raw_flow_csv = settings['keep_raw_flow_csv']
    timestamp_format = settings['timestamp_format']
    protocol_number_to_label = settings['protocol_number_to_label']

    work_path = extracted_path / '_work'
    work_path.mkdir(parents=True, exist_ok=True)

    flow_path = extracted_path / 'flow' / f'{day}.csv'
    packet_path = extracted_path / 'packet' / f'{day}.csv'
    cross_flow_path = extracted_path / 'cross_flow' / f'{day}.csv'
    merged_path = merged_output_path / f'{day}.csv'

    logger.info("Processing day %s. PCAP file(s): %d", day, len(pcap_files))

    for stale_path in (flow_path, packet_path, cross_flow_path, merged_path):
        if stale_path.is_file():
            logger.info("Existing output file found. Removing: %s", stale_path)
            stale_path.unlink()

    for pcap_index, pcap_file in enumerate(pcap_files):
        append = pcap_index > 0
        work_flow_csv = work_path / f'{pcap_file.stem}_flow.csv'
        raw_flow_csv = Path(cicflowmeter_cfg['work_dir']) / f'{pcap_file.name}_Flow.csv'

        logger.info("Extracting %s (%d/%d) for day %s.", pcap_file.name, pcap_index + 1, len(pcap_files), day)

        try:
            run_flow_extraction(pcap_file, {**flow_cfg, 'cicflowmeter': {**cicflowmeter_cfg, 'preserve_intermediate_csv': True}, 'output': {**flow_cfg.get('output', {}), 'path': str(work_flow_csv)}})

            flow_rows = write_csv_in_chunks(flow_path, _csv_header(work_flow_csv), _iter_csv_rows(work_flow_csv), EXTRACTION_CHUNK_SIZE, append)
            logger.info("Flow-level extraction completed for %s. Rows: %d", pcap_file.name, flow_rows)

            packet_rows = write_csv_in_chunks(packet_path, PACKET_LEVEL_FIELDNAMES, _extract_packet_level_rows(pcap_file, raw_flow_csv, work_flow_csv), EXTRACTION_CHUNK_SIZE, append)
            logger.info("Packet-level extraction completed for %s. Rows: %d", pcap_file.name, packet_rows)

            cross_flow_rows = write_csv_in_chunks(cross_flow_path, CROSS_FLOW_FIELDNAMES, _extract_cross_flow_rows(work_flow_csv, timestamp_format, protocol_number_to_label), EXTRACTION_CHUNK_SIZE, append)
            logger.info("Cross-flow extraction completed for %s. Rows: %d", pcap_file.name, cross_flow_rows)

        except Exception:
            logger.exception("Extraction failed for %s.", pcap_file.name)
            raise

        finally:
            if work_flow_csv.exists():
                work_flow_csv.unlink()

            if not keep_raw_flow_csv and raw_flow_csv.exists():
                raw_flow_csv.unlink()

    merged_file = merge_pipeline(flow_path, packet_path, cross_flow_path, merged_path)

    logger.info("Completed day %s.", day)

    return merged_file


def extraction_pipeline(pcap_dataset_path: str | Path = PCAP_DATASET_PATH, extracted_path: str | Path = EXTRACTED_PATH, merged_output_path: str | Path = MERGED_OUTPUT_PATH):

    pcap_dataset_path = Path(pcap_dataset_path)
    extracted_path = Path(extracted_path)
    merged_output_path = Path(merged_output_path)

    logger.info("Starting extraction pipeline. Input: %s | Extracted: %s | Merged: %s", pcap_dataset_path, extracted_path, merged_output_path)

    if not pcap_dataset_path.is_dir():
        logger.error("PCAP dataset path is not a directory: %s", pcap_dataset_path)
        raise ValueError(f"PCAP dataset path must be a directory: {pcap_dataset_path}")

    days = _group_pcaps_by_day(pcap_dataset_path)

    logger.info("Found %d PCAP file(s) across %d day(s).", sum(len(files) for files in days.values()), len(days))

    settings = _load_extraction_settings()

    merged_files = []

    try:
        for day, pcap_files in days.items():
            merged_files.append(_extract_day(day, pcap_files, extracted_path, merged_output_path, settings))

    except Exception:
        logger.exception("Extraction pipeline failed.")
        raise

    logger.info("Extraction pipeline completed successfully. Days: %d | Merged files: %s", len(days), [str(path) for path in merged_files])

    return merged_files


def _list_archive_days():
    days = []

    for row in pcap_archive_downloader.read_csv(pcap_archive_downloader.ALL_LIST):
        if row['day'] not in days:
            days.append(row['day'])

    return days


def _extraction_state_path(extracted_path: Path, day: str):
    return extracted_path / 'state' / f'{day}.json'


def _load_extraction_state(extracted_path: Path, day: str):
    path = _extraction_state_path(extracted_path, day)

    if not path.exists():
        return {'batch_sizes': []}

    return json.loads(path.read_text(encoding='utf-8'))


def _save_extraction_state(extracted_path: Path, day: str, state: dict):
    path = _extraction_state_path(extracted_path, day)
    path.parent.mkdir(parents=True, exist_ok=True)

    temp = path.with_name(path.name + '.tmp')
    temp.write_text(json.dumps(state, indent=2), encoding='utf-8')
    os.replace(temp, path)


def _extract_piece(pcap_file: Path, work_path: Path, group_flow_path: Path, packet_path: Path, settings: dict):

    flow_cfg = settings['flow_cfg']
    cicflowmeter_cfg = settings['cicflowmeter_cfg']
    keep_raw_flow_csv = settings['keep_raw_flow_csv']

    work_flow_csv = work_path / f'{pcap_file.stem}_flow.csv'
    raw_flow_csv = Path(cicflowmeter_cfg['work_dir']) / f'{pcap_file.name}_Flow.csv'

    logger.info("Extracting %s.", pcap_file.name)

    try:
        run_flow_extraction(pcap_file, {**flow_cfg, 'cicflowmeter': {**cicflowmeter_cfg, 'preserve_intermediate_csv': True}, 'output': {**flow_cfg.get('output', {}), 'path': str(work_flow_csv)}})

        flow_rows = write_csv_in_chunks(group_flow_path, _csv_header(work_flow_csv), _iter_csv_rows(work_flow_csv), EXTRACTION_CHUNK_SIZE, group_flow_path.exists())
        logger.info("Flow-level extraction completed for %s. Rows: %d", pcap_file.name, flow_rows)

        packet_rows = write_csv_in_chunks(packet_path, PACKET_LEVEL_FIELDNAMES, _extract_packet_level_rows(pcap_file, raw_flow_csv, work_flow_csv), EXTRACTION_CHUNK_SIZE, packet_path.exists())
        logger.info("Packet-level extraction completed for %s. Rows: %d", pcap_file.name, packet_rows)

    except Exception:
        logger.exception("Extraction failed for %s.", pcap_file.name)
        raise

    finally:
        if work_flow_csv.exists():
            work_flow_csv.unlink()

        if not keep_raw_flow_csv and raw_flow_csv.exists():
            raw_flow_csv.unlink()


def _extract_batch(day: str, batch_index: int, groups: list, extracted_path: Path, merged_output_path: Path, settings: dict):

    state = _load_extraction_state(extracted_path, day)
    batch_sizes = state['batch_sizes']

    if len(batch_sizes) > batch_index:
        logger.info("Batch %d of %s is already merged. Skipping extraction.", batch_index + 1, day)
        return

    if len(batch_sizes) < batch_index:
        logger.error("Batch %d of %s cannot be processed: only %d earlier batch(es) are recorded as merged.", batch_index + 1, day, len(batch_sizes))
        raise RuntimeError(f'Extraction state for {day} is inconsistent with the downloader state')

    pcap_archive_downloader.ensure_free_space(extracted_path, 0)

    timestamp_format = settings['timestamp_format']
    protocol_number_to_label = settings['protocol_number_to_label']

    work_path = extracted_path / '_work'
    batch_path = work_path / day / f'batch{batch_index}'
    merged_path = merged_output_path / f'{day}.csv'

    merged_output_path.mkdir(parents=True, exist_ok=True)

    if batch_path.exists():
        shutil.rmtree(batch_path)

    batch_path.mkdir(parents=True)

    if batch_index > 0:
        if not merged_path.is_file() or merged_path.stat().st_size < batch_sizes[-1]:
            logger.error("Merged CSV %s is missing or shorter than the recorded %d byte(s).", merged_path, batch_sizes[-1])
            raise RuntimeError(f'Merged CSV for {day} is missing or shorter than recorded: {merged_path}')

        with merged_path.open('r+b') as merged_file:
            merged_file.truncate(batch_sizes[-1])

    flow_path = batch_path / 'flow.csv'
    packet_path = batch_path / 'packet.csv'
    cross_flow_path = batch_path / 'cross_flow.csv'
    group_flow_path = batch_path / 'group_flow.csv'

    logger.info("Extracting batch %d of %s. Original PCAP(s): %d", batch_index + 1, day, len(groups))

    for group_index, pieces in enumerate(groups):
        logger.info("Original PCAP %d/%d of batch %d: %d piece(s).", group_index + 1, len(groups), batch_index + 1, len(pieces))

        for pcap_file in pieces:
            _extract_piece(pcap_file, work_path, group_flow_path, packet_path, settings)

        write_csv_in_chunks(flow_path, _csv_header(group_flow_path), _iter_csv_rows(group_flow_path), EXTRACTION_CHUNK_SIZE, flow_path.exists())

        cross_flow_rows = write_csv_in_chunks(cross_flow_path, CROSS_FLOW_FIELDNAMES, _extract_cross_flow_rows(group_flow_path, timestamp_format, protocol_number_to_label), EXTRACTION_CHUNK_SIZE, cross_flow_path.exists())
        logger.info("Cross-flow extraction completed for original PCAP %d/%d of batch %d. Rows: %d", group_index + 1, len(groups), batch_index + 1, cross_flow_rows)

        group_flow_path.unlink()

    merge_pipeline(flow_path, packet_path, cross_flow_path, merged_path, append=batch_index > 0)

    batch_sizes.append(merged_path.stat().st_size)
    _save_extraction_state(extracted_path, day, state)

    shutil.rmtree(batch_path)

    logger.info("Batch %d of %s merged into %s.", batch_index + 1, day, merged_path)


def _run_archive(day: str, limit: int | None, extracted_path: Path, merged_output_path: Path, settings: dict):

    logger.info("Starting archive %s.", day)

    batch_count = pcap_archive_downloader.plan(day, limit)

    if batch_count == 0:
        pcap_archive_downloader.delete(day)
        logger.info("Archive %s already done, skipping.", day)
        return None

    logger.info("Archive %s: %d batch(es).", day, batch_count)

    for batch_index in range(batch_count):
        groups = pcap_archive_downloader.download_batch(day, batch_index)

        if groups is None:
            pcap_archive_downloader.delete_batch(day, batch_index)
            logger.info("Archive %s batch %d/%d already done, skipping.", day, batch_index + 1, batch_count)
            continue

        if not groups or not all(groups):
            logger.error("No PCAP files were downloaded for batch %d of archive %s.", batch_index + 1, day)
            raise FileNotFoundError(f'No PCAP files downloaded for batch {batch_index + 1} of archive {day}')

        logger.info("Archive %s batch %d/%d: extracting %d original PCAP(s).", day, batch_index + 1, batch_count, len(groups))

        _extract_batch(day, batch_index, groups, extracted_path, merged_output_path, settings)

        pcap_archive_downloader.delete_batch(day, batch_index)

        logger.info("Archive %s batch %d/%d: PCAPs removed.", day, batch_index + 1, batch_count)

    logger.info("Archive %s done.", day)

    return merged_output_path / f'{day}.csv'


def download_and_extract(day: str | None = None, limit: int | None = None, extracted_path: str | Path = EXTRACTED_PATH, merged_output_path: str | Path = MERGED_OUTPUT_PATH, skip_days: int = 0):

    extracted_path = Path(extracted_path)
    merged_output_path = Path(merged_output_path)
    limit = limit if limit and limit > 0 else None

    logger.info("Starting download and extraction pipeline. Archive: %s | Limit: %s | Skip days: %d | Extracted: %s | Merged: %s", day or 'all', limit or 'none', skip_days, extracted_path, merged_output_path)

    if skip_days < 0:
        logger.error("skip_days must not be negative: %d", skip_days)
        raise ValueError(f'skip_days must not be negative: {skip_days}')

    if day and skip_days:
        logger.error("skip_days cannot be combined with a single archive: %s", day)
        raise ValueError('skip_days cannot be combined with day')

    all_days = [day] if day else _list_archive_days()

    if skip_days >= len(all_days):
        logger.error("skip_days (%d) leaves no archives to process; the list has %d archive(s).", skip_days, len(all_days))
        raise ValueError(f'skip_days ({skip_days}) leaves no archives to process; the list has {len(all_days)} archive(s)')

    days = all_days[skip_days:]

    logger.info("Archives to process: %d | Skipped: %s", len(days), all_days[:skip_days] or 'none')

    settings = _load_extraction_settings()

    merged_files = []

    try:
        for archive_day in days:
            merged_file = _run_archive(archive_day, limit, extracted_path, merged_output_path, settings)

            if merged_file is not None:
                merged_files.append(merged_file)

    except Exception:
        logger.exception("Download and extraction pipeline failed. Fix the issue and run the same command again to resume.")
        raise

    logger.info("Download and extraction pipeline completed successfully. Archives: %d | Newly merged files: %s", len(days), [str(path) for path in merged_files])

    return merged_files