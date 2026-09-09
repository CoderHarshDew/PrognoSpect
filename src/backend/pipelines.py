import os
import pandas as pd
from pathlib import Path
import pyarrow as pa
import pyarrow.parquet as pq

from src.preprocessing.cleaning import initial_cleanup
from src.preprocessing.preprocessing import PreprocessingPipeline
from src.core.config import config_loader
from src.core.logger import logger


VALIDATION_SCHEMA_CFG_PATH = Path('config/preprocessing/validation_schema.yaml')
VALIDATION_RULES_CFG_PATH = Path('config/preprocessing/validation_rules.yaml')
CLEANING_CFG_PATH = Path('config/preprocessing/cleaning.yaml')
PIPELINE_CFG_PATH = Path('config/preprocessing/pipeline.yaml')
REPORT_PATH = Path('reports/')


def load_configurations():
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
        schema_cfg, rules_cfg, cleaning_cfg, pipeline_cfg = load_configurations()

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