import os
import pandas as pd
from pathlib import Path
import pyarrow as pa
import pyarrow.parquet as pq
from src.preprocessing.cleaning import initial_cleanup
from src.preprocessing.preprocessing import PreprocessingPipeline
from src.core.config import config_loader


VALIDATION_SCHEMA_CFG_PATH = Path('config/preprocessing/validation_shema.yaml')
VALIDATION_RULES_CFG_PATH = Path('config/preprocessing/validation_rules.yaml')
CLEANING_CFG_PATH = Path('config/preprocessing/cleaning.yaml')
PIPELINE_CFG_PATH = Path('config/preprocessing/pipeline.yaml')
REPORT_PATH = Path('reports/')

def load_configurations():
    """Loads all configurations."""

    schema_cfg = config_loader(VALIDATION_SCHEMA_CFG_PATH)
    rules_cfg = config_loader(VALIDATION_RULES_CFG_PATH)
    cleaning_cfg = config_loader(CLEANING_CFG_PATH)
    pipeline_cfg = config_loader(PIPELINE_CFG_PATH)

    return schema_cfg, rules_cfg, cleaning_cfg, pipeline_cfg

def clean_and_save(raw_dataset_path: str | Path = Path('../../dataset/raw'), output_path: str | Path = Path('../../dataset/cleaned/cleaned_dataset.parquet')):

    if raw_dataset_path.exists() and raw_dataset_path.is_file():
        raw_dataset_path.rmdir()

    raw_dataset_path.mkdir(parents=True, exist_ok=True)

    if output_path.exists() and output_path.is_dir():
        output_path.rmdir()

    output_path.parent.mkdir(exist_ok=True, parents=True)

    raw_dataset_files = os.listdir(raw_dataset_path)

    if not raw_dataset_files:
        raise FileNotFoundError('No dataset file found')

    for file in raw_dataset_files:
        if not file.endswith('.csv'):
            raise ValueError(f'The provided file is not a CSV, {file}')


    writer = None

    try:

        schema_cfg, rules_cfg, cleaning_cfg, pipeline_cfg = load_configurations()

        if not all([schema_cfg, rules_cfg, cleaning_cfg, pipeline_cfg]):
            raise Exception('Error loading configurations, check logs for more details.')

        for file in raw_dataset_files:

            dataset_file = Path(raw_dataset_path, file)

            if dataset_file.exists() and not dataset_file.is_file():
                raise ValueError(f"This dataset is not a file: {file}")


            for chunk in pd.read_csv(dataset_file, chunksize=100_000):

                chunk = initial_cleanup(chunk, cleaning_cfg)

                preprocess = PreprocessingPipeline(schema_cfg, rules_cfg, cleaning_cfg)

                for i in range(pipeline_cfg['cycles']):
                    preprocess.validate(chunk)
                    chunk = preprocess.clean(chunk)

                try:
                    if pipeline_cfg['generate_report']:
                        curr_report_path = Path(REPORT_PATH, file)
                        curr_report_path.mkdir(parents=True, exist_ok=True)
                        file_count = len(os.listdir(curr_report_path))
                        report_file = Path(REPORT_PATH, f'validation_report_{file_count + 1}.txt')

                        with open(report_file, 'w') as r_file:
                            r_file.write(
                                preprocess.validation_result[
                                    f'validation_result_{len(preprocess.validation_result)}'].__str__())

                except Exception as e:
                    print(f'Error generating the report file: {e}')

                table = pa.Table.from_pandas(
                    df=chunk,
                    preserve_index=False
                )

                if writer is None:
                    writer = pq.ParquetWriter(
                        output_path,
                        table.schema,
                        compression="snappy"
                    )

                writer.write_table(table)

    finally:
        if writer is not None:
            writer.close()