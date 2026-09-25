import inspect
from datetime import datetime, timezone
from pathlib import Path
import pandas as pd
import pyarrow.parquet as pq
from src.backend.pipelines import clean_and_save, REPORT_PATH


def test_clean_and_save(raw_dataset_path=None, output_path=None, report_output_path=None, sample_size=20):

    signature = inspect.signature(clean_and_save)

    resolved_raw_dataset_path = Path(raw_dataset_path) if raw_dataset_path is not None else signature.parameters['raw_dataset_path'].default
    resolved_output_path = Path(output_path) if output_path is not None else signature.parameters['output_path'].default
    resolved_report_output_path = Path(report_output_path) if report_output_path is not None else REPORT_PATH / 'clean_and_save_validation_report.txt'

    resolved_report_output_path.parent.mkdir(parents=True, exist_ok=True)

    raw_dataset_files = sorted(path.name for path in resolved_raw_dataset_path.glob('*.csv')) if resolved_raw_dataset_path.exists() else []

    clean_and_save(raw_dataset_path=resolved_raw_dataset_path, output_path=resolved_output_path)

    parquet_file = pq.ParquetFile(resolved_output_path)

    total_rows = parquet_file.metadata.num_rows
    schema = parquet_file.schema_arrow
    column_names = schema.names

    sample_batch = next(parquet_file.iter_batches(batch_size=sample_size), None)
    sample_df = sample_batch.to_pandas() if sample_batch is not None else pd.DataFrame(columns=column_names)

    with pd.option_context('display.max_columns', None, 'display.width', None):
        sample_repr = sample_df.to_string()

    lines = []

    lines.append(f"Module/function under test: src.backend.pipelines.clean_and_save")
    lines.append(f"Run timestamp (UTC): {datetime.now(timezone.utc).isoformat()}")
    lines.append("")
    lines.append(f"Input raw_dataset_path: {resolved_raw_dataset_path}")
    lines.append(f"Input raw dataset file(s) ({len(raw_dataset_files)}): {raw_dataset_files}")
    lines.append(f"Output path: {resolved_output_path}")
    lines.append("")
    lines.append(f"Total rows produced (complete output): {total_rows}")
    lines.append(f"Total columns produced: {len(column_names)}")
    lines.append(f"Records retained for inspection: {len(sample_df)}")
    lines.append("")
    lines.append("Produced record structure (field name: type):")

    for field in schema:
        lines.append(f"  {field.name}: {field.type}")

    lines.append("")
    lines.append(f"Retained sample records (first {len(sample_df)} of {total_rows}):")
    lines.append(sample_repr)

    resolved_report_output_path.write_text("\n".join(lines), encoding='utf-8')

    return resolved_report_output_path


if __name__ == "__main__":
    print(test_clean_and_save())