import pyarrow.parquet as pq
from pathlib import Path

def load_parquet_chunks(path: str | Path, batch_size: int = 1_000_000):
    parquet_file = pq.ParquetFile(path)

    for batch in parquet_file.iter_batches(batch_size=batch_size):
        yield batch.to_pandas()