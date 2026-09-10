# data_loader.py

import os
import pandas as pd


def find_csv_files(dataset_path):
    """
    Dataset folder ke andar recursively
    saari CSV files find karta hai.
    """

    csv_files = []

    for root, dirs, files in os.walk(dataset_path):

        for file in files:

            if file.lower().endswith(".csv"):

                full_path = os.path.join(root, file)

                csv_files.append(full_path)

    return csv_files


def load_csv(file_path):
    """
    Single CSV load karta hai.
    """

    print(f"\nLoading: {file_path}")

    df = pd.read_csv(
        file_path,
        low_memory=False
    )

    print(f"Rows: {len(df):,}")
    print(f"Columns: {len(df.columns)}")

    return df


def load_dataset(dataset_path):

    csv_files = find_csv_files(dataset_path)

    if not csv_files:

        raise FileNotFoundError(
            f"No CSV files found in: {dataset_path}"
        )

    print("csv files found:")

    for file in csv_files:

        print(file)

    return csv_files