import os

import yaml

from src.preprocessing.state_builder.state_builder import build_states_from_csv
from src.preprocessing.state_builder.state_arrays import stack_windows, get_feature_names, save_arrays
from src.preprocessing.state_builder.state_scaler import fit_scaler, apply_scaler, save_scaler


def load_config(config_path):
    with open(config_path) as file:
        return yaml.safe_load(file)


def run_state_builder(csv_path, config, output_dir, train_ratio):
    results = build_states_from_csv(csv_path, config)
    stacked = stack_windows(results)
    train_size = int(len(results) * train_ratio)
    train_arrays = {name: array[:train_size] for name, array in stacked.items()}
    scaler = fit_scaler(train_arrays, config)
    scaled = apply_scaler(stacked, scaler, config)
    save_arrays(scaled, get_feature_names(results), output_dir)
    save_scaler(scaler, os.path.join(output_dir, "scaler.npz"))
    return scaled


def print_summary(scaled):
    for name, array in scaled.items():
        print(name, array.shape, array.dtype)


def main():
    csv_path = "data/raw/flows.csv"
    config_path = "configs/state_builder_config.yaml"
    output_dir = "data/states"
    train_ratio = 0.7
    config = load_config(config_path)
    scaled = run_state_builder(csv_path, config, output_dir, train_ratio)
    print_summary(scaled)


if __name__ == "__main__":
    main()