from pathlib import Path

import pandas as pd
import yaml

from src.state_builder.state_builder import build_states

DEFAULT_INPUT_PATH = Path("dataset/extracted/labeled/Thursday-15-02-2018.csv")
DEFAULT_CONFIG_PATH = Path("config/state_builder/state_builder.yaml")
DEFAULT_OUTPUT_PATH = Path("tests/output/test_state_builder_output.txt")


def load_config(config_path: Path):
    with open(config_path, "r") as f:
        return yaml.safe_load(f)


def format_state_report(input_path, config_path, df, states, state_index, sample_size):
    lines = []
    lines.append("module_under_test: src.state_builder.state_builder.build_states")
    lines.append(f"input_path: {input_path}")
    lines.append(f"config_path: {config_path}")
    lines.append(f"input_rows_total: {len(df)}")
    lines.append(f"input_columns_total: {len(df.columns)}")
    lines.append(f"states_built_total: {len(states)}")
    lines.append(f"selected_state_index: {state_index}")

    selected_state = states[state_index]
    lines.append(f"selected_window_time: {selected_state['window_time']}")

    global_state = selected_state["state"]["global"]
    lines.append("global_state_structure:")
    for k, v in global_state.items():
        lines.append(f"  {k}: {type(v).__name__}")
    lines.append("global_state_values:")
    for k, v in global_state.items():
        lines.append(f"  {k}: {v}")

    host_items = list(selected_state["state"]["host"].items())
    lines.append(f"host_state_total_hosts: {len(host_items)}")
    lines.append(f"host_state_retained_sample_size: {min(sample_size, len(host_items))}")
    if host_items:
        lines.append("host_state_record_structure:")
        for k, v in host_items[0][1].items():
            lines.append(f"  {k}: {type(v).__name__}")
    lines.append("host_state_retained_sample:")
    for host, feats in host_items[:sample_size]:
        lines.append(f"  {host}: {feats}")

    edge_items = list(selected_state["state"]["graph"]["edges"].items())
    lines.append(f"graph_edges_total: {len(edge_items)}")
    lines.append(f"graph_edges_retained_sample_size: {min(sample_size, len(edge_items))}")
    if edge_items:
        lines.append("graph_edge_record_structure:")
        for k, v in edge_items[0][1].items():
            lines.append(f"  {k}: {type(v).__name__}")
    lines.append("graph_edges_retained_sample:")
    for edge, feats in edge_items[:sample_size]:
        lines.append(f"  {edge}: {feats}")

    delta = selected_state["delta"]
    lines.append("delta_structure:")
    for k, v in delta.items():
        lines.append(f"  {k}: {type(v).__name__}")
    lines.append("delta_values:")
    for k, v in delta.items():
        lines.append(f"  {k}: {v}")

    label = selected_state["label"]
    lines.append("label_structure:")
    for k, v in label.items():
        lines.append(f"  {k}: {type(v).__name__}")
    lines.append("label_values:")
    for k, v in label.items():
        lines.append(f"  {k}: {v}")

    return "\n".join(lines)


def test_state_builder(
    input_path: Path = DEFAULT_INPUT_PATH,
    config_path: Path = DEFAULT_CONFIG_PATH,
    output_path: Path = DEFAULT_OUTPUT_PATH,
    state_index: int = 0,
    sample_size: int = 10,
):
    config = load_config(config_path)
    df = pd.read_csv(input_path, chunksize=1_000_000, low_memory=False).get_chunk()
    states = build_states(df, config)

    assert len(df) > 0, f"Input CSV has no rows: {input_path}"
    assert config["columns"]["label"] in df.columns, "Label column missing from input CSV"

    states = build_states(df, config)

    assert len(states) > 0, "No states were built"
    assert state_index < len(states), f"state_index {state_index} out of range, only {len(states)} states built"

    report = format_state_report(input_path, config_path, df, states, state_index, sample_size)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    with open(output_path, "w") as f:
        f.write(report)

    print(report)
    return output_path