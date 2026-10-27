import json
import os

import numpy as np


def get_global_vector(global_values):
    return np.array(list(global_values.values()), dtype=np.float32)


def get_window_arrays(result):
    state = result["state"]
    arrays = {
        "global": get_global_vector(state["global"]),
        "host": state["host"]["features"].to_numpy(dtype=np.float32),
        "host_mask": np.array(state["host"]["mask"], dtype=np.float32),
        "adjacency": state["graph"]["adjacency"].astype(np.float32),
        "edge": state["graph"]["edge_features"].astype(np.float32),
    }
    if "global" in state["delta"]:
        arrays["delta_global"] = get_global_vector(state["delta"]["global"])
    if "host" in state["delta"]:
        arrays["delta_host"] = state["delta"]["host"].to_numpy(dtype=np.float32)
    return arrays


def stack_windows(results):
    window_arrays = [get_window_arrays(result) for result in results]
    stacked = {name: np.stack([arrays[name] for arrays in window_arrays]) for name in window_arrays[0]}
    stacked["attack_presence"] = np.array([result["label"]["attack_presence"] for result in results], dtype=np.float32)
    stacked["attack_types_present"] = np.array([result["label"]["attack_types_present"] for result in results], dtype=np.float32)
    stacked["window_start"] = np.array([result["window_start"] for result in results], dtype="datetime64[ns]")
    return stacked


def get_feature_names(results):
    state = results[0]["state"]
    return {"global": list(state["global"].keys()), "host": list(state["host"]["features"].columns), "edge": state["graph"]["edge_feature_names"]}


def save_arrays(stacked, feature_names, output_dir):
    os.makedirs(output_dir, exist_ok=True)
    np.savez_compressed(os.path.join(output_dir, "states.npz"), **stacked)
    with open(os.path.join(output_dir, "feature_names.json"), "w") as file:
        json.dump(feature_names, file, indent=2)


def load_arrays(output_dir):
    with np.load(os.path.join(output_dir, "states.npz")) as data:
        return {name: data[name] for name in data.files}