import numpy as np

SCALED_ARRAYS = {"global": None, "delta_global": None, "host": "host_mask", "delta_host": "host_mask", "edge": "adjacency"}


def get_valid_rows(array, mask):
    if mask is None:
        return array.reshape(-1, array.shape[-1])
    return array[mask > 0]


def compute_stats(rows, min_std):
    if rows.shape[0] == 0:
        return {"mean": np.zeros(rows.shape[1], dtype=np.float32), "std": np.ones(rows.shape[1], dtype=np.float32)}
    std = rows.std(axis=0)
    return {"mean": rows.mean(axis=0), "std": np.where(std < min_std, 1.0, std)}


def fit_scaler(train_arrays, config):
    min_std = config["scaling"]["min_std"]
    scaler = {}
    for name, mask_name in SCALED_ARRAYS.items():
        if name in train_arrays:
            mask = None if mask_name is None else train_arrays[mask_name]
            scaler[name] = compute_stats(get_valid_rows(train_arrays[name], mask), min_std)
    return scaler


def scale_array(array, stats, mask, clip_value):
    scaled = np.clip((array - stats["mean"]) / stats["std"], -clip_value, clip_value)
    if mask is None:
        return scaled.astype(np.float32)
    return (scaled * mask[..., None]).astype(np.float32)


def apply_scaler(arrays, scaler, config):
    if not config["scaling"]["enabled"]:
        return arrays
    scaled = dict(arrays)
    for name, stats in scaler.items():
        mask_name = SCALED_ARRAYS[name]
        mask = None if mask_name is None else arrays[mask_name]
        scaled[name] = scale_array(arrays[name], stats, mask, config["scaling"]["clip_value"])
    return scaled


def save_scaler(scaler, path):
    np.savez(path, **{f"{name}__{stat}": value for name, stats in scaler.items() for stat, value in stats.items()})


def load_scaler(path):
    scaler = {}
    with np.load(path) as data:
        for key in data.files:
            name, stat = key.split("__")
            scaler.setdefault(name, {})[stat] = data[key]
    return scaler