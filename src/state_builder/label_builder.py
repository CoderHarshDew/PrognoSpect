def get_unique_labels(window_df, label_column):
    return set(window_df[label_column].unique())


def check_unknown_labels(unique_labels, label_config):
    known_labels = set(label_config["attack_labels"]) | {label_config["benign_label"]}
    unknown_labels = unique_labels - known_labels
    if unknown_labels:
        raise ValueError(f"Unknown labels in window: {sorted(unknown_labels)}")


def get_attack_presence(unique_labels, benign_label):
    return int(any(label != benign_label for label in unique_labels))


def get_attack_types_present(unique_labels, attack_labels):
    return [int(label in unique_labels) for label in attack_labels]


def get_window_label(window_df, config):
    label_config = config["window_label"]
    unique_labels = get_unique_labels(window_df, config["columns"]["label"])
    check_unknown_labels(unique_labels, label_config)
    return {"attack_presence": get_attack_presence(unique_labels, label_config["benign_label"]), "attack_types_present": get_attack_types_present(unique_labels, label_config["attack_labels"])}