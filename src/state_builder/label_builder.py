def get_window_label(window_df, config):
    cols = config["columns"]
    benign_value = config["label"]["benign_value"]
    label_counts = window_df[cols["label"]].value_counts().to_dict()
    attack_types_present = [label for label in label_counts if label != benign_value]
    attack_presence = 1 if len(attack_types_present) > 0 else 0
    return {"attack_presence": attack_presence, "attack_types_present": attack_types_present, "label_counts": label_counts}