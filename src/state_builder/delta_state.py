def calculate_delta(current_state, previous_state, config):
    if previous_state is None:
        strategy = config["delta"]["first_window_strategy"]
        if strategy == "zero":
            previous_state = {"global": {k: 0 for k in current_state["global"]}, "host": {}, "graph": {"nodes": [], "edges": {}}}
    global_delta = {k: current_state["global"][k] - previous_state["global"].get(k, 0) for k in current_state["global"]}
    new_hosts = list(set(current_state["host"].keys()) - set(previous_state["host"].keys()))
    removed_hosts = list(set(previous_state["host"].keys()) - set(current_state["host"].keys()))
    current_edges = set(current_state["graph"]["edges"].keys())
    previous_edges = set(previous_state["graph"]["edges"].keys())
    new_edges = list(current_edges - previous_edges)
    removed_edges = list(previous_edges - current_edges)
    return {"global_delta": global_delta, "new_hosts": new_hosts, "removed_hosts": removed_hosts, "new_edges": new_edges, "removed_edges": removed_edges}