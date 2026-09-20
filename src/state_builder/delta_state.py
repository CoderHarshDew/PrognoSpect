# state/delta_state.py

def calculate_delta(current_state, previous_state):

    # Agar previous state nahi hai
    if previous_state is None:

        return {
            "is_first_state": True,
            "global_changes": {}
        }

    current_global = current_state["global_state"]

    previous_global = previous_state["global_state"]

    changes = {}

    # Har global feature ka difference
    for key in current_global:

        current_value = current_global[key]

        previous_value = previous_global[key]

        changes[key] = (
            current_value - previous_value
        )

    return {
        "is_first_state": False,
        "global_changes": changes
    }