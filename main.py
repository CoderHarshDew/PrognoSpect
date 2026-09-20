# main.py

import pandas as pd

from src.state_builder import StateBuilder


# DATASET PATH

DATASET_PATH = r"C:\Users\Chandrakant\Downloads\state_representation_test_dataset.csv"


# DATASET LOAD

df = pd.read_csv(
    DATASET_PATH
)

print("\n========== DATASET COLUMNS ==========")
print(df.columns.tolist())


# STATE BUILDER

builder = StateBuilder(
    window_size="1min"
)


# STATES CREATE

states = builder.build_all_states(
    df
)


# RESULT

print(
    "\nTotal states:",
    len(states)
)


if len(states) > 0:

    first_state = states[0]

    print("\n========== FIRST STATE ==========")

    print("\nX_t - Global State:")
    print(first_state["X_t"])

    print("\nH_t - Host State:")
    print(first_state["H_t"])

    print("\nG_t - Graph State:")
    print(first_state["G_t"])

    print("\nDelta S_t:")
    print(first_state["delta_S_t"])