# PrognoSpect — Development Log

## Architecture

We decided to use separate models for different tasks rather than having one model handle the entire system.

The World Model will learn network-state evolution and predict future states. A separate classifier will interpret the resulting network behavior in terms of malicious activity and attack progression.

The World Model therefore needs to model:

**Current Network State → Next Network State → ... → Future Network State**

rather than simply predicting an attack label from the current state.

---

## Dataset Selection

We investigated several publicly available cybersecurity datasets and compared their suitability for the project.

CSE-CIC-IDS2018 was selected as the primary dataset because it provides network-flow features together with attack labels and timestamps suitable for constructing temporal network states.

We decided to use a **single dataset** for the initial development instead of combining multiple datasets. Other datasets can be considered later for generalization and cross-dataset evaluation.

We also discussed developing the system progressively in stages: establish the data and state representation, build the predictive model, add attack interpretation and explainability, and then investigate additional capabilities.

The staged approach is an intended development trajectory rather than a fixed requirement. It can be changed as implementation reveals new requirements or problems.

---

## Class Imbalance — SMOTE-ENN

CICIDS2018 has significant class imbalance, so SMOTE-ENN was considered as a possible preprocessing technique.

SMOTE can increase minority-class representation by generating synthetic samples, while ENN can remove samples considered noisy or inconsistent.

This creates a problem for the World Model because the data is temporal. A synthetic state produced independently of neighboring observations may not correspond to a valid point in an actual network trajectory. ENN could also remove unusual transitional states that may be important for learning attack progression.

We therefore decided **not to use SMOTE-ENN as the default approach for World Model training**.

Other possibilities remain open, including class-weighted losses, focal loss, balanced batch sampling and trajectory-level sampling.

SMOTE or SMOTE-ENN can still be evaluated for suitable downstream classification experiments. Any resampling would need to be performed only within training data/folds to avoid leakage.

This decision can be revisited if experiments show that another treatment of class imbalance is necessary.

---

## Network-State Representation

We considered representing the network state as either a feature vector or a graph.

A vector representation is simpler but does not naturally preserve relationships between hosts and communication entities. A graph preserves these relationships but does not by itself capture all the global and temporal information required by the World Model.

We therefore chose a **hierarchical representation** combining both.

The state is represented as:

**Global/Network-Level Information + Host/Entity-Level Information + Network Relationship Graph + Changes from Previous States**

where:

* **Global/network-level features** — overall characteristics of the network during the time window
* **Host/entity-level information** — information about individual hosts or entities
* **Network relationship graph** — relationships and communication between network entities
* **Changes from previous states** — how the network behavior has changed over time

A state represents a temporal window containing multiple flows. The flows contribute to the relationships represented in the graph while aggregate features capture broader network behavior.

Attack labels remain external supervision and are not included as components of the network state.

---

## World Model Architecture

We investigated different approaches for modeling temporal network evolution, including LSTMs, Temporal Transformers, latent temporal models and Temporal GNNs.

The architecture converged toward combining a **GNN with a temporal model**.

Two primary candidates were selected for investigation:

* **GNN + Temporal Transformer**
* **GNN + LSTM**

The GNN handles the structural relationships within the network, while the temporal component models how those representations evolve across successive states.

The Temporal Transformer is the leading candidate, while the LSTM provides a practical alternative for comparison.

---

## Classifier Architecture

For the classification component, we selected a **GNN + MLP** architecture.

The classifier will operate on graph-aware representations rather than treating the network purely as a flat feature vector.

The MLP can use separate output heads for different prediction tasks, allowing the system to produce outputs such as:

* malicious/infiltration probability,
* likely attack stage,
* relevant hosts or network edges.

Other classifiers such as Logistic Regression or XGBoost can still be evaluated where appropriate.

---

## Latent Graph Prediction

Predicting an entire future graph directly would make the World Model unnecessarily complex.

We therefore decided to encode the graph first and perform future-state prediction in the encoded space.

The intended flow is:

**Network Graph → Graph Encoder → Encoded Graph**

followed by:

**Encoded Current State → Temporal World Model → Predicted Future States**

The World Model therefore predicts the evolution of the **latent graph representation** rather than generating every future flow or reconstructing the complete raw graph.

A decoder can be added if reconstruction or visualization of predicted graph states becomes useful.

We also considered two formulations for future-state prediction:

**Current State → Predicted Next State**

and:

**Current State → Predicted Change**

with:

**Current State + Predicted Change → Predicted Next State**

State-change prediction is particularly relevant because changes in behaviors such as port diversity, SYN activity, internal connections and timing can indicate progression through an attack.

The exact formulation remains open for experimentation.

---

## Shared Graph Encoder

Since both the World Model and classifier require graph representations, we considered whether they should use separate graph encoders or a common encoder.

We decided to use a **shared graph encoder** to simplify the architecture and avoid duplicating the structural representation-learning component.

The same encoded graph representation can therefore be supplied to both the World Model and classifier.

The decision can be revisited if experiments show that the two tasks require substantially different representations or that sharing produces negative transfer.

---

## Training the World Model and Classifier

A question arose about what should be supplied to the classifier during training.

One possibility was:

**CICIDS2018 → State → World Model → Predicted State → Classifier**

This would make the classifier learn directly from World Model outputs.

The other possibility was to derive states from CICIDS2018 and train both models using those states independently:

**CICIDS2018 → States → World Model**

**CICIDS2018 → States → Classifier**

We chose the second approach.

Both models will initially be trained using states derived directly from CICIDS2018. This keeps the classifier independent of the World Model while the predictive architecture is still being developed.

The classifier can later be fine-tuned using World Model-generated outputs so that it also becomes adapted to predicted rather than ground-truth states.

This preserves the modular structure of the architecture and allows the World Model and classifier to be improved independently.

---

## Dataset Acquisition

The full CSE-CIC-IDS2018 dataset was investigated for use, but its size was found to be impractical for the available storage environment.

The complete dataset is roughly **400 GB**, making it unsuitable for the available SSD capacity.

A smaller **approximately 7 GB variant** was therefore selected for development.

The smaller dataset retained the necessary flow-level information while making local development feasible.

---

## Dataset Loading

Loading the approximately 7 GB dataset introduced a separate problem.

Although the files occupy roughly 7 GB on disk, loading all of them into memory requires substantially more RAM because of dataframe representation, data types and intermediate copies created during preprocessing.

Attempting to load all seven files together on a system with **16 GB RAM** was therefore impractical.

The preprocessing pipeline needs to work without loading the complete dataset into memory.

The current direction is to use:

* chunked CSV loading,
* selective column loading,
* incremental preprocessing,
* appropriate data types,
* intermediate processed storage,
* avoidance of unnecessary dataframe copies.

This becomes the immediate implementation constraint for the data pipeline.

---

## Preprocessing

Per the previous architectural decision, the same state representation will be used for both the World Model and classifier.

The preprocessing stage is being divided into two parts that will proceed concurrently:

* **Data Cleaning** — removing unnecessary columns, validating values, and performing other required cleaning operations.
* **State Representation Creation** — creating the network-state representation from the available dataset.

Rather than creating a permanently cleaned dataset first and then creating a separate state-representation dataset from it, we are building **pipelines** that perform these operations.

The state representation pipeline will work together with configuration files (`.yaml`) that define which columns should be included in the state representation and how they should be aggregated.

For example, the configuration can specify which columns are part of the state representation, while the pipeline uses the rules defined in the configuration to aggregate those columns and create the representation.

This allows the same pipeline to work with both the raw and cleaned dataset with very little modification to the implementation. The required changes can largely be controlled through the configuration files.

We are taking this approach to speed up development. The pipeline will first be prepared to work with the raw dataset and will then be modified through the required configuration and implementation changes to work with the cleaned dataset.

---

## CICIDS2018 Dataset Investigation

Further investigation of CSE-CIC-IDS2018 showed that the dataset appears to have already undergone some cleaning or preprocessing. However, invalid values are still present, so additional cleaning and investigation are required before the dataset can be used directly.

During the investigation, we found that CICIDS2018 has substantial similarity to CICIDS2017. The major differences observed include changes to column names, the introduction of new columns, and the removal of some redundant columns.

Based on these similarities, the data-processing pipeline previously developed for the Observion project, which was built around CICIDS2017, may be adaptable for CICIDS2018 after the necessary changes.

Before adopting the Observion pipeline, we need to investigate the remaining CICIDS2018 files and determine how consistently the observed structure and data characteristics apply across the dataset.

Only **one of the ten CSV files** has been investigated so far, so no final conclusion has been made regarding the suitability of the Observion pipeline. Further dataset investigation is required.
