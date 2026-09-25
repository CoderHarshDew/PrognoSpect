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

---

## Dtype Warning Investigation

While loading the CICIDS2018 CSV files with pandas, a `DtypeWarning` was encountered indicating that some columns contained mixed data types.

Further inspection showed that the affected columns are expected to contain numerical network-flow features, suggesting that unexpected non-numeric values may be present in the dataset.

During the investigation, suspicious header-like rows were identified within the data. These rows appear to contain column-name or header information where normal numerical observations should be present, which could explain the mixed-type inference by pandas.

The investigation is being extended across all ten CSV files to determine whether this is a dataset-wide issue or limited to specific files.

The current approach is to identify and remove erroneous/header-like rows where confirmed, followed by appropriate numeric type conversion and validation of the affected columns.

No final conclusion has been made yet regarding the complete cause of the `DtypeWarning`. Further investigation of the remaining files is required.

---

## EDA Conclusions and Observion Pipeline Reuse

EDA of CICIDS2018 showed that the dataset is largely similar to CICIDS2017. Based on the similarities, we determined that the preprocessing pipeline previously developed for the Observion project can be reused for CICIDS2018 after making several changes:

* **Renaming columns** to match the expected pipeline format.
* **Removing extra columns** that are not required.
* **Adding logic for newly introduced useful columns** in CICIDS2018.

With these changes, the existing Observion preprocessing pipeline can be adapted for CICIDS2018 instead of developing an entirely new pipeline.

EDA also identified several features that contribute no useful information to the model's prediction because they are duplicated, constant, or otherwise provide no additional predictive value. These features have therefore been selected for removal:

1. Bwd PSH Flags
2. Fwd URG Flags
3. Bwd URG Flags
4. CWE Flag Count
5. Fwd Byts/b Avg
6. Fwd Pkts/b Avg
7. Fwd Blk Rate Avg
8. Bwd Byts/b Avg
9. Bwd Pkts/b Avg
10. Bwd Blk Rate Avg
11. Subflow Fwd Pkts
12. Subflow Bwd Pkts
13. Subflow Bwd Byts
14. Fwd Seg Size Avg
15. Bwd Seg Size Avg_

## Configuration Updates

The existing **Observion preprocessing pipeline** was taken as the base for CICIDS2018. Its configuration files were modified and improved to match the structure and requirements of CICIDS2018, including renaming columns, removing or handling columns that differ from CICIDS2017, and adding rules for newly introduced useful columns.

The updated configurations were then checked against the CICIDS2018 data to ensure that the pipeline correctly interpreted the available columns and their required processing rules.

---

## Cleaned Dataset Pipeline

After fixing the configurations, the modified Observion pipeline was used to build a complete cleaning pipeline for CICIDS2018.

The pipeline loads the dataset in **1-million-row chunks**, performs the required cleaning and validation operations on each chunk, and stores the processed results in Parquet format. This avoids requiring the entire dataset to be held in memory at once.

Parquet was selected as the intermediate storage format because it provides more efficient storage than the original CSV representation and is better suited for subsequent large-scale data processing.

---

## Data Cleaning and Dtype Consistency

The cleaning pipeline was configured to handle issues identified during dataset investigation, including **extra columns, duplicate header rows, invalid values, and dtype inconsistencies**.

To ensure that different chunks use consistent data types before being written to Parquet, a `dtype_map` was introduced based on the expected schema.

During dtype enforcement, some columns that were defined as `int16` in the `validation_schema` contained values outside the valid `int16` range. Rather than forcing an unsafe conversion, the affected columns were kept as `int64`. Floating-point columns were similarly retained as `float64`, providing a consistent and safe numerical representation across the processed chunks.

---

## Chunk-Level Preprocessing

A row-index mismatch was encountered during chunked processing because a **single global preprocessing pipeline instance** was being reused for every chunk.

The preprocessing pipeline maintained state that caused row indices to become inconsistent when processing subsequent chunks.

This was resolved by creating a **separate preprocessing pipeline instance for each chunk**, allowing each chunk to be processed independently while maintaining the correct row indexing and preventing state from one chunk from affecting another.

## Demonstrative Frontend

A standalone web frontend was developed to provide an early demonstration of the intended PrognoSpect system. The frontend has not yet been connected to the backend and currently operates independently.

The frontend currently contains the following pages:

* `index.html`
* `dashboard.html`
* `hosts.html`
* `attack-map.html`
* `prediction.html`
* `explain-ai.html`
* `trajectory.html`

Some components, such as the Explainable AI interface, are outside the scope of the current version and have therefore been marked as **WIP (Work In Progress)**.

The current frontend simulates the appearance and behavior of a working system. The displayed values are not produced by the actual backend or ML models; they are generated or changed randomly within predefined value ranges to demonstrate how the interface would behave with changing system data.

The frontend will be connected to the actual backend and model outputs in subsequent development.

## Dataset Re-evaluation and Transition to PCAP Processing

After completing the dataset cleaning process, we were preparing to create the network-state representations.

During this process, we discovered that **9 of the 10 CSV files did not contain source and destination IP addresses and ports**, which are mandatory for constructing the network relationship graphs required by the selected architecture.

Without these fields, the available dataset did not provide sufficient information to construct the required graph-based states and train the World Model and classifier as intended.

We therefore decided to use the **complete CSE-CIC-IDS2018 dataset**, which is over **400 GB**, instead of the smaller flow-level variant.

To avoid the storage and memory constraints associated with processing the entire dataset at once, the dataset will be processed **PCAP file by PCAP file in batches**, rather than loading or converting the entire dataset into a single processed dataset.

Working directly with the raw PCAP files also allows **packet-level information** to be incorporated into PrognoSpect, which was not possible with the previously selected flow-level dataset variant.

This changes the data-processing pipeline from primarily **flow-level processing** to a pipeline capable of incorporating both **packet-level and flow-level information**.

---

## CICFlowMeter Setup

CICFlowMeter was selected for **flow-level feature extraction**, while additional packet-level information would be extracted using our own Python implementation.

The **GintsEngelen CICFlowMeter fork** was selected and pinned to commit `4dd5319ad36457010d7a406505790b17a582810c`.

The existing Java 25 installation was incompatible with CICFlowMeter's Gradle 4.2, so **Eclipse Temurin JDK 8** was installed and configured for the project.

The initial runtime encountered an `UnsatisfiedLinkError` from jNetPcap. Investigation identified a mismatch between the repository's bundled **r1425** jNetPcap package, the Maven dependency, and references to r1500.

The bundled r1425 JAR and native libraries were configured instead, and the incorrect r1500 references were corrected.

The Windows CICFlowMeter launcher was also modified so that the native-library path is resolved relative to `cfm.bat` rather than the current working directory.

CICFlowMeter was rebuilt successfully and tested on a CICIDS2018 PCAP, producing a valid flow CSV containing **6,001 flows**.

---

## Extraction Scope and Architecture

The extraction pipeline was initially restricted to **TCP and UDP**, with ICMP and IGMP outside the current scope.

The target flow-level schema was defined as **79 flow-level features** required by PrognoSpect.

CICFlowMeter was established as an **external dependency** for flow-level extraction and will not be modified.

The extraction architecture was defined around three levels of information:

* **Packet-level information**
* **Flow-level information**
* **Cross-flow behavioural information**

CICFlowMeter provides the flow-level representation, while packet-level and cross-flow features are implemented separately in Python.

---

## PCAP Reading and Parsing

A dedicated **`PCAPReader`** was implemented to sequentially stream packets from a PCAP rather than loading the entire file into memory.

A separate **PCAP frame parser** was implemented to interpret the packet data produced by the reader and expose the required packet-level information to subsequent extraction modules.

This separation established a clear boundary between **reading raw PCAP data, parsing packets, and calculating features**, allowing the later packet-level and behavioural extraction modules to operate on a common parsed packet representation.

---

## Packet-Level Extraction

The packet-level extractor was designed to use CICFlowMeter's flow CSV for **flow and direction mapping**.

Using CICFlowMeter's mapping ensures that packet-level information remains aligned with the flow definitions used for flow-level features, avoiding inconsistencies that could occur if packets were independently grouped or assigned directions.

The packet-level extraction module was implemented to obtain information such as TTL, fragmentation, TCP/window behaviour, payload information, timing, and retransmission-related features.

The packet-level output was designed to be written as a separate CSV containing the extracted packet-derived features.

Packet-level extraction was made configurable through a dedicated YAML configuration.

---

## Cross-Flow Behavioural Extraction

A separate cross-flow behavioural extraction module was introduced to derive information that cannot be obtained from individual flows alone.

The extracted behaviours include port diversity, scanning behaviour, port entropy, and source-destination communication rates.

Cross-flow extraction was made configurable through a dedicated YAML configuration.

The cross-flow output was designed to be written separately from the packet-level and flow-level outputs.

---

## Flow-Level Extraction

CICFlowMeter was integrated into the extraction pipeline to generate the required **flow-level features** from each PCAP.

The flow extraction component was kept separate from packet-level and cross-flow processing, allowing CICFlowMeter to remain an external dependency while the additional PrognoSpect-specific features are calculated independently.

The flow-level output was written separately so that it could later be combined with the packet-level and cross-flow representations.

---

## Extraction Validation and Feature Investigation

The individual extraction components were tested against sample PCAPs and their expected outputs.

Testing identified several implementation issues, including a discrepancy between the flow count produced by the integrated extraction module and direct CICFlowMeter execution. The relevant logic was corrected so that the outputs matched.

Feature comparisons also identified overlap between some packet-derived features and CICFlowMeter features. In particular, some payload-related values were identical because both calculations were based on the same underlying payload information. These columns were retained for the time being, with the affected calculations requiring further verification or correction.

---

## Extraction and Daily Merging

A dedicated **merger** was designed to combine the separately generated packet-level, flow-level, and cross-flow CSV outputs into a single dataset.

The merger is structured around the common flow identifiers so that information from the three extraction levels can be associated with the correct flow.

PCAPs belonging to the same day are ultimately represented in a common daily dataset.

A PCAP inventory system was also created, including per-archive PCAP lists.

---

## Repository Restructure

Relevant data-processing components were moved from the `preprocessing` package into a dedicated **`extraction` package** to reflect the separation between raw PCAP extraction and later data cleaning/preprocessing.

---

## PCAP Download and Batch Processing

An individual-PCAP downloader was developed to retrieve PCAPs directly from the CICIDS2018 S3 archives without downloading the complete ZIP archives.

The large-scale processing system was designed around manageable batches of PCAPs. Downloaded PCAPs can be processed and then deleted before subsequent batches are downloaded.

Because approximately **100 GB of SSD space** is available, storage-aware batch planning and disk-space checks were incorporated into the design.

Restart and recovery behaviour was defined for download, processing, and deletion failures.

---

## Temporal Ordering and Ground-Truth Labelling

The need to correctly handle **multi-part PCAPs** and concurrently captured PCAPs from different hosts was identified.

Because the network-state forecaster depends on the actual temporal sequence of network activity, extracted flows must be chronologically ordered after merging.

A downstream module was therefore designed to perform **daily ordering and ground-truth labelling together**, since both operations require the complete day's extracted data.

The ordering scheme uses **Timestamp → Flow ID**, with additional network identifiers available for further tie-breaking.

Ground-truth labels will be reconstructed using the CICIDS2018 attack schedule, attacker/victim information, and attack time windows.

Ambiguous labelling decisions will be handled using a strict reliability filter, with uncertain flows dropped rather than retained.

Manual Wireshark-based verification and correction of attack windows was deferred to a later implementation phase.

---

## Ground-Truth Labelling Re-evaluation

The CICIDS2018 attack schedule was investigated against the processed CSV datasets available through Kaggle and Hugging Face mirrors.

It was found that the official attack schedule does not provide enough granularity to reliably reproduce the attack-label columns present in those processed datasets. The schedule groups several attacks under more general labels, while the processed datasets contain more specific attack categories.

Further investigation led to the labelling approach described in *[This study](https://intrusion-detection.distrinet-research.be/CNS2022/index.html)*.

The decision was made to implement this labelling approach for PrognoSpect so that the labels can be reconstructed using a more detailed and consistent methodology.

---

## Extraction Performance Optimisation

Performance testing revealed significant processing delays on large PCAPs, with a single **4 GB PCAP taking several hours** to process.

The main bottleneck was identified in the **cross-flow behavioural feature extractor**. Each observation was rescanning the entire active window for every feature, resulting in **O(W)** work per observation. The effective window size also increased during traffic bursts such as port scans and DoS activity, making the slowdown particularly severe during high-volume periods.

Unnecessary deque copies were first removed.

The feature extraction logic was then redesigned to maintain **incremental per-group state**, including running counts, entropy sums, and run-tracking information. These states are updated whenever observations are appended to or evicted from the window.

This changed the cross-flow feature calculations from repeated full-window scans to **O(1) amortized work per observation**, substantially reducing the computational cost of processing large PCAPs.
