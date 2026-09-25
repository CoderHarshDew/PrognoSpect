# Project Development Policies

## 1. Purpose and Scope

This document defines the development policies and conventions governing the PrognoSpect project. It establishes how the project's code, architecture, configuration, documentation, data pipelines, experiments, and development records should be developed and maintained.

The purpose of these policies is to maintain consistency across the project as it grows, preserve architectural decisions, reduce unnecessary complexity, and ensure that new development remains compatible with the project's existing direction.

These policies describe **how PrognoSpect should be developed**, rather than defining the implementation of any individual component. Technical designs, model architectures, configuration values, and implementation details should remain in their respective documentation, configuration, or source files.

The policies apply to all development carried out within the project, including new implementations, modifications to existing components, refactoring, experimentation, documentation, and supporting tooling.

### 1.1 Policy Principles

Development decisions should generally follow these principles:

* **Consistency** — New work should remain coherent with established project structure and conventions.
* **Maintainability** — Implementations should remain understandable and practical to maintain as the project grows.
* **Reproducibility** — Development and experimentation should produce results and artifacts that can be reproduced where practical.
* **Controlled complexity** — Additional complexity should provide a corresponding technical benefit.
* **Architectural integrity** — Local implementation decisions should not unnecessarily compromise the wider system architecture.
* **Traceability** — Significant development decisions and changes should remain understandable from the project's documentation and development history.

### 1.2 Interpreting the Policies

These policies establish general development standards rather than prescribing a fixed implementation for every situation.

Where a situation is not directly covered, decisions should follow the principles established throughout this document and remain consistent with the project's existing architecture and conventions.

When a proposed change would substantially depart from an established policy, architecture, or development convention, the change should be considered with the relevant project context and discussed with the appropriate contributors before adoption.

As the project evolves, these policies may be refined when existing rules no longer serve the project's technical requirements. Significant policy changes should themselves be documented through the project's development records.

---

## 2. Coding Policy

The following principles govern the creation, modification, refactoring, and extension of code within PrognoSpect.

### 1. Preserve Existing Code and Configuration Structure

Changes to existing code should preserve its established structure and behavior wherever practical.

* Do not rename, regroup, reorganize, or restructure existing components without a technical reason.
* Do not alter unrelated logic while implementing a change.
* Preserve established YAML and configuration structures unless a structural change is required for the system to function correctly.
* When a structural change appears beneficial but is not required for the immediate implementation, the implications should be considered before proceeding.

### 2. Maintain Architectural Consistency

Existing architecture and implementation patterns should be understood before extending or modifying the system.

* Extend established patterns where they remain appropriate rather than introducing unrelated designs.
* Maintain consistency in naming, module responsibilities, data flow, interfaces, and configuration handling.
* Avoid introducing competing patterns that solve the same problem without a clear architectural reason.
* New components should integrate naturally with the existing system rather than creating unnecessary architectural divergence.

### 3. Use Abstractions Where They Provide Genuine Value

Abstractions should be introduced when they provide meaningful benefits in architecture, maintainability, extensibility, reuse, or separation of concerns.

* Do not avoid a useful abstraction merely because a direct implementation is shorter or requires less initial work.
* Avoid abstraction for its own sake.
* The implementation effort required by an abstraction should not, by itself, be treated as a reason to reject it.
* New abstractions should address a recognizable architectural need and fit the existing system.

### 4. Keep Changes Within Their Relevant Scope

Modifications should remain focused on the part of the system they affect.

* Avoid unrelated changes while modifying existing code.
* Do not perform opportunistic cleanup, restructuring, or stylistic alterations alongside an implementation unless they are relevant to the change.
* Changes that affect broader parts of the system should have a clear technical justification.
* When a broader refactoring or structural change would be beneficial, its impact should be considered before incorporating it into the current work.

### 5. Minimize Unnecessary Changes

Every code change should have a discernible purpose.

* Do not modify functioning code merely for stylistic preference.
* Avoid changes that provide little practical benefit while increasing complexity or maintenance cost.
* Prefer solutions that satisfy the requirement while introducing the smallest necessary amount of unrelated change.
* Where multiple valid implementations exist, favor the approach that provides an appropriate balance of simplicity, maintainability, and architectural consistency.

### 6. Consult Before Significant Architectural Deviations

Changes that substantially alter established architecture, interfaces, configuration structure, or implementation patterns should be considered deliberately before adoption.

* Significant deviations should be discussed with the project maintainers or relevant contributors.
* Proposed structural changes should consider their effect on existing components, configuration, data flow, testing, and future development.
* A locally convenient implementation should not override established project architecture without considering the wider consequences.

---

## 3. Project Structure Policy

The PrognoSpect repository should maintain a clear separation between source code, configuration, datasets, persistent generated artifacts, experiments, validation, documentation, and development records. Each directory should have a defined responsibility, and files should be placed according to their role rather than convenience.

### 3.1 General Structure

The repository should follow a modular structure in which related functionality is grouped together and unrelated concerns remain separated.

The current structure generally follows this pattern:

```text
PrognoSpect/
├── src/
├── config/
├── dataset/
│   ├── pcap/
│   ├── extracted/
│   └── processed/
├── artifacts/
├── experiments/
├── tests/
├── docs/
├── development_log.md
├── project_development_policies.md
├── README.md
└── ...
```

The exact directories and their internal organization may evolve as PrognoSpect develops. Structural changes should preserve clear separation of responsibilities and remain consistent with the overall architecture.

### 3.2 Source Code

`src/` contains the project's implementation code.

Source code should be organized according to functional responsibility rather than allowing unrelated functionality to accumulate in large, general-purpose modules.

Components such as data processing, feature extraction, state construction, graph processing, model implementations, prediction, explanation, and supporting utilities should have clearly defined responsibilities.

Modules should communicate through deliberate interfaces rather than relying on unnecessary coupling or hidden dependencies.

### 3.3 Configuration

`config/` contains configuration files used to control project behavior.

Configuration should be separated from implementation wherever a value represents a tunable parameter, environment-specific setting, processing option, model parameter, or other behavior that may reasonably change without modifying source code.

Configuration files should follow consistent structures and naming conventions.

Existing configuration structures should be preserved when extending them unless a structural change is required by the system.

### 3.4 Dataset

`dataset/` contains data and data-related artifacts associated with the project's data pipeline.

The dataset structure follows the current progression of data through the system:

```text
dataset/
├── pcap/
├── extracted/
└── processed/
```

#### `dataset/pcap/`

Contains PCAP files and PCAP-related resources used as the source material for extraction.

Resources directly associated with obtaining, organizing, identifying, or managing the PCAP source data may also belong here.

#### `dataset/extracted/`

Contains data derived from the source PCAP data before the project's main processing stage.

This includes extracted flow-level or packet-derived data as well as data produced by operations that derive additional information from the PCAP source, such as:

* Extracted network flows and packet-level features.
* Merged extraction outputs.
* Attack labels derived from the PCAP data and associated attack schedules or other source information.
* Other metadata or representations directly derived during the extraction stage.

Merging and labeling do not by themselves constitute the processing stage. If the resulting data is still part of the extraction pipeline and is derived from the PCAP source, it remains within `extracted/`.

#### `dataset/processed/`

Contains the output of processing the extracted data.

This includes data that has undergone the project's subsequent processing operations, such as cleaning, transformation, validation, feature preparation, state construction, or other operations that prepare extracted data for downstream use.

The distinction between `pcap`, `extracted`, and `processed` should be preserved according to the **stage and purpose of the data**, rather than simply the number or type of transformations applied to it.

### 3.5 Persistent Artifacts

`artifacts/` contains persistent generated files that are produced by the project and are expected to remain useful over an extended period.

This includes, but is not limited to:

* Trained models and model checkpoints.
* Encoders and learned representations.
* Scalers and normalization artifacts.
* Label mappings and other learned mappings.
* Tokenizers, vocabularies, or similar persistent preprocessing artifacts.
* Other generated files required to reproduce or operate the deployed system.

Artifacts stored here should represent deliberate, retained outputs rather than temporary execution files or disposable intermediate results.

Persistent artifacts should remain distinguishable from source code, configuration, and datasets.

### 3.6 Experiments

`experiments/` contains experimental implementations, evaluation work, exploratory analysis, and other development work that does not yet form part of the primary system implementation.

Experimental work should remain sufficiently separated from production-oriented source code so that exploratory changes do not inadvertently become dependencies of the main system.

When an experiment becomes part of the primary implementation, the resulting code should be integrated into the appropriate production structure rather than leaving the experimental copy as the canonical implementation.

### 3.7 Manual Validation and Tests

`tests/` contains code used to manually validate the behavior and correctness of project components.

PrognoSpect currently uses **manual test execution** rather than an automated testing framework. Test files should therefore be designed as executable validation procedures that can be run deliberately during development.

Tests should be organized according to the components or behavior they validate.

Test code should remain separate from production implementation and should not become a dependency of the primary system.

Where test data or fixtures are required, they should remain distinguishable from the project's primary datasets.

### 3.8 Documentation

`docs/` contains project documentation that is too substantial or specialized to belong in the repository root.

Documentation should be organized according to its purpose, such as architecture, technical design, development procedures, experiments, or operational guidance.

Documentation should describe the actual state of the project and clearly distinguish implemented functionality from planned or experimental functionality.

### 3.9 Repository Root

The repository root should contain only files that are broadly relevant to the project or conventionally expected at the repository level.

Core project documentation and governance files such as `README.md`, `project_development_policies.md`, and `development_log.md` belong at the root.

Temporary files, experimental artifacts, generated outputs, and implementation-specific resources should be placed in their appropriate directories rather than accumulating in the repository root.

### 3.10 Structural Changes

The project structure should evolve as the system grows.

When a new category of functionality, artifact, or development activity emerges, it should be given an appropriate location rather than being placed into an unrelated existing directory merely for convenience.

Changes that substantially reorganize the repository should consider their effect on imports, configuration paths, documentation, tooling, data flow, and reproducibility before being adopted.

---

## 4. Configuration Policy

PrognoSpect uses configuration files to separate adjustable system behavior, processing parameters, and environment-specific settings from implementation logic. Configuration should remain structured, explicit, consistent, and reproducible so that system behavior can be understood and modified without unnecessarily altering source code.

YAML is the primary configuration format used throughout the project.

### 4.1 Configuration File Naming

Configuration files should use `snake_case.yaml` naming and should be named according to the pipeline stage, component, or responsibility they configure.

Examples include:

```text
packet_feature_extractor.yaml
flow_packet_joiner.yaml
pcap_frame_parser.yaml
validation_rules.yaml
validation_schema.yaml
```

A singular and plural form may coexist when they represent different responsibilities or levels of configuration. Files should not be combined merely to eliminate similar names when doing so would make their responsibilities less distinct.

### 4.2 Configuration and Implementation Separation

Values that control system behavior should generally be placed in configuration rather than being hardcoded throughout source code.

This includes values such as:

* Dataset paths and locations.
* Processing parameters.
* Feature and state construction parameters.
* Model hyperparameters.
* Training parameters.
* Runtime settings.
* Thresholds and limits.
* External tool configuration.
* Environment-specific paths or settings.

Configuration should not be used to represent logic that belongs in the implementation itself.

Complex behavior, algorithms, validation logic, data transformations, and architectural decisions should remain implemented in source code rather than being expressed through excessively complicated configuration structures.

### 4.3 Configuration Structure and Key Ordering

Configuration files should use clear, hierarchical structures that group related settings according to their responsibility.

Where applicable, top-level keys should generally follow this order:

1. `settings:` or configuration flags.
2. `constants:`
3. `statistics:`
4. `templates:`
5. Domain-specific blocks.
6. `formulas:`, `repairable:`, `non_repairable:`, or `columns_to_drop:`.
7. `rules:`
8. `output_field_names:`, `output_feature_columns:`, or `schema:`.

Keys that do not apply to a particular configuration should be omitted rather than represented with empty or irrelevant sections.

The canonical output definition should remain at the end of configuration files where such an output definition exists.

Existing configuration structures should be preserved when extending them unless a structural change is required by the system.

### 4.4 Configuration Naming Conventions

Configuration keys should use clear, descriptive names that communicate their purpose without requiring the implementation to be inspected.

Names should remain consistent with the terminology used throughout the project.

Abbreviations should be avoided where they make configuration less understandable, particularly when a clear descriptive name is available.

### 4.5 Internal and External Field Naming

PrognoSpect may use separate naming conventions for internal pipeline fields and external dataset columns.

**Internal or pipeline field names** should use `snake_case`.

Examples:

```text
src_ip
dst_port
flow_duration
payload_length
is_fragmented
```

These names should be used for code-facing keys, internal mappings, formula dependencies, and other implementation-facing configuration.

**External or dataset column names** should preserve the naming convention of the source or generated dataset.

For CICFlowMeter-derived data, this includes names such as:

```text
Flow Duration
Fwd Pkt Len Max
Flow Bytes/s
Init Fwd Win Byts
```

When a configuration bridges internal and external naming conventions, the relationship should be represented through an explicit mapping rather than relying on implicit renaming.

### 4.6 Constants and Repeated Values

Repeated literals and named constants should be defined once and referenced where appropriate.

Values such as protocol names, sentinel values, and other repeated literals should be placed in a `constants:` block when doing so improves consistency and maintainability.

For example:

```yaml
constants:
  tcp_protocol: TCP
  sentinel_value: -1
```

Sentinel values should always have a clearly defined condition describing when the sentinel is valid.

A sentinel value should not be introduced without also defining the eligibility or applicability condition under which it represents a valid state.

### 4.7 YAML Type Handling

YAML values should retain the intended data type throughout configuration processing.

Explicit `!!str` tags should be used when YAML could otherwise interpret a value as another type and that value must remain a string.

This is particularly relevant for:

* Numeric-looking strings.
* Regular expressions.
* Protocol numbers used as string keys.
* Format strings.
* Dataset field names that may resemble other YAML types.

For example:

```yaml
protocol: !!str '6'
pattern: !!str '\d{2}-\d{2}-\d{4}'
field: !!str 'Flow ID'
```

Values that are genuinely numeric should remain numeric and should not be unnecessarily represented as strings.

### 4.8 Reusable Configuration Structures

Repeated configuration structures should be defined once and reused through YAML anchors, aliases, and merge keys where this improves consistency.

Reusable fragments should use descriptive `snake_case` anchor names.

For example:

```yaml
templates:
  error: &error
    severity: error
    action: reject
```

Repeated values such as attacker IP lists, validation templates, data-type definitions, or other structurally identical objects should be reused rather than independently duplicated.

Anchor definitions should remain grouped in an appropriate section such as `templates:` rather than being introduced incidentally within unrelated configuration.

### 4.9 Expressions and Formulas

Multi-line expressions should use YAML block scalars according to their purpose.

* `>` should be used for arithmetic or mathematical expressions that read naturally as a continuous expression.
* `|` should be used for boolean, logical, or repair expressions where line structure is meaningful.

Every formula or expression that depends on fields or constants should identify its dependencies through a `requires:` list or equivalent explicit field declaration.

Expressions should not rely on undocumented dependencies.

Boolean expressions should use the project's established expression syntax consistently rather than mixing incompatible conventions.

### 4.10 Explicit Column and Field Definitions

Feature and column sets should be declared explicitly rather than inferred where the configuration defines a specific data contract.

Purpose-specific lists should remain clearly separated.

Examples include:

* `repairable:` — columns that can be repaired using defined formulas.
* `non_repairable:` — columns that must not be automatically repaired.
* `columns_to_drop:` — columns removed entirely.
* `output_feature_columns:` — the canonical ordered list of columns produced by a stage.
* `output_field_names:` — the canonical output fields of an extraction or parsing stage.

Output column and field lists should preserve their intended emission order rather than being alphabetically reordered.

### 4.11 Validation Rules

Validation rules should use a consistent structured representation.

Where a configuration contains a `rules:` list, each rule should have a predictable structure containing the information required to identify, evaluate, and, where applicable, repair the condition.

Severity and action definitions should be reusable through configuration templates rather than repeatedly redefining the same structure within individual rules.

Rule identifiers should follow a consistent naming and numbering convention within the configuration file.

Rules that represent different categories of validation should use identifiers that make those categories distinguishable.

### 4.12 Validation Schema and Reusable Types

Validation schemas should define reusable validation and data-type templates where multiple fields share the same semantic requirements.

A reusable template may define properties such as:

```yaml
dtype:
validation:
  allow_negative:
  allow_inf:
  allow_nan:
  minimum:
  maximum:
  sentinel:
```

Features sharing the same semantic type and validation requirements should reference the appropriate template rather than duplicating identical validation definitions for each individual feature.

Non-numeric fields such as identifiers, timestamps, and labels should be represented separately where their validation requirements differ from numeric features.

### 4.13 Field Mappings

Field-mapping structures such as `input_field_mapping:`, `output_field_names:`, and `column_mapping:` should remain simple and predictable.

Mappings should generally remain one level deep where a direct field-to-field relationship is sufficient.

Field order should follow the logical structure of the data rather than being alphabetically sorted.

For network fields, a consistent ordering such as identifiers, addresses, ports, protocol, timing, and payload should be maintained where applicable.

### 4.14 Stream and Feature-Extraction Configuration

Windowed statistical or behavioral feature extraction should use a consistent configuration structure.

A stream should define the fields used to group events and, where applicable, the eligibility condition and value being aggregated.

A feature should identify the stream it uses, the statistic being calculated, its statistic-specific parameters, missing-value behavior, and the formula used to produce the final feature.

Where expressions are used, their dependencies should be explicitly declared.

The distinction between **eligibility**, **value extraction**, **statistical aggregation**, and **final feature calculation** should remain clear in the configuration.

### 4.15 Packet Parsing Configuration

Packet-parsing configuration should organize protocol-specific information according to protocol layers where appropriate.

Parsing definitions may contain:

* Byte offsets.
* Field lengths.
* Bit masks.
* Bit shifts.
* Protocol labels.
* Output field definitions.

Offset and parsing knowledge should remain within the configuration belonging to the parser that owns that responsibility.

When multiple parsers operate at different depths or provide different representations, their configuration should remain independently understandable rather than creating unnecessary coupling between parser configurations.

Known limitations or unverified assumptions concerning parsing behavior should be documented close to the affected configuration so that the limitation remains visible to future development.

### 4.16 Configuration Validation

Configuration should be validated before being used by components that depend on it.

Validation should identify invalid values, missing required settings, incompatible combinations, and malformed configuration structures as early as practical.

Configuration validation should remain consistent with the expected schema and behavior of the component using the configuration.

### 4.17 Paths and Environment-Specific Settings

Paths and environment-dependent values should be configurable rather than embedded throughout source code.

Machine-specific paths should not be unnecessarily hardcoded into reusable project components.

Where a setting is inherently specific to a development environment, it should remain distinguishable from project-wide configuration so that environment-specific values do not silently become project requirements.

### 4.18 Avoid Configuration Duplication

A single conceptual setting should have a clear authoritative location.

The same parameter should not be independently defined in multiple configuration files when doing so can result in conflicting values or ambiguous behavior.

Where multiple components require the same value, the configuration architecture should provide a clear mechanism for sharing or referencing that value.

### 4.19 Reproducibility

Configuration required to reproduce an experiment, processing operation, model training run, or other significant result should be retained alongside the corresponding development or experimental record where practical.

Changes to important configuration values should remain traceable so that the conditions under which an artifact or result was produced can be determined.

### 4.20 Secrets and Sensitive Values

Secrets, credentials, access tokens, private keys, and other sensitive values should not be stored directly in version-controlled configuration files.

Environment variables or appropriate local configuration mechanisms should be used for values that must remain outside the repository.

Configuration committed to the repository should remain safe to share within the intended project context.

### 4.21 Configuration Changes

Configuration changes should be evaluated for their effect on existing processing pipelines, experiments, models, artifacts, and reproducibility.

Changes that alter the meaning or structure of established configuration should be considered deliberately and discussed with the relevant contributors when their impact extends beyond the immediate component being modified.

Configuration should evolve with the system, but structural changes should provide a clear technical benefit rather than being introduced solely for stylistic preference.

---

## 5. Architecture Policy

The architecture of PrognoSpect should remain modular, understandable, and consistent as the system evolves. Architectural decisions should preserve clear responsibilities between components, predictable data flow, and the ability to extend or replace individual parts without unnecessary changes to unrelated parts of the system.

### 5.1 Separation of Responsibilities

Each component should have a clearly defined responsibility within the system.

Components should not combine unrelated processing stages, model responsibilities, data management, configuration handling, or interface responsibilities without a clear architectural reason.

Where multiple stages are required to perform a larger operation, the stages should remain distinguishable even when they are closely related.

### 5.2 Architectural Boundaries

Established boundaries between major components and processing stages should be preserved.

Components should interact through clearly defined inputs, outputs, interfaces, and data contracts rather than relying on hidden dependencies or internal implementation details.

Changes to one component should avoid requiring unnecessary changes to unrelated components.

### 5.3 Data Flow and Representation Contracts

Data passed between architectural components should have a defined structure and purpose.

Changes to shared representations, schemas, feature sets, graph representations, state representations, or intermediate outputs should consider all components that consume them.

A representation shared by multiple components should have one clearly defined contract rather than allowing each consumer to interpret the same data differently.

### 5.4 Model Architecture

PrognoSpect's predictive models should remain separated according to their distinct responsibilities.

The World Model and classifier are separate architectural components. They may use the same processed state representation or other shared data, but their training, evaluation, and prediction responsibilities remain independent.

A component should not become implicitly dependent on another model's output merely because the outputs are available. Such a dependency should represent an intentional architectural decision and be reflected in the relevant data flow and component interfaces.

### 5.5 Modularity and Extensibility

Architectural components should be designed so that individual implementations can be extended, replaced, or improved without unnecessarily restructuring unrelated parts of the system.

New algorithms, models, processing methods, or supporting components should integrate with established interfaces and responsibilities where practical.

Extensibility should not require unnecessary abstraction or additional architectural layers where the existing structure already provides an appropriate integration point.

### 5.6 Dependency Direction

Dependencies should follow the logical direction of the architecture.

Components should avoid unnecessary circular dependencies, hidden coupling, and direct dependence on implementation details belonging to other components.

Common or lower-level functionality should remain sufficiently independent from higher-level application logic to allow reuse and modification without creating unnecessary coupling.

### 5.7 Shared Components and Interfaces

Functionality used by multiple components should have a clearly identified authoritative implementation.

Duplicate implementations of the same architectural responsibility should be avoided when they can result in inconsistent behavior.

Shared interfaces, schemas, representations, and utilities should remain stable enough for their intended consumers while still being allowed to evolve when a technical change requires it.

### 5.8 Experimental and Primary Architecture

Experimental implementations should remain separated from the primary architecture while their suitability is being evaluated.

When an experimental approach becomes part of the primary system, it should be integrated into the established architecture rather than maintained as an independent parallel implementation.

Experimental code should not establish undocumented dependencies on production components that make later integration or removal unnecessarily difficult.

### 5.9 Architectural Changes

Changes to component boundaries, major data flows, shared interfaces, model relationships, or other fundamental architectural decisions should be considered in terms of their effect on the wider system before implementation.

A local implementation convenience should not introduce a broader architectural change without considering its effects on existing components, configuration, data flow, testing, documentation, and future development.

Significant architectural deviations should be discussed with the relevant project contributors before being incorporated into the primary architecture.

### 5.10 Architecture Documentation

The architecture policy defines how the system should be structured and evolved; it does not replace technical architecture documentation.

Detailed component diagrams, data flows, model designs, interfaces, implementation decisions, and planned architectural changes should be documented in the appropriate technical documentation.

Documentation should distinguish between implemented architecture, experimental approaches, and planned future architecture.

---

## 6. Documentation & Language Policy

Documentation within PrognoSpect should accurately represent the project's implementation, architecture, decisions, and development history. Documentation should use consistent terminology, clear technical language, and remain aligned with the actual state of the project.

### 6.1 Documentation Accuracy

Documentation should describe the actual state of the project.

Implemented functionality, experimental work, planned functionality, deferred work, and deprecated functionality should be distinguishable.

Planned or proposed work should not be documented as implemented functionality.

Known limitations, assumptions, and relevant constraints should be documented where they materially affect the understanding or use of a component.

### 6.2 Documentation Scope

Information should be documented in the location appropriate to its purpose.

Project-level information should remain in project-level documentation.

Detailed architecture, implementation behavior, interfaces, processing pipelines, algorithms, and technical procedures should be documented in appropriate technical documentation.

Development history should be recorded in the development log.

Project policies and engineering standards should remain in the project development policies document.

The same information should not be unnecessarily duplicated across multiple documents when a clear authoritative location exists.

### 6.3 Terminology Consistency

Established project terminology should be used consistently across source code, configuration, documentation, diagrams, development records, and other project materials.

New terminology should be introduced only when it represents a meaningful distinction or provides a clearer description of a concept.

Different names should not be used interchangeably for the same component or concept without a clear reason.

### 6.4 Language and Writing Style

Project documentation should use clear, direct, and technically precise language.

Documentation should prioritize useful technical information over unnecessary background explanation or promotional language.

Descriptions should state what a component does, how it behaves, or why a decision was made rather than relying on vague statements.

Technical terms should be used consistently and precisely throughout the project.

### 6.5 README Policy

The README should provide the information necessary to understand, set up, and use the project at a project level.

It should contain relevant project purpose, major capabilities, required dependencies, setup or execution procedures, and other information necessary for users or contributors to work with the repository.

Detailed implementation explanations, extensive development history, and internal engineering decisions should be documented separately rather than making the README an implementation record.

README content should remain consistent with the actual project state.

### 6.6 Technical Documentation

Technical documentation should describe implementation and design details that are too specific or extensive for project-level documentation.

This may include architecture, data flow, processing stages, configuration behavior, module responsibilities, model design, interfaces, algorithms, experimental procedures, and operational procedures.

Technical documentation should distinguish between currently implemented behavior and planned or experimental approaches.

When implementation changes materially affect documented behavior, the relevant technical documentation should be updated.

### 6.7 Chronological Documentation

Documentation that records project development, research, decisions, investigations, or other historical activity should preserve the chronological order in which events occurred.

Related work may be grouped where appropriate, but later discoveries, decisions, or changes should not be presented as though they occurred earlier.

Documentation should describe the actual progression of the work rather than reconstructing events into a more polished sequence.

### 6.8 Append-Only Historical Records

Historical project records should preserve finalized information once it has been recorded.

New information should be added as new entries or sections rather than unnecessarily rewriting, restructuring, or paraphrasing previously finalized content.

When a correction is required, only the relevant incorrect portion should be modified.

Previously finalized wording should remain unchanged unless a deliberate correction is required.

### 6.9 Recording Development and Research

Documentation of development and research should record actual work, decisions, discoveries, investigations, implementations, changes, and relevant technical findings.

The distinction between decisions, implementations, discoveries, and planned or deferred work should remain clear.

Planned or future work should not be documented as completed work.

Documentation should preserve meaningful technical details when they are necessary to understand the development or the resulting implementation.

### 6.10 Documentation of Development Evolution

Documentation should capture meaningful changes in the evolution of the project where applicable.

Problems, investigations, findings, decisions, and resulting implementations should be recorded when they materially contribute to understanding why the project changed.

This should reflect the actual development process rather than imposing a fixed narrative structure on every entry.

### 6.11 Dates and Temporal References

Chronological documentation does not require dates for every entry.

Dates should be included when they provide useful context or are specifically required.

Relative temporal references that may become ambiguous over time should be avoided.

### 6.12 Meta-Commentary

Documentation should contain the relevant project information rather than unnecessary commentary about the process of documenting it.

Statements about adding, rewriting, updating, or generating documentation should be avoided unless they are themselves relevant to the project record.

### 6.13 Comments and Explanatory Text

Comments and explanatory text should provide useful engineering context rather than simply restating information that is already evident from the code, configuration, or surrounding documentation.

They should be used for non-obvious behavior, engineering caveats, assumptions, limitations, implementation constraints, or relevant TODOs.

When a rule, configuration option, or behavior requires a substantive explanation, structured documentation should be preferred where the format supports it.

### 6.14 Documentation Changes

Changes to architecture, processing behavior, configuration, interfaces, workflows, or other documented project behavior should be accompanied by corresponding documentation updates when the change materially affects existing documentation.

Documentation should reflect implemented behavior rather than intended behavior that has not yet been implemented.

### 6.15 Documentation Maintenance

Documentation should be maintained as part of development rather than treated as a separate activity performed only after major milestones.

When documentation becomes inaccurate because of an implementation change, the relevant documentation should be corrected as part of that change.

Historical records should retain their chronological and append-only characteristics even when other project documentation is updated normally.

---

## 7. Testing & Validation Policy

Testing and validation within PrognoSpect should provide reliable evidence that implemented changes behave as intended. Tests should exercise real project components and representative inputs while remaining consistent with the production execution path.

### 7.1 Manual Validation

PrognoSpect currently uses manual test execution rather than an automated testing framework.

Tests should therefore be implemented as executable validation procedures that can be deliberately run against the relevant component or flow.

A test should verify actual behavior rather than merely confirming that execution completed without an error.

### 7.2 Test Structure

Each test should be implemented as a plain function rather than introducing a separate test class.

Each test file should contain one primary test corresponding to the module or function being validated.

The test should remain callable from another module and should not depend on a special entry-point block or hardcoded execution environment.

### 7.3 Test Scope

A test should cover the appropriate execution scope for the behavior being validated.

A file-level test should exercise the module under test together with the upstream modules that form part of its normal execution flow.

Real implementations should be used rather than mocking or stubbing dependency modules when validating the actual project flow.

When the final module in a flow is the natural endpoint of the behavior being tested, the file-level test should serve as the flow-level validation rather than creating a duplicate test for the same execution path.

When a dependency belongs to a separate flow and is produced by another pipeline, the test should consume that dependency as an input rather than reproducing the separate flow inside the test.

### 7.4 Test Inputs

External dependencies required by a test should be supplied as function arguments rather than embedded as hardcoded paths or environment-specific values.

This includes source data paths, executable paths, configuration paths, working directories, output paths, and other external resources.

Where the production module provides an established default for an input, the test may use that existing default rather than defining a separate duplicate value.

Tests should use real, caller-provided project data and dependencies where the behavior being validated requires them.

Synthetic, mocked, or simplified inputs should not replace representative real inputs when they would prevent meaningful validation of the production execution path.

### 7.5 Representative Execution

Tests should use the same configuration structure, interfaces, and call patterns used by the production implementation.

A test should validate the real integration between components rather than constructing a simplified test-only representation that bypasses relevant production behavior.

Configuration supplied to a test should therefore follow the same structure expected by the production component.

### 7.6 Complete Output Consumption

When a tested component produces an iterable, stream, generator, or other incremental output, the test should consume the complete output when determining totals or validating complete execution.

Counts such as packet, row, record, or feature totals should represent the complete produced output rather than only the retained sample.

Tests should retain only a bounded sample of records when the full output is not required for inspection, so that validation remains practical for large inputs.

### 7.7 Test Output

Each test should produce a single structure-describing text output containing enough information to inspect the result of the validation.

The output should identify:

1. The module, function, or method under test.
2. The relevant input identifiers and dependencies.
3. The true total counts produced.
4. The number of records retained for inspection.
5. The structure of the produced records, including field names and types.
6. The retained sample records and their values.

Test output should have a predictable location and naming convention while allowing the output path to be overridden when required.

The test function should return the path to the generated output so that the result can be inspected or consumed by another caller.

### 7.8 Test Output Directories

Directories required specifically by the test should be created by the test when necessary.

Tests should not assume that their required working or output directories already exist.

A test should not create directories or resources that are the responsibility of the module under test.

### 7.9 Regression Validation

Changes should be validated for their effect on existing behavior in addition to the new or modified behavior they introduce.

When a change affects shared functionality, interfaces, configuration, data structures, or execution flow, relevant dependent behavior should also be considered for regression.

Validation should be proportional to the scope of the change.

### 7.10 Failure Investigation

A failed test should be investigated to determine whether the failure originates from the implementation, its inputs, configuration, environment, dependency, or the test itself.

Failures should not be hidden, bypassed, or treated as successful merely because execution reached completion.

When a test exposes an implementation defect, the defect should be addressed or explicitly recorded before the tested behavior is considered validated.

### 7.11 Test Independence and Reuse

Tests should remain focused on the behavior they are intended to validate while reusing the actual project interfaces and configuration structures.

A test should not introduce alternative implementations of production logic merely to make validation easier.

Reusable test inputs or procedures may be shared where this improves consistency without obscuring which component or behavior is being validated.

### 7.12 Test Maintenance After Structural Changes

When project restructuring, renaming, or relocation affects a test, only the import paths, call sites, or other portions directly affected by the change should be modified.

Unrelated test logic should remain unchanged.

This preserves the validity of the existing validation procedure while adapting it to the new project structure.

### 7.13 Validation Workflow

Before implementing a test, the relevant import and execution chain should be understood.

Dependencies referenced by the test should be confirmed as existing project components. Unknown or unverified dependencies should be investigated before being incorporated into the test.

Each test should be executed and confirmed to work before being treated as established validation or before proceeding to dependent test development.

### 7.14 Test Style

Tests should follow the same coding and structural standards as the rest of the project.

Test code should avoid unnecessary abstraction, duplicated configuration structures, and unrelated implementation changes.

Test code should remain representative of the production system rather than becoming a separate simplified implementation of the behavior it is intended to validate.

---

## 8. Dependencies & Tooling Policy

External libraries, software tools, runtimes, build systems, and development utilities used by PrognoSpect should be introduced and maintained deliberately. Dependencies and tools should support the project's technical requirements without creating unnecessary complexity, duplication, or compatibility problems.

### 8.1 Dependency Justification

New dependencies should have a clear technical purpose within the project.

A dependency should be introduced when it provides functionality that is required or provides a meaningful technical benefit that cannot be reasonably achieved through existing project functionality.

Dependencies should not be added solely for convenience when an established project dependency or implementation already provides the required capability.

### 8.2 Prefer Established Dependencies

Existing project dependencies should be preferred when they appropriately satisfy a new requirement.

Multiple libraries or tools providing substantially overlapping functionality should not be introduced without a clear technical reason.

Introducing an alternative implementation should consider the additional maintenance, compatibility, configuration, and dependency burden it creates.

### 8.3 Toolchain Compatibility

New dependencies and tools should be compatible with the project's existing development and execution environment.

Compatibility should be considered with respect to relevant programming languages, runtimes, operating systems, build systems, frameworks, and existing dependencies.

Known compatibility conflicts should be investigated and resolved before a dependency or tool becomes part of the primary development environment.

### 8.4 External Tools

External software required for development, data processing, building, testing, execution, or other project operations should be treated as part of the project's tooling environment.

Required external tools should have their role and relevant setup requirements documented in the appropriate project documentation.

Tool-specific behavior or limitations that materially affect project functionality should be documented where necessary.

### 8.5 Environment-Specific Configuration

Environment-specific dependency paths, executable locations, working directories, and other machine-specific settings should not be embedded into source code when they can reasonably be configured.

Project configuration should distinguish between project-defined behavior and values that depend on a particular development or execution environment.

### 8.6 Dependency Scope

Dependencies should be used only where required.

Dependencies needed exclusively for testing, experimentation, development, documentation, or other auxiliary activities should remain distinguishable from dependencies required by the primary system.

A development-only tool should not become an unnecessary runtime dependency.

### 8.7 Dependency Changes

Adding, removing, replacing, upgrading, or substantially changing a dependency should consider its effect on the existing project.

Relevant effects may include compatibility, APIs, behavior, configuration, build processes, execution environments, performance, reproducibility, and dependent components.

Dependency changes that require corresponding source, configuration, documentation, or testing changes should update those components as part of the same development change.

### 8.8 Tool Selection

Tools should be selected according to the technical requirements of the task and their fit with the existing project environment.

A tool should not be introduced solely because it is commonly used or provides a marginal convenience when its adoption would introduce disproportionate complexity or maintenance requirements.

Where multiple tools can satisfy the same requirement, the choice should consider compatibility with the existing architecture, workflow, dependencies, and development environment.

### 8.9 Avoid Unnecessary Tooling

The project should avoid accumulating tools that provide overlapping or rarely used functionality without a clear benefit.

Tools that are no longer required should not remain part of the primary development environment solely because they were previously used.

Removing a tool should also consider whether existing documentation, configuration, tests, or workflows depend on it.

### 8.10 Reproducibility

Dependencies and external tools that materially affect project execution should be identifiable and reproducible across supported development environments.

The project should retain sufficient dependency and tooling information to allow another developer to establish an equivalent environment without relying on undocumented local configuration.

### 8.11 Dependency and Tooling Documentation

Dependencies and external tools that are necessary to build, execute, test, process data, or otherwise operate the project should be documented in the appropriate location.

Documentation should reflect the tools and dependencies actually required by the current implementation rather than retaining obsolete requirements.

### 8.12 Changes to the Development Environment

Changes to the established development environment should be made with consideration for their effect on the wider project.

Replacing a runtime, build system, framework, external processing tool, or other fundamental development dependency should be treated as a broader technical change when it affects existing components or workflows.

Significant tooling changes should be evaluated for compatibility, migration effort, reproducibility, and maintenance impact before becoming part of the established project environment.

---

## 9. Version Control Policy

Version control should preserve a clear, reliable, and understandable history of PrognoSpect development. Repository changes should be organized so that the history reflects meaningful development work and the state of the project remains reproducible.

### 9.1 Commit Discipline

Commits should represent meaningful and coherent changes.

Unrelated changes should not be unnecessarily combined into the same commit.

A commit should have a clear purpose and should contain the changes necessary to represent that purpose without unrelated modifications.

### 9.2 Commit Scope

The scope of a commit should remain appropriate to the change being made.

When a development change requires corresponding modifications to source code, configuration, tests, documentation, or other project files, those related changes should remain coherent within the relevant change history.

Unrelated cleanup, restructuring, or formatting changes should not be mixed into a commit merely because they are convenient to perform at the same time.

### 9.3 Commit Messages

Commit messages should clearly communicate the purpose of the change.

Messages should describe the relevant development change rather than relying on vague or ambiguous descriptions.

Commit history should provide enough information to understand the progression of significant project changes.

### 9.4 Branching

Branches should be used when separate development work requires isolation from the primary development line.

Branch structure should remain as simple as practical and should reflect actual development needs rather than introducing unnecessary workflow complexity.

### 9.5 History Preservation

Existing version-control history should not be rewritten without a clear technical or repository-management reason.

Changes to history should consider their effect on collaborators, references to existing commits, and the ability to trace previous project states.

### 9.6 Tracked and Generated Files

Files required to build, configure, execute, test, document, or otherwise reproduce the project should be tracked appropriately.

Temporary files, caches, local environment files, and disposable generated output should not be added to version control.

Generated files that are deliberately retained as project artifacts should be handled according to their established role within the project structure.

### 9.7 Large Data and Generated Artifacts

Large datasets and generated outputs should not be committed to the repository merely because they are available locally.

Persistent generated artifacts should follow the project's established storage and artifact-management approach.

Repository tracking should distinguish between files required as part of the project and files generated during local development.

### 9.8 Configuration and Sensitive Information

Configuration required by the project should be version controlled where it is part of the reproducible project definition.

Secrets, credentials, private keys, and other sensitive information should not be committed to the repository.

Machine-specific or private configuration should remain separate from shared project configuration when it cannot be safely represented as project-level configuration.

### 9.9 Repository Consistency

Changes should avoid knowingly leaving the repository in an inconsistent or unnecessarily broken state.

When a change temporarily requires an intermediate state that cannot function independently, the development process should minimize the duration of that state and preserve a coherent final change.

### 9.10 Related Project Changes

When a change affects multiple parts of the project, the relevant modifications should be kept consistent within version history.

Source code, configuration, tests, documentation, and other dependent files should not be left permanently inconsistent when they are changed as part of the same development work.

### 9.11 Version-Control Scope

Version control should preserve the project itself and the information necessary to understand and reproduce its development.

Repository contents should follow the project's established structure rather than becoming a general storage location for temporary experiments, local environments, unrelated files, or disposable outputs.

---

## 10. Change Management

Changes to PrognoSpect should be introduced deliberately and with consideration for their effect on the existing system. Changes should have a clear purpose, remain appropriately scoped, and preserve established project structure and behavior where practical.

### 10.1 Purpose and Scope

Every significant change should have a clear technical purpose.

The scope of a change should remain proportional to the requirement being addressed. A change intended to modify a specific behavior should not unnecessarily expand into unrelated restructuring, cleanup, or redesign.

### 10.2 Impact Assessment

Changes should be considered in terms of their effect on the wider project before they are incorporated.

Relevant effects may include architecture, source code, configuration, data flow, interfaces, schemas, tests, documentation, dependencies, tooling, reproducibility, and existing behavior.

The assessment should be proportional to the significance of the change.

### 10.3 Minimal Necessary Change

Changes should modify only what is necessary to achieve their intended purpose.

Unrelated code, configuration, documentation, structure, or behavior should not be changed merely because they are encountered during implementation.

Broader changes should have a clear technical justification rather than being introduced as incidental cleanup.

### 10.4 Structural Changes

Changes to established directory structures, module boundaries, interfaces, configuration structures, schemas, or other project conventions should have a clear technical reason.

Structural changes should consider their effect on dependent components, configuration, tests, documentation, tooling, and development workflows before being incorporated.

### 10.5 Compatibility

Changes to established interfaces, configuration structures, schemas, outputs, or other contracts should consider existing consumers and dependent components.

Where compatibility cannot be preserved, the affected components should be identified and updated as part of the change rather than being left in an inconsistent state.

### 10.6 Validation Before Adoption

Changes should be validated before being treated as established project functionality.

The level of validation should be appropriate to the scope and potential impact of the change.

Changes affecting shared components, architectural boundaries, data flow, configuration, or other widely used functionality should receive corresponding broader validation.

### 10.7 Documentation Consistency

Changes that materially alter documented behavior should be accompanied by the corresponding documentation updates.

Documentation should reflect the resulting implementation rather than remaining aligned with the previous behavior after a change has been adopted.

### 10.8 Experimental Changes

Experimental approaches should remain distinguishable from established functionality while they are being evaluated.

Experimental changes should not silently alter the established behavior or architecture of the primary system.

When an experimental approach is adopted as part of the primary implementation, the resulting change should be integrated according to the project's established architectural, coding, configuration, testing, and documentation policies.

### 10.9 Traceability and Recovery

Significant changes should remain traceable through version control and relevant project documentation.

Development history should provide sufficient information to identify what changed and why.

Changes should be introduced in a manner that allows problems to be investigated and, where necessary, the affected change to be isolated or reverted without unnecessarily compromising unrelated project history.

### 10.10 Significant Deviations

Changes that substantially deviate from established architecture, coding conventions, configuration structures, project organization, development workflows, or other project policies should be considered deliberately before adoption.

Significant deviations should be discussed with the relevant project contributors when their effects extend beyond the immediate component or development task.

The convenience of a local implementation should not by itself justify a broader deviation from established project standards.

---

## 11. Policy Maintenance

The project development policies should evolve alongside PrognoSpect's development practices while remaining stable enough to provide consistent engineering standards.

### 11.1 Living Document

This policy should be treated as a maintained project document rather than a fixed specification.

Policies may evolve when project architecture, development practices, tooling, or other established project requirements change.

### 11.2 Alignment with the Project

The policies should reflect how PrognoSpect is actually developed and maintained.

When established project practices change substantially, the relevant policy should be reviewed to determine whether it remains appropriate.

The policy should not prescribe practices that conflict with the established architecture or legitimate technical requirements of the project.

### 11.3 Policy Changes

Changes to the policy should have a clear reason related to project development, engineering practice, or maintainability.

Changes should not be introduced solely to alter wording or style when the existing policy already communicates the intended standard clearly.

When a policy is changed, the resulting wording should remain consistent with the other policies in the document.

### 11.4 Resolving Conflicts

If two policies conflict, the conflict should be identified and resolved deliberately rather than silently disregarding one of the policies.

Where a general policy conflicts with a specific technical requirement, the relevant context and implications should be considered before determining the appropriate approach.

Significant deviations from an established policy should be deliberate and should consider their effect on the wider project.

### 11.5 Contextual Application

Policies should be interpreted according to the context in which they are applied.

Not every policy applies identically to every component, development task, experimental implementation, or project artifact.

The purpose of a policy is to establish consistent engineering principles without preventing technically justified implementation decisions.

### 11.6 Avoiding Unnecessary Specification

This document should define development standards rather than duplicate detailed implementation specifications.

Specific architecture, algorithms, configuration schemas, interfaces, dataset structures, tool procedures, and other implementation details should remain in their appropriate technical documentation.

When such details change, the policy should only be changed when the underlying development standard itself has changed.

### 11.7 Policy Review

The policies should be reviewed when substantial changes to the project's architecture, development workflow, tooling, or engineering practices occur.

Routine development should not require continual modification of the policy.

Policy changes should preserve useful established standards while allowing outdated or unnecessary rules to be removed or revised when the project's requirements change.
