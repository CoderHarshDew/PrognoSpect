# PrognoSpect — Foreseeing What Follows

**An AI world model for predictive cyber defence.**

PrognoSpect learns how network states evolve under adversarial activity and forecasts the likely progression of an ongoing attack, giving defenders foresight into what may happen next instead of only telling them what already happened.

## Table of Contents

* [Overview](#overview)
* [Dataset](#dataset)
* [Repository Structure](#repository-structure)
* [Getting Started](#getting-started)
* [Contributing](#contributing)
* [License](#license)

---

## Overview

Most network defence tooling is reactive: it flags an attack once it is already visible in the traffic. PrognoSpect takes a predictive approach. It models a network as a system that moves through a sequence of states, learns how those states change when an attacker is active, and uses that knowledge to forecast where the attack is heading, how likely each outcome is, and how much time defenders have to respond.

Because real attacks are rarely deterministic, PrognoSpect does not commit to a single prediction. It keeps several probable future trajectories and reports how uncertain the forecast is, so analysts can judge how much to trust a warning.

---

## Dataset

PrognoSpect is developed and evaluated using the **CSE-CIC-IDS2018** dataset, produced by the Communications Security Establishment (CSE) and the Canadian Institute for Cybersecurity (CIC). It contains realistic network traffic captured in a large simulated enterprise environment, covering benign activity alongside a range of attack scenarios such as brute force, DoS, DDoS, botnet, web attacks, infiltration, and Heartbleed. The dataset is available as raw PCAPs and as flow-level CSVs generated with CICFlowMeter.

The dataset is large and is **not stored in this repository**; the `dataset/` directory is git-ignored. Raw captures are downloaded separately and processed locally.

---

## Repository Structure

```
PrognoSpect/
├── SIHproject/      temporary - scheduled for removal
├── config/          YAML configuration files
├── docs/            Project documentation
├── images/          Images 
├── notebooks/       Jupyter notebooks for exploration and experiments
├── src/             Source code
├── static/          Static assets for the web interface
├── templates/       HTML templates for the web interface
├── .gitignore
├── LICENSE
├── readme.md
└── requirements.txt
```

Directories that hold generated or bulky data (`dataset/`, `out/`, `reports/`, `logs/`, `third_party/`) are git-ignored and will only exist locally after you run the project.

---

## Getting Started

### Clone the repository

```bash
git clone https://github.com/CoderHarshDew/PrognoSpect.git
cd PrognoSpect
```

To work on a specific branch instead of `main`:

```bash
git clone --branch <branch-name> https://github.com/CoderHarshDew/PrognoSpect.git
```

To pull the latest changes later:

```bash
git pull origin main
```

### Set Up CICFlowMeter

PrognoSpect uses a standalone, patched CICFlowMeter runtime for PCAP-to-flow extraction. The required CICFlowMeter runtime is provided separately as a ZIP release asset.

#### Install Java 8

CICFlowMeter uses an older Gradle/runtime environment and requires Java 8.

Install a Java 8 JDK such as Eclipse Temurin 8.

After installation, verify:

```powershell
java -version
javac -version
```

Both commands should report Java 8.

If another Java version is installed on your system, make sure Java 8 is selected for the CICFlowMeter environment.

On Windows PowerShell, for example:

```powershell
$env:JAVA_HOME="C:\Program Files\Eclipse Adoptium\jdk-8.0.504.1-hotspot"
$env:Path="$env:JAVA_HOME\bin;$env:Path"
```

Verify again:

```powershell
java -version
```

#### Download and Extract the CICFlowMeter Runtime

Download the `CICFlowMeter-PrognoSpect-<version>.zip` release asset provided with the corresponding PrognoSpect release.

Extract it to a permanent location.

For example:

```text
D:\programming\CICFlowMeter\
```

The extracted directory should contain:

```text
CICFlowMeter/
├── bin/
│   ├── cfm.bat
│   └── ...
├── lib/
│   ├── CICFlowMeter-4.0.jar
│   ├── jnetpcap.jar
│   └── ...
├── LICENSE.txt
├── README.md
├── PrognoSpect-patches.md
└── THIRD-PARTY-NOTICES.txt
```

Do not move or remove files from `bin/` or `lib/`. The runtime depends on the complete distribution.

#### Verify the CICFlowMeter Installation

From PowerShell, navigate to the extracted CICFlowMeter directory:

```powershell
cd "D:\programming\CICFlowMeter"
```

Verify that the CLI executable exists:

```powershell
Test-Path ".\bin\cfm.bat"
```

This should return:

```text
True
```

#### Test CICFlowMeter

CICFlowMeter's CLI accepts a PCAP file followed by an output directory:

```powershell
.\bin\cfm.bat "PATH_TO_PCAP" "OUTPUT_DIRECTORY"
```

For example:

```powershell
.\bin\cfm.bat "D:\data\example.pcap" "D:\data\output"
```

CICFlowMeter will process the PCAP and generate its Flow CSV in the specified output directory.

#### PrognoSpect Configuration

PrognoSpect needs to know the location of the CICFlowMeter executable:

```text
<path-to-CICFlowMeter>\bin\cfm.bat
```

For the example installation above:

```text
D:\programming\CICFlowMeter\bin\cfm.bat
```

Configure this path wherever the PrognoSpect configuration specifies the CICFlowMeter executable.

#### Important

The provided CICFlowMeter ZIP is already built and patched. **Do not run Gradle or rebuild CICFlowMeter when setting up PrognoSpect.**

The supplied runtime already contains:

* The required CICFlowMeter JARs
* The matching jNetPcap Java library
* The required native jNetPcap Windows libraries
* The corrected Windows launcher
* The required runtime directory structure

The only external prerequisite that must be installed separately is **Java 8**.

For details about the modifications made to the upstream CICFlowMeter distribution, see `PrognoSpect-patches.md`. For third-party licensing and redistribution information, see `THIRD-PARTY-NOTICES.txt`.

### Install Wireshark / TShark

PrognoSpect uses **TShark**, the command-line network analyzer distributed with Wireshark, for PCAP inspection and packet-level processing.

Install **Wireshark** from the official website:

[Wireshark — Official Download Page](https://www.wireshark.org/download.html?utm_source=chatgpt.com)

TShark is included with the standard Wireshark installation. Ensure that it is installed when configuring Wireshark.

Verify the installation from PowerShell:

```powershell
tshark --version
```

The command should display the installed TShark version.

If `tshark` is not recognized, add the Wireshark installation directory to the system `PATH`. On a typical Windows installation:

```text
C:\Program Files\Wireshark\
```

PrognoSpect uses TShark through the command line; the Wireshark graphical interface is not required for the extraction workflow.

### Install AWS CLI

PrognoSpect uses the **AWS Command Line Interface (AWS CLI)** to access the publicly hosted CSE-CIC-IDS2018 dataset on Amazon S3.

Install AWS CLI using the official AWS installation guide:

[AWS CLI Installation Guide](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html?utm_source=chatgpt.com)

Verify the installation from PowerShell:

```powershell
aws --version
```

The command should display the installed AWS CLI version.

No AWS account or credentials are required for accessing the public CSE-CIC-IDS2018 S3 bucket used by PrognoSpect.

---

## Contributing

Contributions are currently not accepted from non-members. This project is being developed by Team CodeWhale for Smart India Hackathon 2026, and pull requests from outside the team will not be merged for now.

---

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.
