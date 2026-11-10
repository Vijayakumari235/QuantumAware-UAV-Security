[![DOI](https://zenodo.org/badge/1451574206.svg)](https://doi.org/10.5281/zenodo.24088247)
# Quantum-Aware Graph-Based UAV Security Risk Assessment Framework

Quantum-Aware Graph-Based Threat and Vulnerability Assessment for UAV Networks under Post-Quantum Cryptographic Transition

## Overview

This repository provides a Python-based reference implementation of a quantum-aware, graph-based framework for assessing security threats and structural vulnerabilities in Uncrewed Aerial Vehicle (UAV) networks during the transition from classical cryptography to post-quantum cryptography.

The framework integrates simulation-driven threat modelling, temporal multilayer graph construction, graph-theoretic vulnerability analysis, and a five-component Composite Risk Score (CRS). It supports reproducible evaluation of classical attacks and hypothetical quantum-capable cryptographic-compromise scenarios under heterogeneous UAV network configurations.

The implementation is intended for research, experimental methodology verification, vulnerability analysis, comparative assessment, and reproducible security evaluation.

## Key Features

- Configurable UAV network scenarios with star, mesh, and clustered topologies.
- Random Waypoint, Gauss–Markov, and Leader–Follower mobility models.
- Simulation of replay, Sybil, GPS spoofing, and denial-of-service attack conditions.
- Hypothetical quantum-capable compromise modelled through cryptographic trust-state transitions.
- Classical, post-quantum, and hybrid cryptographic configuration profiles.
- Temporal multilayer graph construction for communication and security analysis.
- Centrality, articulation-point, bridge-link, and minimum-cut analysis.
- Node-level and link-level vulnerability estimation.
- Five-component Composite Risk Score computation.
- Four reference risk assessment methods and five component-ablation experiments.
- Independent mission-disruption outcome validation.
- Statistical analysis, comparative evaluation, and research visualizations.
- Support for importing externally generated simulation traces.

## Proposed Framework

The framework consists of three principal algorithms.

### Algorithm 1: Quantum-Aware Threat Scenario Generation and Simulation

Generates reproducible UAV security scenarios based on topology, mobility, traffic, cryptographic configurations, attack types, and severity levels. It produces communication, security, and attack-related event traces for subsequent analysis.

### Algorithm 2: Graph-Based Vulnerability Analysis

Processes temporal graph snapshots to identify structurally critical nodes and links using degree, betweenness, closeness, and eigenvector centralities, articulation points, bridges, and mission-relevant minimum cuts. Attack-effect indicators are integrated to calculate temporal node and link vulnerability scores.

### Algorithm 3: Composite Quantum-Aware Risk Assessment

Combines five normalized security-risk dimensions:

1. Attack Likelihood
2. Mission and Quality-of-Service Impact
3. Inverse Detectability
4. Post-Quantum Cryptographic Cost–Security Factor
5. Graph Vulnerability

The Composite Risk Score is calculated using equal component weights:

$$
CRS = 0.20 \left( A + I + D_{\mathrm{inv}} + P + G \right)
$$

The resulting score ranges from 0 to 1 and is interpreted as Low, Medium, or High risk using predefined thresholds of 1/3 and 2/3.

## Technology Stack

- Programming: Python
- Graph Analysis: NetworkX
- Data Processing: NumPy, Pandas
- Scientific Computing: SciPy
- Visualization: Matplotlib
- Configuration: YAML
- Testing: pytest
- Data Formats: CSV and JSON
- External Simulation Compatibility: NS-3 and ArduPilot SITL trace integration

## Installation

Clone the repository and navigate to the project directory.

```bash
git clone <your-repository-url>
cd QuantumAware-UAV-Security
```

Install the project and its testing dependencies:

```bash
python -m pip install -e ".[test]"
```

Verify the installation:

```bash
pytest -q
```

## Running the Framework

### Single Scenario Execution

```bash
python run.py run --config configs/default.yaml --output results/single --keep-traces
```

This executes a configured analytical UAV security scenario, generates graph vulnerability measurements, and calculates the Composite Risk Score.

### Batch Experimental Evaluation

```bash
python run.py batch --config configs/default.yaml --limit 24 --seeds 101 102 --output results/demo --plots
```

This executes a selected collection of scenarios and produces evaluation records, comparative analysis, and research figures.

### Complete Factorial Experiment

```bash
python run.py batch --config configs/default.yaml --limit 0 --seeds 101 102 103 104 105 106 107 108 109 110 --swarm-sizes 10 --output results/full
```

The complete experimental design includes 1,782 scenario configurations and 10 independent seeds, resulting in 17,820 runs per UAV swarm size.

### Demonstration Execution

```bash
python scripts_demo.py
```

This executes a smaller analytical demonstration comprising 48 runs across attack and cryptographic conditions.

### External Trace Integration

```bash
python run.py import --config configs/default.yaml --scenario examples/scenario.json --csv /path/to/real_snapshots.csv --output results/external
```


## Experimental Design

The proposed experimental design considers:

| Parameter | Configuration |
| --- | --- |
| UAV Swarm Sizes | 10 and 50 UAVs |
| Network Topologies | Star, Mesh, Clustered |
| Mobility Models | Random Waypoint, Gauss–Markov, Leader–Follower |
| Traffic Profiles | Command and Control, Telemetry, Payload |
| Cryptographic Modes | Classical, PQC, Hybrid |
| Threat Scenarios | No Attack and Seven Active Threat Conditions |
| Attack Intensities | Low, Medium, High |
| Independent Seeds | 101–110 |
| Scenario Duration | 300 seconds |
| Total Configurations | 1,782 |
| Repetitions per Configuration | 10 |

## Evaluation Methodology

**Network and Security Assessment:** Communication performance degradation, attack effects, graph vulnerability, and cryptographic cost–security characteristics.

**Independent Outcome Validation:** AUROC, AUPRC, and correlation-based assessment using subsequently observed mission-disruption outcomes.

**Baseline Comparisons:** QoS-based, cryptographic, static graph-based, and temporal graph-based risk assessment methods.

**Ablation Analysis:** Five leave-one-component-out experiments evaluating the contribution of individual CRS dimensions.

**Statistical Evaluation:** Confidence intervals and paired bootstrap comparisons with multiple-comparison correction.

**Research Visualizations:** Risk-distribution plots, cryptographic configuration comparisons, and mission-disruption analysis.

## Repository Structure

```text
QuantumAware-UAV-Security/
├── configs/
│   └── default.yaml
├── docs/
│   └── EXTERNAL_INTEGRATION.md
├── examples/
│   └── scenario.json
├── src/
│   └── quantumuav/
│       ├── cli.py
│       ├── config.py
│       ├── simulator.py
│       ├── graph.py
│       ├── risk.py
│       ├── evaluation.py
│       └── io.py
├── tests/
│   └── test_pipeline.py
├── results/
├── README.md
├── IMPLEMENTATION_STATUS.md
├── requirements.txt
├── pyproject.toml
├── run.py
└── scripts_demo.py
```

## Implementation Scope and Scientific Limitations

The current repository includes a functional analytical simulation and risk-assessment pipeline. Its built-in simulator is a synthetic research backend and must not be represented as a native NS-3 or ArduPilot SITL implementation.

Actual NS-3/SITL co-simulation, wireless-network measurements, and post-quantum cryptographic benchmarking require independently configured external environments. The repository supports importing external simulation measurements but does not include a complete native co-simulation implementation.

Default cryptographic overhead profiles are illustrative rather than experimentally measured. Hypothetical quantum-capable cryptographic compromise is represented through predefined trust-state transitions. No quantum hardware, Shor's algorithm, Grover's algorithm, or actual quantum cryptanalysis is executed.

The generated demonstration data and figures are intended for implementation verification and should not be reported as experimentally validated NS-3/SITL findings.



## Research Applications

This framework can support research on UAV network cybersecurity, post-quantum cryptographic migration, temporal graph vulnerability, mission-critical communication resilience, explainable security-risk assessment, and simulation-based comparative security analysis.

## Reproducibility

The repository provides configurable experimental parameters, deterministic scenario identifiers, independent random seeds, automated testing, structured output records, and reproducible analysis procedures.

Researchers should retain simulator versions, cryptographic benchmark settings, generated traces, and configuration files when conducting independent experiments.

## Citation

If you use this implementation in academic research, please cite the associated manuscript:

*Quantum-Aware Graph-Based Threat and Vulnerability Assessment for UAV Networks under Post-Quantum Cryptographic Transition.*



## Acknowledgment

This implementation was developed to support reproducible research into quantum-aware security, structural vulnerability, and multidimensional risk assessment for dynamic UAV communication networks.
