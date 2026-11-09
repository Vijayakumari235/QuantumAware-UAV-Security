# Implementation status and reproducibility report

## Verified in this development environment

- 9/9 automated tests passed (`PYTHONPATH=src pytest -q`).
- One single-scenario CLI run completed.
- Batch CLI run with 8 scenarios completed and generated CSV/JSON and 600-dpi figures.
- A balanced analytical smoke run across 8 threat states × 3 crypto modes × 2 seeds (48 runs) completed.
- Evaluation correctly reports null for undefined metrics if only one outcome class is observed.
- The 48-run **synthetic/analytical** demo generated 13 positive future communication-failure labels; these are NOT manuscript results or NS-3/SITL measurements.

## Included modules

1. Deterministic DoE and scenario IDs (1,782 configurations per seed per swarm size)
2. Executable synthetic UAV mobility, links, traffic, attack and trust-state simulation
3. Time-stamped physical, routing and cryptographic graph-state records
4. Articulation/bridge/minimum-cut and normalized centrality analysis
5. Node and link vulnerability and temporal aggregation
6. Five-component CRS, risk levels, comparators and five ablations
7. Forward-only future mission disruption labels and validation with uncertainty
8. CLI for run, batch, external-trace import and evaluation
9. CSV/JSON research exports and 600-dpi figures
10. Automated tests and standalone offline source runner

## Not included (must not be misrepresented)

- Native NS-3.42 C++ integrated simulator implementation
- A deployed ArduPilot Copter SITL + NS-3 synchronized runtime
- Actual liboqs/OpenSSL cryptographic benchmark measurements
- Real UAV telemetry or RF-derived network measurements
- A field-validated, calibrated security risk predictor

These are *external experimental dependencies* for the manuscript's experimental claims. Importing their output is supported, but installing/executing those native systems is not performed by this ZIP.
