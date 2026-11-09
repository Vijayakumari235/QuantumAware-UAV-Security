# NS-3 / ArduPilot SITL Integration Boundary

The Python package is **fully runnable in analytical mode**. The manuscript's intended NS-3.42 + ArduPilot Copter 4.5.7 SITL installation is NOT bundled; it requires native C++/firmware/runtime integration beyond pip. An external simulator may export the following snapshot schema and import it without modifying CRS or graph-analysis code.

## External CSV schema

Each record represents one time snapshot. Columns:

`time_s,pdr,latency_ms,throughput_bps,connected_fraction,monitor_score,monitor_alarm,edges_json`

`edges_json` is a JSON-serialized object containing:

- `positions`: `[ [x,y,z], ... ]`, node 0 GCS, nodes 1..N UAVs
- `physical_edges`: `[ [u,v,{"loss":0.01, "distance_m":80.0}], ... ]`
- `routing_edges`: `[ [u,v], ... ]`; currently treated as undirected for the graph engine
- `mission_paths`: `[ [node, ..., 0], ... ]`
- `per_node`: `[ {"node":1, "pdr":0.98, "latency_ms":30, "compromised":0}, ... ]`
- `compromised_nodes`: `[ 3, ... ]`

All snapshot times must span both the configuration's warm-up, risk observation time and future mission-label horizon. The first `warmup_seconds` of traces define the no-attack QoS reference. Provide actual cryptographic overhead profiles in `configs/default.yaml` from liboqs/OpenSSL benchmark data before importing cryptographic study results.

## Recommended external execution flow

1. Install and verify NS-3.42 and ArduPilot Copter SITL separately on Linux.
2. Instrument NS-3 for UAV topology, mobility, 802.11 ad-hoc channels, PHY/MAC statistics, packet events, AODV/OLSR/DSDV and UDP attacks.
3. Couple SITL flight/navigation telemetry to network simulation in a time-synchronized way; preserve true coordinates separately from injected GPS coordinates.
4. Export physical and routing snapshots. Ensure all attacks are classified by source (packet/network events versus **hypothetical** cryptographic trust state).
5. Run an independent and non-leaky monitoring pipeline to obtain `monitor_score` and `monitor_alarm`.
6. Run `quantumuav import --csv ... --scenario ...` to compute graph vulnerabilities, CRS, baselines and ablations.

**Important:** The import path processes real traces *if the input is real*. The importer does not by itself establish real-world provenance, co-simulation correctness, measurement methodology or cryptographic implementation validity.
