"""Strict scenario definitions and factorial Design-of-Experiments generation."""
from __future__ import annotations
from dataclasses import dataclass, asdict
from itertools import product
from pathlib import Path
import hashlib, json
import yaml

TOPOLOGIES = ("star", "mesh", "clustered")
MOBILITY = ("random_waypoint", "gauss_markov", "leader_follower")
TRAFFIC = ("c2", "telemetry", "payload")
CRYPTO = ("classical", "pqc", "hybrid")
THREATS = ("none", "replay", "sybil", "gps_spoofing", "dos", "key_compromise", "auth_forgery", "combined_compromise")
INTENSITIES = ("none", "low", "medium", "high")
SEEDS = tuple(range(101, 111))

@dataclass(frozen=True)
class Scenario:
    topology: str = "mesh"
    mobility: str = "random_waypoint"
    traffic: str = "telemetry"
    crypto: str = "hybrid"
    threat: str = "dos"
    intensity: str = "medium"
    seed: int = 101
    swarm_size: int = 10
    routing: str = "aodv"

    def __post_init__(self):
        for attr, choices in (("topology", TOPOLOGIES), ("mobility", MOBILITY),
                              ("traffic", TRAFFIC), ("crypto", CRYPTO),
                              ("threat", THREATS), ("intensity", INTENSITIES)):
            if getattr(self, attr) not in choices:
                raise ValueError(f"Invalid {attr}: {getattr(self, attr)!r}")
        if (self.threat == "none") != (self.intensity == "none"):
            raise ValueError("Threat 'none' requires intensity 'none' and vice versa")
        if self.swarm_size < 2:
            raise ValueError("swarm_size must be >=2")
        if self.routing not in ("aodv", "olsr", "dsdv"):
            raise ValueError("Invalid routing protocol")

    @property
    def scenario_id(self):
        canonical = json.dumps(asdict(self), sort_keys=True)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]


def load_config(path: str | Path):
    with open(path, encoding="utf8") as f:
        cfg = yaml.safe_load(f)
    if cfg["snapshot_seconds"] <= 0 or cfg["simulation_seconds"] <= 0:
        raise ValueError("Time parameters must be positive")
    if cfg["observation_seconds"] + cfg["outcome_horizon_seconds"] > cfg["simulation_seconds"]:
        raise ValueError("Observation + horizon exceeds simulation time")
    if cfg["warmup_seconds"] >= cfg["observation_seconds"]:
        raise ValueError("Warm-up must end before observation")
    return cfg


def designs(seeds=SEEDS, swarm_sizes=(10,), routing="aodv"):
    """22 threat/intensity states; 3^4 * 22 = 1782 configurations, 10 seeds = 17820 per size."""
    conditions = [("none", "none")] + [(t, i) for t in THREATS if t != "none" for i in INTENSITIES if i != "none"]
    for topology, mobility, traffic, crypto, (threat, intensity), seed, size in product(
        TOPOLOGIES, MOBILITY, TRAFFIC, CRYPTO, conditions, seeds, swarm_sizes
    ):
        yield Scenario(topology, mobility, traffic, crypto, threat, intensity, int(seed), int(size), routing)
