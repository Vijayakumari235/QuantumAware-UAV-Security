"""Self-contained analytical/event-level UAV network simulator.

IMPORTANT: This is a synthetic/network-analytical simulator, not NS-3 or ArduPilot SITL.
Network link availability, routing, packet QoS and navigation perturbations are approximations.
It supplies a fully executable backend to test the proposed graph/risk methodology and
must not be reported as real NS-3/SITL experimental measurements.
"""
from __future__ import annotations
import math
import numpy as np
import networkx as nx
from .config import Scenario

TRAFFIC_SPECS = {"c2": (128, 5), "telemetry": (256, 10), "payload": (1024, 20)}
INTENSITY = {"none": 0., "low": .25, "medium": .55, "high": .9}
CLASSICAL_COMPROMISE = {"key_compromise", "auth_forgery", "combined_compromise"}


def _clip(x, lo=0., hi=1.):
    return float(np.clip(x, lo, hi))


def _initial_positions(rng, n, topology, area):
    gcs = np.array([[area / 2, area / 2, 70.]])
    if topology == "star":
        angles = np.linspace(0, 2*np.pi, n, endpoint=False)
        radius = min(190, area*.20)
        xyz = np.column_stack([area/2 + radius*np.cos(angles), area/2 + radius*np.sin(angles), rng.uniform(65,115,n)])
    elif topology == "clustered":
        centers = np.array([[.3*area,.3*area],[.7*area,.7*area],[.5*area,.5*area]])
        c = centers[np.arange(n)%3]
        xyz = np.column_stack([c + rng.normal(0,90,(n,2)),rng.uniform(65,115,n)])
    else:
        xyz = np.column_stack([rng.uniform(.2*area,.8*area,(n,2)),rng.uniform(65,115,n)])
    return np.vstack([gcs,xyz])


def _mobility_step(xyz, velocity, rng, scenario, dt, cfg):
    area = cfg['area_m']
    max_step = cfg['speed_max_mps']*dt
    if scenario.mobility == "random_waypoint":
        change = rng.random(len(xyz)-1) < .28
        velocity[1:][change] = rng.normal(0,1,(sum(change),3))
    elif scenario.mobility == "gauss_markov":
        velocity[1:] = .85*velocity[1:] + .15*rng.normal(0,1,velocity[1:].shape)
    else:  # leader-follower: shared leader direction plus formation-restoring control
        velocity[1] = .85*velocity[1] + .15*rng.normal(0,1,3)
        velocity[2:] = .78*velocity[1] + .22*velocity[2:]
    norms = np.linalg.norm(velocity[1:],axis=1,keepdims=True)
    speed = rng.uniform(cfg['speed_min_mps'],cfg['speed_max_mps'],(len(xyz)-1,1))
    shift = velocity[1:]/np.maximum(norms,1e-12)*np.minimum(speed*dt,max_step)
    xyz[1:] += shift
    xyz[1:,:2] = np.clip(xyz[1:,:2],0,area)
    xyz[1:,2] = np.clip(xyz[1:,2],cfg['altitude_min_m'],cfg['altitude_max_m'])
    velocity[1:] = np.where((xyz[1:,:] <= 0) | (xyz[1:,:] >= area),-velocity[1:,:],velocity[1:,:])
    return xyz, velocity


def _physical_graph(xyz, rng, cfg, compromised_nodes=()):
    g = nx.Graph()
    g.add_nodes_from(range(len(xyz)))
    max_dist=cfg['radio_range_m']
    for i in range(len(xyz)):
        for j in range(i+1,len(xyz)):
            d=float(np.linalg.norm(xyz[i]-xyz[j]))
            if d > max_dist:
                continue
            # Nakagami-like fading by gamma-distributed power; tractable approximation.
            fading=rng.gamma(shape=2.0,scale=.5)
            quality=max(0., (1-d/max_dist))*fading
            if quality < .055: continue
            g.add_edge(i,j,distance_m=d,link_quality=_clip(quality),loss=_clip(cfg['baseline_packet_loss']+.025*(1-quality)))
    return g


def simulate(scenario: Scenario, cfg: dict):
    """Return serializable graph snapshots and network/attack traces for one seed."""
    rng = np.random.default_rng(scenario.seed)
    n = scenario.swarm_size
    xyz = _initial_positions(rng,n,scenario.topology,cfg['area_m'])
    vel = rng.normal(0,1,(n+1,3));vel[0]=0
    times = np.arange(0,cfg['simulation_seconds']+1e-8,cfg['snapshot_seconds'])
    severity=INTENSITY[scenario.intensity]
    attack_start=max(cfg['warmup_seconds'],int(cfg['simulation_seconds']*.20))
    attack_end=int(cfg['simulation_seconds']*.90)
    compromise_at=cfg['simulation_seconds']*({'low':.75,'medium':.50,'high':.25}.get(scenario.intensity,1.1))
    compromised_targets=set(range(1, max(2,int(math.ceil(n*severity*.25))+1)))
    output=[]
    crypto=cfg['crypto_profiles'][scenario.crypto]
    crypto_load = crypto['expansion'] * .045
    previous_normal_pdr=1.
    previous_normal_latency=cfg['base_latency_ms']
    cumulative_attempts=0
    cumulative_success=0
    for k,t in enumerate(times):
        if k: xyz,vel=_mobility_step(xyz,vel,rng,scenario,cfg['snapshot_seconds'],cfg)
        active = scenario.threat != 'none' and attack_start <= t <= attack_end
        hypothetic = scenario.threat in CLASSICAL_COMPROMISE and t >= compromise_at and scenario.crypto == 'classical'
        compromise = sorted(compromised_targets) if hypothetic else []
        positions_perceived=xyz.copy()
        gps_error=0.
        if active and scenario.threat=='gps_spoofing':
            gps_error=severity*110.
            positions_perceived[list(compromised_targets),:2]+=gps_error
        g=_physical_graph(xyz,rng,cfg)
        # Ground-truth physical topology and perceived topology are kept separately.
        observed= _physical_graph(positions_perceived, np.random.default_rng(scenario.seed+100000+k), cfg) if gps_error else g.copy()
        routing=g.copy()
        if hypothetic and scenario.threat in ('key_compromise','combined_compromise'):
            for u,v in list(routing.edges()):
                if (u in compromised_targets or v in compromised_targets) and rng.random()<severity*.55:
                    routing.remove_edge(u,v)
        if active and scenario.threat == 'sybil':
            # Synthetic fake-neighbor events: not accepted as genuine physical UAVs.
            # Routing instability is modelled by invalidating some discovered routes.
            for u,v in list(routing.edges()):
                if u in compromised_targets and rng.random()<severity*.4:
                    routing.remove_edge(u,v)
        if active and scenario.threat == 'gps_spoofing':
            # Mislocated navigation causes routing decisions based on perceived topology.
            routing = nx.Graph()
            routing.add_nodes_from(g.nodes(data=True))
            for u,v,attr in observed.edges(data=True):
                if g.has_edge(u,v): routing.add_edge(u,v,**g.edges[u,v])
        byte_size,pps=TRAFFIC_SPECS[scenario.traffic]
        sent=n*pps*cfg['snapshot_seconds']
        good=0;delays=[];connected=0;per_node=[];routed_paths=[]
        flood = severity*4 if active and scenario.threat=='dos' else 0.
        replay = severity*.5 if active and scenario.threat=='replay' else 0.
        forced_auth = severity*.2 if hypothetic and scenario.threat in ('auth_forgery','combined_compromise') else 0.
        for i in range(1,n+1):
            try:
                path=nx.shortest_path(routing,i,0)
                hops=len(path)-1
                connected+=1
                avail=math.prod(1.-g.edges[u,v]['loss'] for u,v in zip(path[:-1],path[1:]))
                congestion=(n*pps*byte_size*8/cfg['bitrate_bps']) * (.55+flood+replay+crypto_load)
                loss=_clip((1-avail)+max(0,congestion-.6)*.35+replay*.12+forced_auth)
                if active and scenario.threat=='replay': loss=_clip(loss+.08*severity)
                if active and scenario.threat=='dos': loss=_clip(loss+.27*severity)
                pdr=1-loss
                latency=cfg['base_latency_ms']*hops*(1+min(7.,congestion)) + 1.5*crypto['handshake_ms']/(1+k)
                if hypothetic: latency += 10*severity
                if active and scenario.threat=='gps_spoofing': latency+=severity*18
                delays.append(latency)
                routed_paths.append(path)
            except (nx.NetworkXNoPath,nx.NodeNotFound):
                pdr=0.;latency=float('nan')
            per_node.append({'node':i,'pdr':float(pdr),'latency_ms':None if not np.isfinite(latency) else float(latency),
                             'compromised':int(i in compromise),'gps_error_m':gps_error if i in compromised_targets else 0.})
            good += pps*cfg['snapshot_seconds']*pdr
        pdr=float(good/sent)
        latency=float(np.mean(delays)) if delays else cfg['normalization']['impact_latency_ms']*2
        throughput=good*byte_size*8/cfg['snapshot_seconds']
        connected_fraction=connected/n
        if scenario.threat != 'none' and active:
            cumulative_attempts += 1
            # attack effects are explicitly simulated, not inferred from the future mission label
            effective = (pdr < previous_normal_pdr-.06 or hypothetic or (gps_error>0 and severity>=.5))
            cumulative_success += int(effective)
        monitor_score=_clip((1-pdr)*1.8+max(0.,latency-40)/200+(.2*len(compromise)/max(n,1)))
        monitor_alarm = bool(monitor_score>.28)
        monitor_truth=bool(active or hypothetic)
        snapshot = {
            'time_s':float(t),'positions':xyz.tolist(),'perceived_positions':positions_perceived.tolist(),
            'physical_edges':[[int(u),int(v),dict(a)] for u,v,a in g.edges(data=True)],
            'routing_edges':[[int(u),int(v)] for u,v in routing.edges()],
            'crypto_mode':scenario.crypto,'crypto_profile':dict(crypto),'compromised_nodes':compromise,
            'attack_active':bool(active),'hypothetical_compromise':bool(hypothetic),
            'attack_attempts_to_date':cumulative_attempts,'attack_successes_to_date':cumulative_success,
            'mission_paths':routed_paths,'per_node':per_node,'packets_sent':float(sent),'packets_received':float(good),
            'pdr':pdr,'latency_ms':latency,'throughput_bps':float(throughput),
            'connected_fraction':connected_fraction,'monitor_alarm':monitor_alarm,'monitor_truth':monitor_truth,
            'monitor_score':monitor_score,'gps_error_m':gps_error,
            'routing_protocol':scenario.routing,'backend':'analytical'
        }
        output.append(snapshot)
        if t < attack_start:
            previous_normal_pdr=pdr
            previous_normal_latency=latency
    return {'scenario':scenario.__dict__,'scenario_id':scenario.scenario_id,'backend':'analytical',
            'snapshots':output,'metadata':{'attack_start_s':attack_start,'attack_end_s':attack_end,
                                         'compromise_time_s':compromise_at,'nominal_baseline_latency_ms':previous_normal_latency,
                                         'nominal_baseline_pdr':previous_normal_pdr}}
