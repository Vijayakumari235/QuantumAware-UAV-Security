"""Trace schemas, external trace import and portable JSON serialization."""
from pathlib import Path
import json
import pandas as pd


def dump_json(obj,path):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True)
    with open(path,'w',encoding='utf8') as f:json.dump(obj,f,indent=2,allow_nan=False)

def read_json(path):
    with open(path,encoding='utf8') as f:return json.load(f)

def export_csv(trace,path):
    rows=[]
    for s in trace['snapshots']:
        rows.append({k:v for k,v in s.items() if isinstance(v,(float,int,bool,str))})
    Path(path).parent.mkdir(parents=True,exist_ok=True)
    pd.DataFrame(rows).to_csv(path,index=False)

def import_external_csv(path,scenario,config):
    """Import *already processed* NS-3/SITL time-snapshot CSVs.

    Required columns: time_s, pdr, latency_ms, throughput_bps, connected_fraction,
    monitor_score, monitor_alarm. A separate edges JSON is required per time index in
    column `edges_json`, containing `physical_edges`, `routing_edges`, `positions`,
    `mission_paths`, `per_node`, `compromised_nodes`. No fake graph structure is inferred.
    """
    import numpy as np
    df=pd.read_csv(path)
    required={'time_s','pdr','latency_ms','throughput_bps','connected_fraction','monitor_score','monitor_alarm','edges_json'}
    missing=required-set(df.columns)
    if missing:raise ValueError('Missing required CSV columns: '+', '.join(sorted(missing)))
    snapshots=[]
    for _,row in df.sort_values('time_s').iterrows():
        geometry=json.loads(row['edges_json'])
        required_geometry={'physical_edges','routing_edges','positions','mission_paths','per_node','compromised_nodes'}
        if required_geometry-set(geometry):raise ValueError('Incomplete edges_json')
        s={**geometry,'time_s':float(row['time_s']),
           'pdr':float(row['pdr']),'latency_ms':float(row['latency_ms']),
           'throughput_bps':float(row['throughput_bps']),
           'connected_fraction':float(row['connected_fraction']),
           'monitor_score':float(row['monitor_score']),
           'monitor_alarm':bool(row['monitor_alarm']),
           'crypto_mode':scenario.crypto,'backend':'external',
           'crypto_profile':config['crypto_profiles'][scenario.crypto]}
        if not 0 <= s['pdr'] <= 1:raise ValueError('PDR outside [0,1]')
        snapshots.append(s)
    if not snapshots:raise ValueError('No snapshots')
    baseline=[s for s in snapshots if s['time_s']<=config['warmup_seconds']]
    if not baseline:raise ValueError('External trace needs warm-up data for baselines')
    return {'scenario':scenario.__dict__,'scenario_id':scenario.scenario_id,'backend':'external',
            'snapshots':snapshots,'metadata':{'nominal_baseline_latency_ms':float(np.mean([s['latency_ms'] for s in baseline])),
                                            'nominal_baseline_pdr':float(np.mean([s['pdr'] for s in baseline]))}}
