"""Composite risk score, comparison methods, outcome-safe observation strategy."""
import numpy as np

WEIGHTS = (0.2,)*5
COMPONENTS=('attack_likelihood','mission_impact','inverse_detectability','crypto_cost_security','graph_vulnerability')

def bounded(x):return float(np.clip(x,0.,1.))

def risk_class(x):
    if x<1/3:return 'Low'
    if x<2/3:return 'Medium'
    return 'High'

def score(values, weights=WEIGHTS):
    vals=np.asarray(values,dtype=float)
    w=np.asarray(weights,dtype=float)
    if vals.shape!=(5,) or w.shape!=(5,):raise ValueError('Expected five scores and five weights')
    if not np.all(np.isfinite(vals)) or not np.all((vals>=0)&(vals<=1)):
        raise ValueError('Risk component scores must be finite and in [0,1]')
    if np.any(w<0) or abs(w.sum()-1)>1e-10:raise ValueError('Nonnegative weights must sum to one')
    return bounded(np.dot(vals,w))

def leave_one_out(values):
    return {name:score(values,[0 if j==i else .25 for j in range(5)]) for i,name in enumerate(COMPONENTS)}

def extract_features(trace, graph_report, cfg, at_time=None):
    """Risk uses only snapshots at/before observation; labels only after observation.
    No mission outcome or ground-truth monitor labels enter the risk components.
    Attack likelihood is a preregistered deterministic exposure estimate from prior
    monitor scores and configured adversary intensity, NOT a learned attack probability.
    """
    at_time=at_time if at_time is not None else cfg['observation_seconds']
    paired=[(s,g) for s,g in zip(trace['snapshots'],graph_report['snapshots']) if cfg['warmup_seconds']<=s['time_s']<=at_time]
    if not paired:raise ValueError('No observation snapshots available')
    norm=cfg['normalization']
    crypto=cfg['crypto_profiles'][trace['scenario']['crypto']]
    overhead=np.mean([bounded(crypto['handshake_ms']/norm['latency_ms']),bounded(crypto['energy_mj']/norm['energy_mj']),bounded(crypto['expansion']/norm['message_expansion'])])
    pqc=bounded(.5*overhead+.5*(1-crypto['security_strength']))
    intensity={'none':0,'low':.25,'medium':.55,'high':.9}[trace['scenario']['intensity']]
    # Avoid direct use of future attack successes or independently defined mission-failure labels.
    a=[];imp=[];det=[];gv=[]
    for s,g in paired:
        a.append(bounded(.6*s['monitor_score']+.4*intensity))
        baseline_pdr=trace['metadata']['nominal_baseline_pdr']
        baseline_latency=trace['metadata']['nominal_baseline_latency_ms']
        loss=bounded((baseline_pdr-s['pdr'])/max(baseline_pdr,1e-9))
        delay=bounded((s['latency_ms']-baseline_latency)/norm['impact_latency_ms'])
        # nominal load is a fixed configuration-derived reference (no future observations).
        byte_size,pps={'c2':(128,5),'telemetry':(256,10),'payload':(1024,20)}[trace['scenario']['traffic']]
        nominal=trace['scenario']['swarm_size']*byte_size*pps*8
        throughput_degrade=bounded(1-s['throughput_bps']/max(nominal,1))
        imp.append(float(np.mean([loss,delay,throughput_degrade])))
        # Monitor sensitivity combines confidence and alarm history, independent of ground truth labels.
        # Detectability is zero if no alarm even when anomaly observed.
        detectability=bounded(s['monitor_score']*(1 if s['monitor_alarm'] else .45))
        det.append(1-detectability)
        gv.append(g['graph_vulnerability'])
    vals=[float(np.mean(x)) for x in (a,imp,det)] + [pqc,float(np.mean(gv))]
    return dict(zip(COMPONENTS,map(bounded,vals)))

def outcome_label(trace,cfg,at_time=None):
    """Held-forward binary mission communication violation, independent of CRS."""
    t=cfg['observation_seconds'] if at_time is None else at_time
    future=[s for s in trace['snapshots'] if t<s['time_s']<=t+cfg['outcome_horizon_seconds']]
    if not future: raise ValueError('No future snapshots; adjust horizon')
    limits=cfg['thresholds']
    fail=[s['pdr']<limits['min_pdr'] or s['latency_ms']>limits['max_latency_ms'] or
          s['throughput_bps']<limits['min_throughput_bps'] or
          s['connected_fraction']<limits['min_connected_fraction'] for s in future]
    severity=float(np.mean([max(0.,limits['min_pdr']-s['pdr'])/max(limits['min_pdr'],1e-9) for s in future]))
    return int(any(fail)),severity

def assess(trace,graph_report,cfg):
    x=extract_features(trace,graph_report,cfg)
    values=[x[k] for k in COMPONENTS]
    crs=score(values)
    lbl,sev=outcome_label(trace,cfg)
    obs=next((i for i,s in enumerate(trace['snapshots']) if s['time_s']>=cfg['observation_seconds']),len(trace['snapshots'])-1)
    graph_current=graph_report['snapshots'][obs]['graph_vulnerability']
    comparable={
        'qos_only':x['mission_impact'],
        'cryptographic_only':x['crypto_cost_security'],
        'static_graph':graph_current,
        'temporal_graph':x['graph_vulnerability'],
        'crs':crs,
    }
    return {'scenario_id':trace['scenario_id'],'scenario':trace['scenario'],
            'backend':trace.get('backend','external'),'observation_time_s':cfg['observation_seconds'],
            'outcome_horizon_seconds':cfg['outcome_horizon_seconds'],'components':x,
            'crs':crs,'risk_category':risk_class(crs),'future_mission_failure':lbl,
            'future_disruption_severity':sev,'comparators':comparable,'ablations':leave_one_out(values),
            'mean_node_vulnerability':float(np.mean(list(graph_report['temporal_node_vulnerability'].values()))) if graph_report['temporal_node_vulnerability'] else 0.}
