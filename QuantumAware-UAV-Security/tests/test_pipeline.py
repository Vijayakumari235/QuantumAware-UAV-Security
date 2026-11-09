import math
import pytest
import networkx as nx
from quantumuav.config import Scenario,designs,load_config
from quantumuav.simulator import simulate
from quantumuav.graph import _minimum_cuts,graph_vulnerability,analyze_trace
from quantumuav.risk import score,risk_class,assess,outcome_label,extract_features,leave_one_out
from quantumuav.evaluation import summarize,holm_adjust

@pytest.fixture(scope='module')
def cfg():
    return load_config('configs/default.yaml')

@pytest.fixture(scope='module')
def result(cfg):
    sc=Scenario()
    return simulate(sc,cfg)

def test_doe():
    assert len(list(designs(seeds=[101])))==1782
    assert len(list(designs(seeds=[101,102])))==3564
    assert len(list(designs(seeds=[101],swarm_sizes=[10,50])))==3564

def test_scenario_validation():
    with pytest.raises(ValueError):Scenario(threat='none',intensity='low')
    with pytest.raises(ValueError):Scenario(routing='bad')

def test_deterministic(cfg):
    sc=Scenario()
    assert simulate(sc,cfg)==simulate(sc,cfg)

def test_simulation_snapshots(result):
    assert len(result['snapshots'])==31
    assert result['backend']=='analytical'
    for s in result['snapshots']:
        assert 0<=s['pdr']<=1
        assert s['connected_fraction']<=1
        assert s['throughput_bps']>=0
        assert len(s['positions'])==11

def test_minimum_cut():
    g=nx.path_graph(4)
    nodes,edges=_minimum_cuts(g,0,3)
    assert len(nodes)==1
    assert len(edges)==1
    nodes2,edges2=_minimum_cuts(g,0,1)
    assert nodes2==set() and len(edges2)==1

def test_graph(result):
    x=analyze_trace(result)
    assert len(x['snapshots'])==31
    assert all(0<=s['graph_vulnerability']<=1 for s in x['snapshots'])

def test_score():
    assert score([0,0,0,0,0])==0
    assert score([1,1,1,1,1])==1
    assert risk_class(1/3)=='Medium'
    assert risk_class(2/3)=='High'
    assert len(leave_one_out([0.1]*5))==5
    with pytest.raises(ValueError):score([2,0,0,0,0])

def test_risk_forward(cfg,result):
    graph=analyze_trace(result)
    report=assess(result,graph,cfg)
    assert 0<=report['crs']<=1
    assert report['future_mission_failure'] in (0,1)
    altered=simulate(Scenario(),cfg)
    for s in altered['snapshots']:
        if s['time_s']>cfg['observation_seconds']:
            s['pdr']=0
            s['throughput_bps']=0
            s['latency_ms']=1000
    assert extract_features(altered,graph,cfg)==extract_features(result,graph,cfg)
    assert outcome_label(altered,cfg)[0]==1

def test_statistics(cfg):
    reports=[]
    for i in range(4):
        for threat,intensity in [('none','none'),('dos','high')]:
            t=simulate(Scenario(threat=threat,intensity=intensity,seed=101+i),cfg)
            reports.append(assess(t,analyze_trace(t),cfg))
    stats=summarize(reports,n_boot=35)
    assert stats['n_runs']==8
    assert len(stats['comparators'])==5
    assert len(stats['ablations'])==5
    assert len(stats['paired_comparisons'])==4
    assert holm_adjust([.01,.04,.03])==pytest.approx([.03,.06,.06])
