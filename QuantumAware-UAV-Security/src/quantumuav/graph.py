"""Graph vulnerability analysis (Algorithm 2), directed route awareness and deterministic min-cuts."""
import networkx as nx
import numpy as np


def clamp(x): return float(np.clip(x,0,1))


def _norm_values(d):
    vmax=max(d.values(),default=0.)
    return {k:clamp(v / vmax) if vmax else 0. for k,v in d.items()}


def _minimum_cuts(graph, u, v):
    """Deterministic unit-capacity edge and internally node-disjoint pair cuts.
    NetworkX minimum_cut is deterministic for insertion-sorted edge order. Node split avoids
    treating endpoints as removable internal nodes. Direct adjacent node-pair cuts can be
    undefined for internal node separators; return an empty node cut in that case.
    """
    g=nx.Graph();g.add_nodes_from(sorted(graph.nodes()))
    g.add_edges_from(sorted(tuple(sorted((a,b))) for a,b in graph.edges()))
    if not nx.has_path(g,u,v):return set(),set()
    directed=nx.DiGraph()
    directed.add_nodes_from(g.nodes())
    for a,b in g.edges():
        directed.add_edge(a,b,capacity=1);directed.add_edge(b,a,capacity=1)
    _,(s,t)=nx.minimum_cut(directed,u,v,capacity='capacity',flow_func=nx.algorithms.flow.edmonds_karp)
    edges={tuple(sorted((a,b))) for a,b in directed.edges() if a in s and b in t}
    # adjacent terminals do not admit a finite internal-node separator
    if g.has_edge(u,v):return set(),edges
    split=nx.DiGraph()
    infinity=len(g)+1
    for x in g.nodes():split.add_edge((x,'in'),(x,'out'),capacity=infinity if x in (u,v) else 1)
    for a,b in g.edges():
        split.add_edge((a,'out'),(b,'in'),capacity=infinity)
        split.add_edge((b,'out'),(a,'in'),capacity=infinity)
    _,(s,t)=nx.minimum_cut(split,(u,'out'),(v,'in'),capacity='capacity',flow_func=nx.algorithms.flow.edmonds_karp)
    cut={x for x in g.nodes() if x not in (u,v) and (x,'in') in s and (x,'out') in t}
    return cut,edges


def _safe_eigenvector(g):
    if len(g)<2 or g.number_of_edges()==0:return {u:0. for u in g.nodes()}
    try:return _norm_values(nx.eigenvector_centrality(g,max_iter=1000,tol=1e-7))
    except (nx.PowerIterationFailedConvergence, nx.NetworkXException):return {u:0. for u in g.nodes()}


def graph_vulnerability(snapshot, baseline_pdr=1.0, baseline_latency_ms=6.0):
    """Compute per-node/per-edge vulnerability and routing structure for one snapshot.
    Routing graph is undirected for articulation/bridge and cut analysis in this analytical
    backend. Route paths are retained as explicit source-to-GCS mission pairs.
    """
    nodes=range(len(snapshot['positions']))
    g=nx.Graph();g.add_nodes_from(nodes);g.add_edges_from(sorted(tuple(e) for e in snapshot['routing_edges']))
    degree=nx.degree_centrality(g)
    between=nx.betweenness_centrality(g,normalized=True)
    close=nx.closeness_centrality(g, wf_improved=True)
    eigen=_safe_eigenvector(g)
    close=_norm_values(close)
    degree=_norm_values(degree)
    between=_norm_values(between)
    articulations=set(nx.articulation_points(g))
    bridges={tuple(sorted(e)) for e in nx.bridges(g)}
    pairs={(int(p[0]),int(p[-1])) for p in snapshot.get('mission_paths',[]) if len(p)>1}
    node_counts={i:0 for i in g.nodes()};edge_counts={tuple(sorted(e)):0 for e in g.edges()}
    active_pairs=0
    for u,v in sorted(pairs):
        if u==v or not nx.has_path(g,u,v):continue
        active_pairs+=1
        nodes_cut,edges_cut=_minimum_cuts(g,u,v)
        for i in nodes_cut:node_counts[i]+=1
        for e in edges_cut:edge_counts[e]+=1
    edge_between=_norm_values({tuple(sorted(e)):v for e,v in nx.edge_betweenness_centrality(g,normalized=True).items()})
    per_node={int(r['node']):r for r in snapshot.get('per_node',[])}
    node_v={}; edge_v={}
    global_drop=clamp((baseline_pdr-snapshot['pdr'])/max(baseline_pdr,1e-9))
    lat_drop=clamp((snapshot['latency_ms']-baseline_latency_ms)/max(100.,baseline_latency_ms))
    for i in g.nodes():
        cent=(degree[i]+between[i]+close[i]+eigen[i])/4
        r=per_node.get(i,{})
        pdr_drop=clamp((baseline_pdr-r.get('pdr',snapshot['pdr']))/max(baseline_pdr,1e-9))
        local_lat=r.get('latency_ms')
        local_lat=baseline_latency_ms if local_lat is None else local_lat
        local_d=clamp((local_lat-baseline_latency_ms)/max(100.,baseline_latency_ms))
        attack=(float(r.get('compromised',0))+pdr_drop+local_d)/3
        node_v[i]=clamp((cent+int(i in articulations)+node_counts[i]/max(1,active_pairs)+attack)/4)
    for u,v in g.edges():
        key=tuple(sorted((u,v)))
        compromised=int(u in snapshot.get('compromised_nodes',[]) or v in snapshot.get('compromised_nodes',[]))
        attack=(compromised+global_drop+lat_drop)/3
        edge_v[f'{key[0]}-{key[1]}']=clamp((edge_between.get(key,0.)+int(key in bridges)+edge_counts.get(key,0)/max(1,active_pairs)+attack)/4)
    # Active GCS-oriented relay nodes and links are both considered.
    values=list(node_v.values())+list(edge_v.values())
    return {
        'node_vulnerability':node_v,'edge_vulnerability':edge_v,
        'graph_vulnerability':float(np.mean(values)) if values else 0.,
        'articulation_points':sorted(articulations),'bridges':[list(e) for e in sorted(bridges)],
        'node_cut_participation':node_counts,
        'edge_cut_participation':{f'{a}-{b}':float(v)/max(active_pairs,1) for (a,b),v in edge_counts.items()},
        'active_mission_pairs':active_pairs,
        'centrality':{'degree':degree,'betweenness':between,'closeness':close,'eigenvector':eigen}
    }


def analyze_trace(trace):
    baseline_pdr=trace['metadata'].get('nominal_baseline_pdr',1.)
    baseline_latency=trace['metadata'].get('nominal_baseline_latency_ms',6.)
    reports=[graph_vulnerability(s,baseline_pdr,baseline_latency) for s in trace['snapshots']]
    node_history={};edge_history={}
    for r in reports:
        for u,v in r['node_vulnerability'].items():node_history.setdefault(str(u),[]).append(v)
        for e,v in r['edge_vulnerability'].items():edge_history.setdefault(e,[]).append(v)
    return {'snapshots':reports,
            'temporal_node_vulnerability':{k:float(np.mean(v)) for k,v in node_history.items()},
            'temporal_edge_vulnerability':{k:float(np.mean(v)) for k,v in edge_history.items()}}
