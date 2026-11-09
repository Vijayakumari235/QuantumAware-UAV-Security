"""CLI for complete pipeline and controlled factorial experiments."""
from __future__ import annotations
import argparse,json,sys,time
from dataclasses import asdict
from pathlib import Path
import pandas as pd
from .config import Scenario,load_config,designs
from .simulator import simulate
from .graph import analyze_trace
from .risk import assess
from .evaluation import summarize,flatten_report,plot_results
from .io import dump_json,read_json,export_csv,import_external_csv


def run_pipeline(scenario,cfg,output=None,source_trace=None,keep_traces=False):
    trace=source_trace if source_trace is not None else simulate(scenario,cfg)
    graph=analyze_trace(trace)
    report=assess(trace,graph,cfg)
    if output is not None:
        base=Path(output);base.mkdir(parents=True,exist_ok=True)
        if keep_traces:
            dump_json(trace,base/f'{scenario.scenario_id}_trace.json')
            dump_json(graph,base/f'{scenario.scenario_id}_graph.json')
        dump_json(report,base/f'{scenario.scenario_id}_report.json')
    return report


def main(argv=None):
    p=argparse.ArgumentParser(description='Quantum-aware UAV security research pipeline (analytical backend)')
    sub=p.add_subparsers(dest='command',required=True)
    for name in ('run','batch','import','evaluate'):
        sp=sub.add_parser(name)
        sp.add_argument('--config',default='configs/default.yaml')
        sp.add_argument('--output',default='results/demo')
        if name=='run':
            for arg in ('topology','mobility','traffic','crypto','threat','intensity','routing'):
                sp.add_argument('--'+arg.replace('_','-'))
            sp.add_argument('--swarm-size',type=int,default=10)
            sp.add_argument('--seed',type=int,default=101)
            sp.add_argument('--keep-traces',action='store_true')
        elif name=='batch':
            sp.add_argument('--limit',type=int,default=24,help='Limit number of runs (0=ALL); full factorial is expensive')
            sp.add_argument('--seeds',nargs='+',type=int,default=[101,102])
            sp.add_argument('--swarm-sizes',nargs='+',type=int,default=[10])
            sp.add_argument('--routing',default='aodv')
            sp.add_argument('--plots',action='store_true')
            sp.add_argument('--keep-traces',action='store_true')
        elif name=='import':
            sp.add_argument('--csv',required=True)
            sp.add_argument('--scenario',required=True,help='Scenario JSON file')
        else:
            sp.add_argument('--reports',default=None,help='Directory containing *_report.json files')
            sp.add_argument('--plots',action='store_true')
    args=p.parse_args(argv);cfg=load_config(args.config)
    out=Path(args.output);out.mkdir(parents=True,exist_ok=True)
    start=time.perf_counter()
    if args.command=='run':
        kwargs={k:getattr(args,k) for k in ('topology','mobility','traffic','crypto','threat','intensity','routing') if getattr(args,k) is not None}
        scenario=Scenario(**kwargs,swarm_size=args.swarm_size,seed=args.seed)
        r=run_pipeline(scenario,cfg,out,keep_traces=args.keep_traces)
        print(json.dumps({'id':scenario.scenario_id,'backend':r['backend'],'crs':r['crs'],
                          'risk':r['risk_category'],'future_failure':r['future_mission_failure']},indent=2))
    elif args.command=='batch':
        reports=[]
        for i,scenario in enumerate(designs(seeds=args.seeds,swarm_sizes=args.swarm_sizes,routing=args.routing)):
            if args.limit and i>=args.limit:break
            reports.append(run_pipeline(scenario,cfg,out if args.keep_traces else None,keep_traces=args.keep_traces))
            if (i+1)%10==0:print(f'Completed {i+1} runs',flush=True)
        dump_json(reports,out/'all_reports.json')
        pd.DataFrame([flatten_report(r) for r in reports]).to_csv(out/'records.csv',index=False)
        stats=summarize(reports);dump_json(stats,out/'evaluation.json')
        if args.plots:plot_results(reports,out/'figures')
        print(json.dumps({'runs':len(reports),'positive_outcomes':stats['positive_outcomes'],
                          'evaluation':str(out/'evaluation.json'),'records':str(out/'records.csv')},indent=2))
    elif args.command=='import':
        sc=Scenario(**read_json(args.scenario))
        r=run_pipeline(sc,cfg,out,source_trace=import_external_csv(args.csv,sc,cfg),keep_traces=True)
        print(json.dumps({'id':r['scenario_id'],'crs':r['crs'],'backend':r['backend']},indent=2))
    else:
        source=Path(args.reports or args.output)
        all_file=source/'all_reports.json'
        reports=read_json(all_file) if all_file.exists() else [read_json(f) for f in sorted(source.glob('*_report.json'))]
        if not reports:raise SystemExit('No report files found')
        result=summarize(reports)
        dump_json(result,out/'evaluation.json')
        if args.plots:plot_results(reports,out/'figures')
        print(json.dumps({'runs':len(reports),'evaluation':str(out/'evaluation.json')},indent=2))
    print(f'Runtime seconds: {time.perf_counter()-start:.2f}',file=sys.stderr)

if __name__=='__main__':main()
