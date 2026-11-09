"""End-to-end analytical smoke benchmark covering all eight threat families."""
from pathlib import Path
import sys
sys.path.insert(0,str(Path(__file__).resolve().parent/'src'))
from quantumuav.config import Scenario,THREATS,load_config
from quantumuav.cli import run_pipeline
from quantumuav.evaluation import summarize,plot_results,flatten_report
from quantumuav.io import dump_json
import pandas as pd

cfg=load_config(Path(__file__).resolve().parent/'configs/default.yaml')
out=Path(__file__).resolve().parent/'results/smoke'
out.mkdir(parents=True,exist_ok=True)
reports=[]
for seed in [101,102]:
    for crypto in ['classical','pqc','hybrid']:
        for threat in THREATS:
            intensity='none' if threat=='none' else 'high'
            scenario=Scenario(crypto=crypto,threat=threat,intensity=intensity,seed=seed)
            reports.append(run_pipeline(scenario,cfg))
            print(f'Completed {len(reports)}: {scenario.crypto} {scenario.threat} seed={seed}',flush=True)
dump_json(reports,out/'all_reports.json')
pd.DataFrame([flatten_report(r) for r in reports]).to_csv(out/'records.csv',index=False)
dump_json(summarize(reports),out/'evaluation.json')
plot_results(reports,out/'figures')
print('Completed analytical research smoke run:',len(reports),'reports in',out)
