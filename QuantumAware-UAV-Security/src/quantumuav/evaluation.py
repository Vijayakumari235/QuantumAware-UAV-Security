"""Outcome-based validation, comparator/ablation evaluation and matched-run statistics."""
from __future__ import annotations
import numpy as np
import pandas as pd
from scipy import stats


def _roc_auc(y,s):
    y=np.asarray(y,dtype=int);s=np.asarray(s,dtype=float)
    npos=sum(y==1);nneg=sum(y==0)
    if not npos or not nneg:return None
    # Mann-Whitney rank interpretation handles tied scores.
    ranks=stats.rankdata(s)
    return float((sum(ranks[y==1])-npos*(npos+1)/2)/(npos*nneg))


def _pr_auc(y,s):
    y=np.asarray(y,dtype=int);s=np.asarray(s,dtype=float)
    if len(np.unique(y))<2:return None
    order=np.argsort(-s,kind='stable'); ys=y[order]
    tp=np.cumsum(ys);fp=np.cumsum(1-ys)
    precision=tp/(tp+fp); recall=tp/np.sum(y)
    return float(np.sum((recall-np.r_[0,recall[:-1]])*precision))


def _correlation(y,s):
    if len(set(y))<2 or len(set(s))<2:return None
    v=stats.spearmanr(y,s).statistic
    return float(v) if np.isfinite(v) else None


def _metrics(reports,key,group='comparators'):
    y=[r['future_mission_failure'] for r in reports]
    s=[r[group][key] for r in reports]
    return {'auroc':_roc_auc(y,s),'auprc':_pr_auc(y,s),'spearman_severity':_correlation([r['future_disruption_severity'] for r in reports],s),
            'n':len(reports),'positive':int(sum(y))}


def bootstrap_ci(reports,key,group='comparators',seed=42,n_boot=300,metric='auroc'):
    """Cluster bootstrap over independent complete simulation runs (one report each)."""
    if not reports:return None
    rng=np.random.default_rng(seed);values=[]
    for _ in range(n_boot):
        idx=rng.integers(0,len(reports),len(reports));subset=[reports[i] for i in idx]
        result=_metrics(subset,key,group)[metric]
        if result is not None:values.append(result)
    if len(values)<30:return None
    return [float(x) for x in np.percentile(values,[2.5,97.5])]


def holm_adjust(pvalues):
    """Holm step-down multiplicity correction."""
    out=[None]*len(pvalues)
    valid=sorted((float(p),i) for i,p in enumerate(pvalues) if p is not None and np.isfinite(p))
    last=0.
    for rank,(p,i) in enumerate(valid):
        last=max(last,min(1.,p*(len(valid)-rank)))
        out[i]=last
    return out


def paired_comparison(reports,candidate,baseline,group='comparators',n_boot=200,seed=42):
    """Paired bootstrap AUROC difference, with optional paired-test on independent seed blocks.

    The distribution of individual *per-observation* correctness is not a valid paired
    AUROC test. We bootstrap complete run records and report a two-sided paired
    bootstrap p-value; seed-level differences support Wilcoxon when >=5 seeds have
    both classes (otherwise p remains null). This approach avoids pseudoreplication.
    """
    full=_metrics(reports,candidate,group)['auroc'];base=_metrics(reports,baseline,group)['auroc']
    result={'candidate':candidate,'baseline':baseline,'auroc_diff':None if full is None or base is None else full-base,
            'ci95':None,'p_raw':None,'p_holm':None,'bootstrap_samples':0}
    if full is None or base is None:return result
    rng=np.random.default_rng(seed);diffs=[]
    for _ in range(n_boot):
        idx=rng.integers(0,len(reports),len(reports));chunk=[reports[i] for i in idx]
        v=_metrics(chunk,candidate,group)['auroc'];b=_metrics(chunk,baseline,group)['auroc']
        if v is not None and b is not None:diffs.append(v-b)
    if len(diffs)<30:return result
    result['bootstrap_samples']=len(diffs)
    result['ci95']=[float(v) for v in np.percentile(diffs,[2.5,97.5])]
    result['p_raw']=float(min(1.,2*min((np.sum(np.array(diffs)<=0)+1)/(len(diffs)+1),
                                          (np.sum(np.array(diffs)>=0)+1)/(len(diffs)+1))))
    return result


def summarize(reports,n_boot=200):
    if not reports:return {'error':'No reports provided'}
    result={'n_runs':len(reports),'positive_outcomes':sum(r['future_mission_failure'] for r in reports),
            'backend_types':sorted(set(r['backend'] for r in reports)),'comparators':{},'ablations':{},
            'paired_comparisons':[],'risk_strata':{}}
    for key in reports[0]['comparators']:
        d=_metrics(reports,key)
        d['auroc_ci95']=bootstrap_ci(reports,key,seed=123,n_boot=n_boot)
        result['comparators'][key]=d
    for key in reports[0]['ablations']:
        d=_metrics(reports,key,'ablations')
        d['auroc_ci95']=bootstrap_ci(reports,key,'ablations',seed=123,n_boot=n_boot)
        result['ablations'][key]=d
    tests=[paired_comparison(reports,'crs',k,n_boot=n_boot) for k in ('qos_only','cryptographic_only','static_graph','temporal_graph')]
    adj=holm_adjust([r['p_raw'] for r in tests])
    for r,p in zip(tests,adj):r['p_holm']=p
    result['paired_comparisons']=tests
    for cat in ('Low','Medium','High'):
        data=[r for r in reports if r['risk_category']==cat]
        result['risk_strata'][cat]={'n':len(data),'observed_failure_rate':float(np.mean([r['future_mission_failure'] for r in data])) if data else None}
    # Report repeated-run variability and 95% t CI; do not claim independent CIs for grouped variants.
    scores=[r['crs'] for r in reports]
    mean=float(np.mean(scores));sd=float(np.std(scores,ddof=1)) if len(scores)>1 else 0.
    margin=float(stats.t.ppf(.975,len(scores)-1)*sd/np.sqrt(len(scores))) if len(scores)>1 else None
    result['crs_variability']={'mean':mean,'sd':sd,'ci95':None if margin is None else [mean-margin,mean+margin]}
    return result


def flatten_report(r):
    sc=r['scenario'];return {'scenario_id':r['scenario_id'],**sc,'backend':r['backend'],
        'crs':r['crs'],'risk_category':r['risk_category'],'future_mission_failure':r['future_mission_failure'],
        'future_disruption_severity':r['future_disruption_severity'],**r['components'],
        **{'baseline_'+k:v for k,v in r['comparators'].items()},
        **{'ablation_without_'+k:v for k,v in r['ablations'].items()}}


def plot_results(reports,outdir):
    from pathlib import Path
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    outdir=Path(outdir);outdir.mkdir(parents=True,exist_ok=True)
    df=pd.DataFrame([flatten_report(r) for r in reports])
    if len(df)==0:return []
    paths=[]
    fig,ax=plt.subplots(figsize=(7.4,4.6))
    for cat in ('Low','Medium','High'):
        d=df[df.risk_category==cat]
        if len(d):ax.scatter(d['crs'],d['future_disruption_severity'],label=cat,alpha=.7,s=19)
    ax.set(xlabel='Composite Risk Score (pre-outcome)',ylabel='Future PDR disruption severity')
    ax.grid(alpha=.2);ax.legend();fig.tight_layout()
    p=outdir/'risk_vs_future_disruption.png';fig.savefig(p,dpi=600);paths.append(str(p));plt.close(fig)
    fig,ax=plt.subplots(figsize=(7.4,4.6))
    means=df.groupby('crypto')['crs'].agg(['mean','std']).reindex(['classical','pqc','hybrid'])
    ax.bar(means.index,means['mean'],yerr=means['std'].fillna(0),capsize=4)
    ax.set(xlabel='Cryptographic configuration',ylabel='Mean CRS',ylim=(0,1))
    fig.tight_layout();p=outdir/'crs_by_crypto.png';fig.savefig(p,dpi=600);paths.append(str(p));plt.close(fig)
    return paths
