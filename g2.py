import json, os, pathlib, signal
from run_campaign import ad_load_security_and_utility, load_agentdojo
from agentdojo_integration import run_one_case
from arms import make_arm
import agentdojo

OUT = pathlib.Path("out_g2.jsonl")
done = set()
if OUT.exists():
    for l in OUT.read_text().splitlines():
        try: e=json.loads(l); done.add((e["case_id"],e["arm"],e["rep"]))
        except: pass

ad = load_agentdojo()
cases = [c for c in ad_load_security_and_utility(agentdojo,"workspace",limit=10) if c["kind"]=="security"][:10]
n=0
for c in cases:
    for arm in ("no-defense","monitor-only","monitor+gate"):
        filt = None if arm=="no-defense" else make_arm(arm,None,"gemini-2.5-flash",0.7,1)._filter
        for rep in (1,2):
            if (c["id"],arm,rep) in done or n>=70: continue
            signal.alarm(180)
            try:
                r = run_one_case(c,"frontier",filt,0.7,rep)
                rec=dict(case_id=c["id"],arm=arm,model="gemini-2.5-flash",rep=rep,
                         target_hit=r["target_hit"],n_filtered=r.get("n_filtered"))
            except Exception as ex:
                rec=dict(case_id=c["id"],arm=arm,rep=rep,voided=True,fault=str(ex)[:120])
            finally: signal.alarm(0)
            with open(OUT,"a") as f: f.write(json.dumps(rec,default=str)+"\n")
            n+=1; print(f"{arm:14s} {c['id'].split(':')[2]}:{c['id'].split(':')[3]} r{rep} hit={rec.get('target_hit')} filtered={rec.get('n_filtered')} ({n}/60)",flush=True)
print("DONE G2")
