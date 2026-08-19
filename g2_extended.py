#!/usr/bin/env python3
"""
Extended live-model campaign — FINAL VALIDATED VERSION (v3, 2026-08-19).
Supersedes g2_extended.py / g2_extended_patched.py entirely.

Design: 40 DISTINCT security cases x 1 rep x 3 arms = 120 security episodes;
        24 DISTINCT utility cases x 1 rep x 2 arms = 48 utility episodes.
        Every episode is an independent case -- no repetition-correlation caveat.

Guarantees:
  G1  SIGALRM raises TimeoutError (was: default disposition = process kill).
  G2  Resume retries voided episodes (voided records are not 'done').
  G3  Utility floor: >= MIN_UTIL_EPS episodes/arm, hard assert.
  G4+ Comparability by CONSTRUCTION: the original out_g2.jsonl case_ids are
      loaded BY NAME and run FIRST; new cases fill the remainder in loader
      order. Hard error if any original case_id is no longer loadable
      (that would be genuine benchmark drift -- stop and report it).
  G6  Circuit breaker: abort after 5 consecutive voided episodes.
  SMOKE=1 env var: runs 2+2 cases with a relaxed floor. No file edits needed.

Requires: live gemini-2.5-flash access + AgentDojo 0.1.35.
    source ~/ndss_env.sh     # FRONTIER_BASE_URL / FRONTIER_API_KEY / FRONTIER_MODEL
Run:
    SMOKE=1 python3 g2_extended.py     # 10-episode smoke test
    python3 g2_extended.py             # full run (resumable)
"""
import json, os, pathlib, signal, sys
from run_campaign import ad_load_security_and_utility, load_agentdojo
from agentdojo_integration import run_one_case
from arms import make_arm
import agentdojo

# ---- deterministic config -------------------------------------------------
MODEL       = "gemini-2.5-flash"
TEMP        = 0.7                     # MUST match the original g2.py run
SUITE       = "workspace"
SEC_CASES   = 40          # 40 distinct cases x 1 rep = 40 sec eps/arm
UTIL_CASES  = 24          # 24 distinct cases x 1 rep = 24 util eps/arm (>=20)
REPS        = (1,)
SEC_ARMS    = ("no-defense", "monitor-only", "monitor+gate")
UTIL_ARMS   = ("no-defense", "monitor+gate")   # parity + the defended condition
OUT         = pathlib.Path("out_g2_extended.jsonl")
ORIG        = pathlib.Path("out_g2.jsonl")     # original campaign log
TIMEOUT_S   = 180
MIN_UTIL_EPS    = 20
MAX_CONSEC_VOIDS = 5
if os.environ.get("SMOKE") == "1":            # smoke-test override, no edits
    SEC_CASES, UTIL_CASES, MIN_UTIL_EPS = 2, 2, 2
# ---------------------------------------------------------------------------

def _timeout_handler(signum, frame):
    raise TimeoutError(f"episode exceeded {TIMEOUT_S}s")
signal.signal(signal.SIGALRM, _timeout_handler)

done = set()
if OUT.exists():
    for l in OUT.read_text().splitlines():
        try:
            e = json.loads(l)
            if not e.get("voided"):                     # G2: retry voided on resume
                done.add((e["case_id"], e["arm"], e["rep"]))
        except Exception:
            pass

ad = load_agentdojo()
all_cases = ad_load_security_and_utility(agentdojo, SUITE, limit=None)
sec_pool  = [c for c in all_cases if c["kind"] == "security"]
util_cases = [c for c in all_cases if c["kind"] == "utility"][:UTIL_CASES]

# ---- G4+: original case_ids first, by name; then fill in loader order -----
sec_by_id = {c["id"]: c for c in sec_pool}
if ORIG.exists():
    orig_ids, seen = [], set()
    for l in ORIG.read_text().splitlines():
        try: e = json.loads(l)
        except Exception: continue
        cid = e.get("case_id", "")
        if ":sec:" in cid and not e.get("voided") and cid not in seen:
            seen.add(cid); orig_ids.append(cid)
    unloadable = [i for i in orig_ids if i not in sec_by_id]
    assert not unloadable, (f"benchmark drift: {len(unloadable)} original case_ids no longer "
                            f"loadable: {unloadable[:3]}... — STOP and report this.")
    sec_cases = [sec_by_id[i] for i in orig_ids] + \
                [c for c in sec_pool if c["id"] not in seen]
    sec_cases = sec_cases[:SEC_CASES]
    print(f"comparability OK: {sum(1 for c in sec_cases if c['id'] in seen)}/{len(orig_ids)} "
          f"original cases locked in first", flush=True)
else:
    print("WARNING: out_g2.jsonl not found — comparability guard inactive", flush=True)
    sec_cases = sec_pool[:SEC_CASES]

assert len(sec_cases)  == SEC_CASES, f"need {SEC_CASES} security cases, got {len(sec_cases)}"
assert len(util_cases) * len(REPS) >= MIN_UTIL_EPS, (
    f"only {len(util_cases)} utility cases -> {len(util_cases)*len(REPS)} eps/arm (<{MIN_UTIL_EPS})")

total = len(sec_cases)*len(SEC_ARMS)*len(REPS) + len(util_cases)*len(UTIL_ARMS)*len(REPS)
n = 0
consec_voids = 0
print(f"target episodes: {total} "
      f"(sec {len(sec_cases)}x{len(SEC_ARMS)}x{len(REPS)} + util {len(util_cases)}x{len(UTIL_ARMS)}x{len(REPS)})",
      flush=True)

def run_block(cases, arms, kind_label):
    global n, consec_voids
    for c in cases:
        for arm in arms:
            filt = None if arm == "no-defense" else make_arm(arm, None, MODEL, TEMP, 1)._filter
            for rep in REPS:
                if (c["id"], arm, rep) in done:
                    n += 1; continue
                signal.alarm(TIMEOUT_S)
                try:
                    r = run_one_case(c, "frontier", filt, TEMP, rep)
                    rec = dict(case_id=c["id"], arm=arm, model=MODEL, rep=rep,
                               target_hit=r["target_hit"], n_filtered=r.get("n_filtered"),
                               benign_blocked=r.get("benign_blocked"))
                    consec_voids = 0
                except Exception as ex:
                    rec = dict(case_id=c["id"], arm=arm, rep=rep,
                               voided=True, fault=str(ex)[:120])
                    consec_voids += 1
                finally:
                    signal.alarm(0)
                with open(OUT, "a") as f:
                    f.write(json.dumps(rec, default=str) + "\n")
                n += 1
                tag = c["id"].split(":")
                lbl = f"{tag[2]}:{tag[3]}" if len(tag) > 3 else tag[-1]
                print(f"[{kind_label}] {arm:13s} {lbl} r{rep} "
                      f"hit={rec.get('target_hit')} filt={rec.get('n_filtered')} "
                      f"benign_blocked={rec.get('benign_blocked')} ({n}/{total})", flush=True)
                if consec_voids >= MAX_CONSEC_VOIDS:     # G6: systemic fault -> stop loudly
                    sys.exit(f"ABORT: {MAX_CONSEC_VOIDS} consecutive voided episodes "
                             f"(last fault: {rec.get('fault')}). Fix the fault and rerun -- resume continues.")

run_block(sec_cases,  SEC_ARMS,  "SEC")
run_block(util_cases, UTIL_ARMS, "UTIL")
print("DONE G2_EXTENDED", flush=True)
