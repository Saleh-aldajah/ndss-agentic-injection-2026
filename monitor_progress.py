#!/usr/bin/env python3
"""
Progress monitor for the extended campaign — run this in your SECOND terminal
while g2_extended.py runs in the first.

    python3 monitor_progress.py                # one-shot status
    python3 monitor_progress.py --follow 60    # refresh every 60s (Ctrl-C to stop)

Reads out_g2_extended.jsonl (default) and prints per-arm progress, running
ASRs, voided counts, and the last faults seen. Pure stdlib; reads the file
only — zero interference with the running campaign.
"""
import json, sys, time, os
from collections import defaultdict

PATH = "out_g2_extended.jsonl"
TARGET_SEC, TARGET_UTIL = 40, 24   # per arm
TOTAL_TARGET = 3*TARGET_SEC + 2*TARGET_UTIL  # 168

def status():
    if not os.path.exists(PATH):
        print(f"{PATH} does not exist yet — campaign not started (or wrong directory).")
        return
    sec = defaultdict(lambda: [0, 0]); util = defaultdict(lambda: [0, 0])
    voids = 0; faults = []
    n = 0
    for line in open(PATH):
        try: e = json.loads(line)
        except Exception: continue
        n += 1
        if e.get("voided"):
            voids += 1; faults.append(f"{e.get('arm')}:{e.get('case_id')} — {e.get('fault','?')}")
            continue
        if ":sec:" in e.get("case_id", ""):
            s = sec[e["arm"]]; s[0] += 1; s[1] += 1 if e.get("target_hit") else 0
        elif ":util:" in e.get("case_id", ""):
            u = util[e["arm"]]; u[0] += 1; u[1] += 1 if e.get("benign_blocked") else 0
    done = sum(v[0] for v in sec.values()) + sum(v[0] for v in util.values())
    print(f"\n=== campaign progress: {done}/{TOTAL_TARGET} valid episodes "
          f"({100*done/TOTAL_TARGET:.0f}%), {voids} voided ===")
    print("SECURITY:")
    for arm in ("no-defense", "monitor-only", "monitor+gate"):
        c, h = sec.get(arm, [0, 0])
        bar = "#" * int(20*c/TARGET_SEC)
        print(f"  {arm:14s} {c:3d}/{TARGET_SEC}  [{bar:<20s}]  running ASR {h}/{c}"
              + (f" = {h/c:.3f}" if c else ""))
    print("UTILITY:")
    for arm in ("no-defense", "monitor+gate"):
        c, b = util.get(arm, [0, 0])
        bar = "#" * int(20*c/TARGET_UTIL)
        print(f"  {arm:14s} {c:3d}/{TARGET_UTIL}  [{bar:<20s}]  false-blocks {b}/{c}")
    if faults:
        print(f"last faults ({voids} voided total):")
        for f in faults[-3:]: print(f"  {f}")
        if voids >= 5: print("  WARNING: >=5 voids — check the fault before it wastes quota.")

if "--follow" in sys.argv:
    iv = int(sys.argv[sys.argv.index("--follow")+1]) if len(sys.argv) > sys.argv.index("--follow")+1 else 60
    try:
        while True:
            os.system("clear" if os.name == "posix" else "cls"); status(); time.sleep(iv)
    except KeyboardInterrupt:
        print("\nmonitor stopped.")
else:
    status()
