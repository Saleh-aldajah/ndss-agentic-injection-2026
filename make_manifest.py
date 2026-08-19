#!/usr/bin/env python3
"""Regenerate VERIFICATION_MANIFEST.json (secrets gate + sha256 + recompute)."""
import hashlib, json, math, pathlib, re, sys
from collections import defaultdict
from math import comb

ROOT = pathlib.Path(".")
OUT  = ROOT / "VERIFICATION_MANIFEST.json"

EXCLUDE_DIRS  = {".git", "__pycache__", ".venv", "venv", "node_modules"}
EXCLUDE_FILES = {"VERIFICATION_MANIFEST.json", "ndss_env.sh"}
EXCLUDE_GLOB  = {"*.zip", "*.tar", "*.gz", "*.7z", "*.key", "*.pem", "*.env"}

SECRET_PATTERNS = {
    "google_api_key":  r"AIza[0-9A-Za-z_\-]{20,}",
    "openai_key":      r"sk-(proj-|ant-)?[0-9A-Za-z_\-]{20,}",
    "google_oauth_tok": r"AQ\.Ab8[0-9A-Za-z_\-]{10,}",
    "github_token":    r"(ghp|gho|ghu|ghs|ghr)_[0-9A-Za-z]{20,}",
    "private_key":     r"-----BEGIN [A-Z ]*PRIVATE KEY-----",
}

def sha256(p):
    h = hashlib.sha256()
    with open(p, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()

# secrets gate: scans EVERY file (including hash-excluded ones)
findings = []
candidates = []
for p in sorted(ROOT.rglob("*")):
    if not p.is_file(): continue
    rel = p.relative_to(ROOT).as_posix()
    if any(part in EXCLUDE_DIRS for part in p.parts): continue
    try:
        text = p.read_text(errors="ignore")
    except Exception:
        continue
    for name, pat in SECRET_PATTERNS.items():
        if re.search(pat, text):
            findings.append((rel, name))
    if p.name in EXCLUDE_FILES: continue
    if any(p.match(g) for g in EXCLUDE_GLOB): continue
    candidates.append((rel, p))

if (ROOT / "ndss_env.sh").exists():
    findings.append(("ndss_env.sh", "env file must not live inside the repo"))

if findings:
    print("SECRETS GATE: REFUSED - credential-like material found:")
    for rel, name in findings: print(f"  {rel}  ->  {name}")
    sys.exit(1)
print(f"SECRETS GATE: clean ({len(candidates)} files scanned)")

files = {rel: {"sha256": sha256(p), "bytes": p.stat().st_size} for rel, p in candidates}

def wilson(k, n, z=1.96):
    if n == 0: return (0.0, 0.0, 0.0)
    p = k/n; d = 1 + z*z/n
    c = (p + z*z/(2*n))/d
    m = z*math.sqrt(p*(1-p)/n + z*z/(4*n*n))/d
    return (p, max(0.0, c-m), min(1.0, c+m))

def fisher_two_sided(a, b, c, d):
    n = a+b+c+d; r1 = a+b; c1 = a+c
    def hp(x): return comb(c1, x)*comb(n-c1, r1-x)/comb(n, r1)
    p0 = hp(a); lo = max(0, r1-(n-c1)); hi = min(r1, c1)
    return sum(hp(x) for x in range(lo, hi+1) if hp(x) <= p0*(1+1e-9))

recomputed = {}
log = ROOT / "out_g2_extended.jsonl"
if log.exists():
    sec = defaultdict(lambda: [0, 0]); util = defaultdict(lambda: [0, 0])
    for line in log.read_text().splitlines():
        try: e = json.loads(line)
        except Exception: continue
        if e.get("voided"): continue
        if ":sec:" in e.get("case_id", ""):
            s = sec[e["arm"]]; s[0] += 1; s[1] += 1 if e.get("target_hit") else 0
        elif ":util:" in e.get("case_id", ""):
            u = util[e["arm"]]; u[0] += 1; u[1] += 1 if e.get("benign_blocked") else 0
    for arm, (n, k) in sorted(sec.items()):
        p, lo, hi = wilson(k, n)
        recomputed[f"security:{arm}"] = {
            "hits": k, "n": n, "asr": round(p, 4), "ci95": [round(lo, 3), round(hi, 3)]}
    for arm, (n, b) in sorted(util.items()):
        p, lo, hi = wilson(b, n)
        recomputed[f"utility:{arm}"] = {
            "false_blocks": b, "n": n, "utility_rate": round(1-p, 4)}
    nd, gate = sec.get("no-defense"), sec.get("monitor+gate")
    if nd and gate and nd[0] and gate[0]:
        pf = fisher_two_sided(gate[1], gate[0]-gate[1], nd[1], nd[0]-nd[1])
        recomputed["fisher_gate_vs_nodefense"] = {
            "p_two_sided": round(pf, 6), "significant_0.05": pf < 0.05}
    print(f"RECOMPUTE: {sum(v[0] for v in sec.values())} security + "
          f"{sum(v[0] for v in util.values())} utility episodes folded into manifest")
else:
    print("RECOMPUTE: out_g2_extended.jsonl not found - manifest will hash only")

import datetime
manifest = {
    "package": "epistemic-security-ndss-extended-campaign",
    "generated_utc": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    "generator": "make_manifest.py (secrets gate + sha256 + recompute)",
    "files": files,
    "recomputed": recomputed,
}
OUT.write_text(json.dumps(manifest, indent=2) + "\n")
print(f"WROTE {OUT}  ({len(files)} files hashed)")
