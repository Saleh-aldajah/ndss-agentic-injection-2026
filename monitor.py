"""monitor.py -- Executable core of Algorithm 1 (event admission monitor).

Implements the paper's monitor semantics:
  * Event language: ing(e,ch), upd(b,X,l_prop), end(b,l',rho), act(a), tick.
  * Label lattice: BOTTOM < MEDIUM < TRUSTED (BOTTOM = bottom, TRUSTED = top).
  * I1: no protected action rests on orphan / unattested / sub-floor / stale
    roots. Root certificates cert(b) are MEMOIZED (structural check: every
    maximal derivation path terminates in attested evidence >= ell_min);
    freshness (validity-window containment) is RE-CHECKED AT ACTION TIME
    against the current tick and is deliberately not memoized.
  * I2: labels only rise via authorized endorsement. upd gets the meet of its
    input labels by default; proposing a label above the meet without an
    endorsement is blocked (silent upgrade). end(b,l',rho) requires rho to be
    authorized for l' in the policy pi.
  * I3: aggregator S(support) = sum(w) / (1 + sum(w)) over qualifying
    (cert-ok, fresh, label >= ell_req) cited beliefs; admit iff S >= tau_c
    where tau_c is per action class.
  * Optional two-root policy: destructive classes require >= 2 cited beliefs
    with pairwise-disjoint evidence leaves.
  * Hash-chained append-only log: each record is SHA-256 chained to its
    predecessor and HMAC-SHA256 signed with a fixed test key.
    NOTE: HMAC here stands in for the paper's Ed25519 signatures (stdlib-only
    artifact); the chain construction is identical, only the signing
    primitive differs.
  * Blocking = truncation: the first blocked event ends the trace.

Deterministic given the input trace and policy.
"""
from __future__ import annotations

import hashlib
import hmac
import json

LABEL = {"BOTTOM": 0, "MEDIUM": 1, "TRUSTED": 2}
LNAME = {v: k for k, v in LABEL.items()}

# Fixed test key for HMAC-SHA256 log signing. This replaces Ed25519 from the
# paper (stdlib-only constraint); see README.md.
TEST_KEY = b"launderbench-hmac-test-key-20260814"


def canon(obj) -> str:
    """Canonical JSON serialization for hashing/signing."""
    return json.dumps(obj, sort_keys=True, separators=(",", ":"))


class Monitor:
    def __init__(self, policy: dict):
        # Normalize policy: label names -> lattice ints.
        self.channels = {c: LABEL[v] for c, v in policy["channels"].items()}
        self.endorsers = {r: LABEL[v] for r, v in policy["endorsers"].items()}
        self.tau_c = dict(policy["tau_c"])
        self.ell_req = {c: LABEL[v] for c, v in policy["ell_req"].items()}
        self.ell_min = LABEL[policy["ell_min"]]
        self.two_root = bool(policy.get("two_root", False))
        self.two_root_classes = set(policy.get("two_root_classes", []))

        self.t = 0                     # logical time, advanced by tick
        self.ev = {}                   # eid -> evidence record
        self.bl = {}                   # bid -> belief record
        self.memo = {}                 # bid -> (ok, reason) structural cert
        self.log = []                  # append-only hash-chained log
        self.prev = "0" * 64           # chain head

    # ------------------------------------------------------------------ log
    def _log(self, event, verdict, invariant, reason, detail):
        rec = {
            "seq": len(self.log),
            "t": self.t,
            "event": event,
            "verdict": verdict,
            "invariant": invariant,
            "reason": reason,
            "detail": detail,
            "prev": self.prev,
        }
        h = hashlib.sha256(canon(rec).encode()).hexdigest()
        rec["sha256"] = h
        rec["hmac"] = hmac.new(TEST_KEY, h.encode(), hashlib.sha256).hexdigest()
        self.log.append(rec)
        self.prev = h

    # ----------------------------------------------------------- provenance
    def _leaves(self, bid, _seen=None):
        """All evidence ids reachable from belief bid (cycle-safe)."""
        if _seen is None:
            _seen = set()
        if bid in _seen:
            return set()
        _seen.add(bid)
        b = self.bl.get(bid)
        if b is None:
            return set()
        out = set()
        for inp in b["inputs"]:
            if inp in self.ev:
                out.add(inp)
            elif inp in self.bl:
                out |= self._leaves(inp, _seen)
        return out

    def cert(self, bid):
        """Memoized structural root certificate (I1, without freshness).

        cert(b)=ok iff every maximal derivation path from b terminates in
        attested evidence with label >= ell_min.
        """
        return self._cert(bid, frozenset())

    def _cert(self, bid, visiting):
        if bid in self.memo:
            return self.memo[bid]
        b = self.bl.get(bid)
        if b is None:
            return (False, "unknown_belief")
        if bid in visiting:
            return (False, "cycle")
        if not b["inputs"]:
            res = (False, "orphan_root")
        else:
            res = (True, "ok")
            for inp in b["inputs"]:
                if inp in self.ev:
                    e = self.ev[inp]
                    if not e["attested"]:
                        res = (False, "unattested_root")
                        break
                    if e["label"] < self.ell_min:
                        res = (False, "sub_floor_root")
                        break
                elif inp in self.bl:
                    sub = self._cert(inp, visiting | {bid})
                    if not sub[0]:
                        res = sub
                        break
                else:
                    res = (False, "unknown_input")
                    break
        self.memo[bid] = res
        return res

    def fresh(self, bid):
        """Action-time freshness re-check (NOT memoized): every evidence leaf
        validity window must contain the current logical time."""
        for eid in self._leaves(bid):
            e = self.ev[eid]
            if not (e["t0"] <= self.t < e["t1"]):
                return False
        return True

    # -------------------------------------------------------------- events
    def step(self, ev):
        """Process one event. Returns a verdict dict."""
        ty = ev["type"]
        if ty == "tick":
            n = int(ev.get("n", 1))
            self.t += n
            v = {"verdict": "ADMIT", "invariant": None, "reason": "ok",
                 "detail": {"t": self.t}}
        elif ty == "ing":
            v = self._ing(ev)
        elif ty == "upd":
            v = self._upd(ev)
        elif ty == "end":
            v = self._end(ev)
        elif ty == "act":
            v = self._act(ev)
        else:
            v = {"verdict": "BLOCK", "invariant": "I2",
                 "reason": "unknown_event_type", "detail": {}}
        self._log(ev, v["verdict"], v["invariant"], v["reason"], v["detail"])
        return v

    def _ing(self, ev):
        ch = ev["channel"]
        if ch not in self.channels:
            return {"verdict": "BLOCK", "invariant": "I2",
                    "reason": "unknown_channel", "detail": {"channel": ch}}
        lab = min(LABEL[ev["label"]], self.channels[ch])  # channel clamp
        self.ev[ev["eid"]] = {
            "channel": ch,
            "attested": bool(ev["attested"]),
            "label": lab,
            "t0": int(ev["t0"]),
            "t1": int(ev["t1"]),
            "weight": float(ev.get("weight", 1.0)),
            "content": ev.get("content", ""),
        }
        return {"verdict": "ADMIT", "invariant": None, "reason": "ok",
                "detail": {"eid": ev["eid"], "label": LNAME[lab],
                           "attested": bool(ev["attested"])}}

    def _upd(self, ev):
        bid = ev["bid"]
        X = list(ev.get("inputs", []))
        lp = LABEL[ev["label_prop"]] if ev.get("label_prop") else None
        if not X:
            # Orphan belief: admitted at update time with BOTTOM label, but its
            # root certificate will fail at action time (I1, orphan_root).
            self.bl[bid] = {"inputs": [], "label": LABEL["BOTTOM"],
                            "weight": float(ev.get("weight", 1.0))}
            self.memo.pop(bid, None)
            return {"verdict": "ADMIT", "invariant": None, "reason": "ok",
                    "detail": {"bid": bid, "label": "BOTTOM", "orphan": True}}
        for x in X:
            if x not in self.ev and x not in self.bl:
                return {"verdict": "BLOCK", "invariant": "I2",
                        "reason": "unknown_input", "detail": {"input": x}}
        meet = min(self.ev[x]["label"] if x in self.ev else self.bl[x]["label"]
                   for x in X)
        if lp is None:
            lp = meet  # meet-of-inputs default
        if lp > meet:
            return {"verdict": "BLOCK", "invariant": "I2",
                    "reason": "silent_upgrade",
                    "detail": {"bid": bid, "proposed": LNAME[lp],
                               "meet": LNAME[meet]}}
        self.bl[bid] = {"inputs": X, "label": lp,
                        "weight": float(ev.get("weight", 1.0))}
        self.memo.pop(bid, None)
        return {"verdict": "ADMIT", "invariant": None, "reason": "ok",
                "detail": {"bid": bid, "label": LNAME[lp],
                           "meet": LNAME[meet]}}

    def _end(self, ev):
        bid = ev["bid"]
        lp = LABEL[ev["label"]]
        rho = ev["rho"]
        if bid not in self.bl:
            return {"verdict": "BLOCK", "invariant": "I2",
                    "reason": "unknown_belief", "detail": {"bid": bid}}
        auth = self.endorsers.get(rho)
        if auth is None or auth < lp:
            return {"verdict": "BLOCK", "invariant": "I2",
                    "reason": "unauthorized_endorsement",
                    "detail": {"bid": bid, "rho": rho, "label": LNAME[lp]}}
        self.bl[bid]["label"] = max(self.bl[bid]["label"], lp)
        self.memo.pop(bid, None)
        return {"verdict": "ADMIT", "invariant": None, "reason": "ok",
                "detail": {"bid": bid, "rho": rho,
                           "label": LNAME[self.bl[bid]["label"]]}}

    def _act(self, ev):
        cls = ev["cls"]
        sup = list(ev["support"])
        certs = {}
        # ---- I1: cert (memoized structural) + action-time freshness re-check
        for bid in sup:
            ok, reason = self.cert(bid)
            is_fresh = self.fresh(bid) if ok else False
            certs[bid] = {
                "cert": reason,
                "fresh": is_fresh,
                "label": LNAME[self.bl[bid]["label"]] if bid in self.bl else None,
            }
            if not ok:
                return {"verdict": "BLOCK", "invariant": "I1", "reason": reason,
                        "detail": {"bid": bid, "certs": certs}}
            if not is_fresh:
                return {"verdict": "BLOCK", "invariant": "I1",
                        "reason": "stale_root",
                        "detail": {"bid": bid, "t": self.t, "certs": certs}}
        # ---- two-root policy (support-diversity binding on I3)
        if self.two_root and cls in self.two_root_classes:
            chosen = []
            for bid in sup:
                lv = self._leaves(bid)
                if all(lv.isdisjoint(c) for c in chosen):
                    chosen.append(lv)
            if len(chosen) < 2:
                return {"verdict": "BLOCK", "invariant": "I3",
                        "reason": "two_root_policy",
                        "detail": {"cls": cls, "disjoint_roots": len(chosen),
                                   "certs": certs}}
        # ---- I3: aggregator S = sum(w)/(1+sum(w)) over qualifying beliefs
        lreq = self.ell_req[cls]
        tau = self.tau_c[cls]
        qual = [b for b in sup
                if certs[b]["cert"] == "ok" and certs[b]["fresh"]
                and self.bl[b]["label"] >= lreq]
        w = sum(self.bl[b]["weight"] for b in qual)
        S = w / (1.0 + w)
        if S < tau:
            return {"verdict": "BLOCK", "invariant": "I3",
                    "reason": "below_threshold",
                    "detail": {"cls": cls, "S": S, "tau_c": tau,
                               "qualifying": qual, "certs": certs}}
        return {"verdict": "ADMIT", "invariant": None, "reason": "ok",
                "detail": {"cls": cls, "S": S, "tau_c": tau,
                           "qualifying": qual, "certs": certs}}

    # -------------------------------------------------------------- driver
    def process(self, events):
        """Process a trace; blocking truncates (Algorithm 1)."""
        verdicts = []
        for i, ev in enumerate(events):
            v = self.step(ev)
            verdicts.append({
                "i": i, "type": ev["type"], "verdict": v["verdict"],
                "invariant": v["invariant"], "reason": v["reason"],
                "detail": v["detail"],
            })
            if v["verdict"] == "BLOCK":
                return {"verdicts": verdicts, "final": "BLOCK",
                        "block": {"i": i, "type": ev["type"],
                                  "invariant": v["invariant"],
                                  "reason": v["reason"]},
                        "log_root": self.prev, "log": self.log,
                        "truncated": len(events) - i - 1}
        return {"verdicts": verdicts, "final": "ADMIT", "block": None,
                "log_root": self.prev, "log": self.log, "truncated": 0}


def run_instance(inst):
    """Convenience: run a generated instance dict through a fresh Monitor."""
    return Monitor(inst["policy"]).process(inst["events"])
