#!/usr/bin/env python3
"""
power_analysis.py — S0_integrity pre-registration power analysis
================================================================
Campaign: AgentDojo security evaluation v2 (DEI / CZTA monitor + counterfactual
audit gate). Master seed: 20260814. Date: 2026-08-14.

All power computations use the normal approximation to the two-sided
two-proportion z-test:

  H0: p1 = p2 ;  reject when |phat1 - phat2| / SE_pooled > z_{1-alpha/2}

Power under H1 (p1, p2) is computed with the standard approximation that the
pooled SE under the null is evaluated at the restricted MLE, while the
distribution of (phat1 - phat2) under H1 is N(p1 - p2, p1 q1/n1 + p2 q2/n2).

Methods used:
  - If scipy is available: scipy.stats.norm for Phi / Phi^{-1}.
  - Otherwise: pure-python fallback (math.erf for Phi; Acklam's rational
    approximation for the inverse normal CDF).
Both paths are exercised identically; the active backend is printed.

Wilson 95% intervals: closed-form score interval (Wilson, 1927).

Cohen's h: h = 2*arcsin(sqrt(p1)) - 2*arcsin(sqrt(p2)).

Nothing in this file is an empirical result about any model. All effect sizes
are pre-registered design targets (minimum effects of interest).
"""

import hashlib
import math
import sys

# --------------------------------------------------------------------------
# Backend: scipy if available, else pure python
# --------------------------------------------------------------------------
try:
    from scipy.stats import norm as _norm
    BACKEND = "scipy.stats.norm (scipy %s)" % __import__("scipy").__version__
    Phi = _norm.cdf
    PhiInv = _norm.ppf
except ImportError:
    BACKEND = "pure-python (math.erf Phi; Acklam rational approximation PhiInv)"

    def Phi(x):
        return 0.5 * (1.0 + math.erf(x / math.sqrt(2.0)))

    def PhiInv(p):
        # Acklam's inverse-normal approximation (max |err| ~ 1.15e-9)
        a = [-3.969683028665376e+01, 2.209460984245205e+02,
             -2.759285104469687e+02, 1.383577518672690e+02,
             -3.066479806614716e+01, 2.506628277459239e+00]
        b = [-5.447609879822406e+01, 1.615858368580409e+02,
             -1.556989798598866e+02, 6.680131188771972e+01,
             -1.328068155288572e+01]
        c = [-7.784894002430293e-03, -3.223964580411365e-01,
             -2.400758277161838e+00, -2.549732539343734e+00,
              4.374664141464968e+00, 2.938163982698783e+00]
        d = [7.784695709041462e-03, 3.224671290700398e-01,
             2.445134137142996e+00, 3.754408661907416e+00]
        plow, phigh = 0.02425, 1 - 0.02425
        if p < plow:
            q = math.sqrt(-2 * math.log(p))
            return (((((c[0]*q + c[1])*q + c[2])*q + c[3])*q + c[4])*q + c[5]) / \
                   ((((d[0]*q + d[1])*q + d[2])*q + d[3])*q + 1)
        if p > phigh:
            q = math.sqrt(-2 * math.log(1 - p))
            return -(((((c[0]*q + c[1])*q + c[2])*q + c[3])*q + c[4])*q + c[5]) / \
                    ((((d[0]*q + d[1])*q + d[2])*q + d[3])*q + 1)
        q = p - 0.5
        r = q * q
        return (((((a[0]*r + a[1])*r + a[2])*r + a[3])*r + a[4])*r + a[5])*q / \
               (((((b[0]*r + b[1])*r + b[2])*r + b[3])*r + b[4])*r + 1)

# --------------------------------------------------------------------------
# Core routines
# --------------------------------------------------------------------------
def power_two_prop(p1, p2, n1, n2, alpha=0.05):
    """Normal-approximation power of the two-sided two-proportion z-test.

    Critical value from the pooled-SE test under H0; power integrated under
    H1 with the unpooled variance. Returns power in [0, 1].
    """
    z_a = PhiInv(1 - alpha / 2.0)
    p_pool = (n1 * p1 + n2 * p2) / (n1 + n2)
    se_null = math.sqrt(p_pool * (1 - p_pool) * (1.0 / n1 + 1.0 / n2))
    se_alt = math.sqrt(p1 * (1 - p1) / n1 + p2 * (1 - p2) / n2)
    d = p1 - p2
    crit_hi = z_a * se_null
    crit_lo = -z_a * se_null
    # P(reject | H1) = P(diff > crit_hi) + P(diff < crit_lo)
    power = (1 - Phi((crit_hi - d) / se_alt)) + Phi((crit_lo - d) / se_alt)
    return power


def n_required_two_prop(p1, p2, power_target=0.90, alpha=0.05, ratio=1.0):
    """Required n per arm (equal arms, ratio = n2/n1) via the standard
    closed-form normal approximation; then verified by recomputing power and
    nudging up to the smallest integer n that achieves the target."""
    z_a = PhiInv(1 - alpha / 2.0)
    z_b = PhiInv(power_target)
    pbar = (p1 + ratio * p2) / (1 + ratio)
    qbar = 1 - pbar
    num = (z_a * math.sqrt((1 + 1/ratio) * pbar * qbar)
           + z_b * math.sqrt(p1 * (1 - p1) + p2 * (1 - p2) / ratio)) ** 2
    n1 = num / (p1 - p2) ** 2
    n = math.ceil(n1)
    # verify and nudge upward if the closed form under-delivers
    while power_two_prop(p1, p2, n, int(round(n * ratio)), alpha) < power_target:
        n += 1
    return n


def wilson_halfwidth(phat, n, alpha=0.05):
    """Half-width of the Wilson (score) 100(1-alpha)% CI for a binomial
    proportion. Assumes x = round(phat*n) successes (nearest realizable
    count); reports the realized phat as well."""
    z = PhiInv(1 - alpha / 2.0)
    x = int(round(phat * n))
    p = x / n
    denom = 1 + z * z / n
    centre = (p + z * z / (2 * n)) / denom
    half = (z / denom) * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n))
    return x, p, centre, half


def cohens_h(p1, p2):
    return 2 * math.asin(math.sqrt(p1)) - 2 * math.asin(math.sqrt(p2))


def derive_seed(master_seed, suite, model, temp, arm, rep):
    """Per-arm seed derivation, exactly as pre-registered:
      seed = int(SHA256(f"{master}|{suite}|{model}|{temp}|{arm}|{rep}")
                 .hexdigest()[:8], 16)          # hex-truncated to 32 bits
    i.e. the first 8 hex chars of the digest, big-endian, < 2^32 by
    construction. Fields are joined with '|', UTF-8 encoded, no whitespace.
    """
    msg = f"{master_seed}|{suite}|{model}|{temp}|{arm}|{rep}".encode("utf-8")
    digest = hashlib.sha256(msg).hexdigest()
    return int(digest[:8], 16), digest

# --------------------------------------------------------------------------
# Report
# --------------------------------------------------------------------------
def main():
    ALPHA = 0.05
    out = []
    def p(s=""):
        print(s)
        out.append(s)

    p("=" * 78)
    p("S0_integrity power analysis — executed %s" % "2026-08-14")
    p("Backend: %s" % BACKEND)
    p("Python: %s" % sys.version.split()[0])
    p("Alpha: 0.05 (two-sided) throughout, unless stated")
    p("NOTE: all effect sizes below are pre-registered design targets (MEIs),")
    p("not observed results. No empirical claim about any model is made here.")
    p("=" * 78)

    # (a) power at n=629/arm -------------------------------------------------
    p("")
    p("(a) Power of two-proportion z-test, n = 629 per arm (full AgentDojo")
    p("    security-case count), alpha = 0.05 two-sided")
    p("-" * 78)
    p("%-14s %-10s %-10s %-10s" % ("drop", "p1", "p2", "power"))
    pairs_a = [(0.25, 0.05), (0.25, 0.18), (0.25, 0.15), (0.15, 0.05)]
    for p1, p2 in pairs_a:
        pw = power_two_prop(p1, p2, 629, 629, ALPHA)
        p("%-14s %-10.2f %-10.2f %-10.4f" % ("%.2f->%.2f" % (p1, p2), p1, p2, pw))

    # (a2) supplementary power grid over reduced per-arm n --------------------
    p("")
    p("(a2) Supplementary: power at reduced per-arm n (3-seed cells, subset")
    p("    analyses such as the laundering class, per-suite breakdowns)")
    p("-" * 78)
    p("%-8s %-14s %-10s" % ("n/arm", "drop", "power"))
    for n in (97, 189, 377):
        for p1, p2 in [(0.25, 0.05), (0.25, 0.15), (0.15, 0.05)]:
            pw = power_two_prop(p1, p2, n, n, ALPHA)
            p("%-8d %-14s %-10.4f" % (n, "%.2f->%.2f" % (p1, p2), pw))
    p("    (n=189 ~= 629*0.3, one suite's approximate share; n=97 = smallest")
    p("     pre-registered subset: utility-task count / laundering-class floor)")

    # (b) required n for 90% power at 25% -> 20% -----------------------------
    p("")
    p("(b) Required n per arm for 90%% power, drop 0.25 -> 0.20")
    p("-" * 78)
    nreq = n_required_two_prop(0.25, 0.20, power_target=0.90, alpha=ALPHA)
    pw_check = power_two_prop(0.25, 0.20, nreq, nreq, ALPHA)
    p("required n per arm (verified): %d  (achieved power = %.4f)" % (nreq, pw_check))
    p("total both arms: %d" % (2 * nreq))

    # (c) Wilson 95% half-widths ----------------------------------------------
    p("")
    p("(c) Wilson 95%% CI half-widths (x = nearest realizable count to phat*n)")
    p("-" * 78)
    p("%-8s %-8s %-6s %-8s %-10s %-12s" %
      ("n", "phat", "x", "real.p", "centre", "half-width"))
    for n in (30, 60, 97, 629):
        for phat in (0.05, 0.15, 0.50):
            x, rp, centre, half = wilson_halfwidth(phat, n, ALPHA)
            p("%-8d %-8.2f %-6d %-8.4f %-10.4f %-12.4f" %
              (n, phat, x, rp, centre, half))

    # (d) gate quarantine-precision at reduced (3-seed) schedule --------------
    p("")
    p("(d) Gate quarantine-precision comparison, reduced seed schedule")
    p("    3 seeds => ~60%% of episodes: n = round(629 * 0.6) = %d per arm"
      % round(629 * 0.6))
    p("    Endpoint (pre-registered): monitor+gate quarantine precision vs the")
    p("    monitor-only implicit-block precision, two-proportion z-test.")
    p("-" * 78)
    n_d = round(629 * 0.6)
    p("%-16s %-10s %-10s %-10s" % ("precision gap", "p_gate", "p_mon", "power"))
    pairs_d = [(0.90, 0.70), (0.90, 0.75), (0.95, 0.80), (0.85, 0.70), (0.90, 0.80)]
    for p1, p2 in pairs_d:
        pw = power_two_prop(p1, p2, n_d, n_d, ALPHA)
        p("%-16s %-10.2f %-10.2f %-10.4f" % ("%.2f->%.2f" % (p1, p2), p1, p2, pw))

    # (e) Cohen's h -----------------------------------------------------------
    p("")
    p("(e) Cohen's h = 2*asin(sqrt(p1)) - 2*asin(sqrt(p2))")
    p("    conventions: |h|=0.2 small, 0.5 medium, 0.8 large")
    p("-" * 78)
    all_pairs = pairs_a + [(0.25, 0.20)] + pairs_d
    for p1, p2 in all_pairs:
        h = cohens_h(p1, p2)
        mag = ("large" if abs(h) >= 0.8 else
               "medium" if abs(h) >= 0.5 else
               "small" if abs(h) >= 0.2 else "below-small")
        p("h(%.2f -> %.2f) = %+.4f  (%s)" % (p1, p2, h, mag))

    # sanity: seed-derivation rule (supports the protocol header) -------------
    p("")
    p("Seed-derivation sanity check (rule as pre-registered in PROTOCOL_EVAL_V2)")
    p("-" * 78)
    for args in [("workspace", "ow7b", "0.0", "monitor+gate", 1),
                 ("banking", "frontier", "0.7", "no-defense", 5),
                 ("travel", "ow7b", "0.7", "monitor-only", 3)]:
        s, d = derive_seed(20260814, *args)
        p("seed(20260814|%s|%s|%s|%s|r%d) = %d  (sha256=%s...)"
          % (args + (s, d[:16])))

    p("")
    p("=" * 78)
    p("END OF POWER ANALYSIS OUTPUT")
    p("=" * 78)

    with open("power_analysis_output.txt", "w") as f:
        f.write("\n".join(out) + "\n")


if __name__ == "__main__":
    main()
