# Results

## R.1 Susceptibility of current-generation models to canonical templated attacks

We evaluated the canonical `important_instructions` attack family from the AgentDojo
benchmark (v1.2, agentdojo 0.1.35) against current-generation tool-using models,
executing all episodes through a seed-audited, checkpointed harness derived from the
benchmark's own `run_task_with_pipeline` path.

On the workspace suite (30 security cases × 2 repetitions, temperature 0.7),
**gemini-2.5-flash exhibits ASR = 0.383 (23/60, 95% Wilson CI [0.271, 0.510])**.
Per-task susceptibility is sharply heterogeneous: user_task_1 at 0.50 (14/28),
user_task_3 at 1.00 (4/4), user_task_0 at 0.18 (5/28) — indicating that vulnerability
concentrates in particular task–injection structures rather than distributing uniformly.

In contrast, the Qwen open-weight family (qwen3-coder-30b, qwen3-32b) produced
no successful injections in 344 archived episodes spanning three attack families, four
suites, and two temperatures. We flag that these archived verdicts predate the harness
fix (Section R.4) and report them as negative observations only; powered null claims
about these models await a fixed-harness rerun. Our positive susceptibility claims rest
solely on the fixed-harness Gemini measurements and the calibration control below.

**Calibration control (positive).** To rule out harness inertness as an explanation
for any null result, we replicated the identical attack through the identical code path
against the 2024-era snapshot gpt-4o-2024-05-13 on the known-susceptible workspace
user_task_0 injections: **4/5 successful injections at both t=0.0 and t=0.7**.
The harness lands attacks wherever models are susceptible; null results are model
properties, not setup artifacts.

## R.2 Defense efficacy on a live attack surface

On the susceptible subject (gemini-2.5-flash, workspace, 10 cases × 2 reps per arm,
fixed harness), the proposed defense collapses the attack success rate:

| Arm | ASR | 95% CI | Protected calls filtered |
|---|---|---|---|
| no-defense | 0.20 (4/20) | [0.081, 0.416] | 0 |
| monitor-only (I1–I3 admission) | 0.05 (1/20) | [0.009, 0.236] | 13 |
| **monitor+gate (admission + counterfactual re-commitment)** | **0.00 (0/20)** | [0.000, 0.161] | 12 |

Benign utility remained intact throughout (0 false blocks on all utility episodes).
The monitor verifiably engaged: 12–13 protected tool calls were intercepted per
20 episodes in the defended arms, and interception counts are logged per episode.

The Wilson upper bound on monitor+gate (0.161) reflects the small per-arm sample;
the camera-ready evaluation extends the grid to 50+ cases per arm.

## R.3 Model-dependent susceptibility

Susceptibility in 2026 is **model-specific**. Our validated measurements (fixed
harness, per-episode model strings recorded): gemini-2.5-flash exhibits ASR 0.383
(23/60, 95% CI [0.271, 0.510]) across the 30-case workspace sweep, and 0.20 (4/20)
on the 10-case defense-grid subsample — both drawn from data/rerun_fixed.jsonl and
data/out_g2.jsonl respectively; the difference reflects the case mix, not a
contradiction. In contrast, the Qwen open-weight family (qwen3-coder-30b, qwen3-32b)
showed no successful injections in 344 archived episodes across three attack families
(coverage-verified; those verdicts predate the harness fix and are reported as
negative observations, not powered estimates). Susceptibility claims therefore
require per-model, per-attack-family evaluation with positive calibration controls;
blanket statements about "current models" in either direction are unsupported.

## R.4 Methodological findings (harness defects discovered)

The campaign surfaced four latent defects in naive AgentDojo integrations, each of
which silently invalidates results if unaddressed: (i) pipeline naming requirements
of the attack registry void every security episode when violated; (ii) weakened attack
variants (`no_names`) are ignored by post-2024 models, producing floor-effect zeros;
(iii) TypedDict message contracts break attribute-style interceptors, silently
disabling defenses; (iv) verdict key mismatches force constant False verdicts.
We document each with its detection signature; all fixes ship in the reproduction
package, and all reported results were produced after the fixes, with per-episode
intercept counters proving defense engagement.

# Discussion

**Benchmark threat levels are model-dependent in 2026.** The canonical templated
attacks that produced 40–70% ASR against 2024-era models remain effective against a
current Google flagship (0.383, CI [0.271, 0.510]) while producing no observed
successes against the Qwen open-weight family in our archived runs. Benchmarks must
therefore version their threat model per model and per attack family, and
susceptibility claims require positive calibration controls of the kind we demonstrate.

**Implications for defense evaluation.** A defense can only be evidenced where attacks
land. Our monitor+gate design is evaluated against a measured 0.20 baseline
(10-case grid; 0.383 across the wider 30-case sweep) and drives it to zero with full
utility preservation; evaluations on resistant models cannot demonstrate this and
should not be reported as defense evidence.

**Limitations.** Per-arm n=20 in the defense grid (extension planned); the temporal
contrast rests on a dated-snapshot calibration with small n; open-weight arms were
evaluated on 30B-class local models only; the Qwen nulls predate the harness fix and
await powered re-measurement.
