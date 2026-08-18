# Agentic Prompt-Injection Susceptibility & Monitor+Gate Defense
Campaign 2026-08-16/17. Protocol seal dfac3893, master seed 20260814.

## Validated results (fixed harness, gemini-2.5-flash)
- Susceptibility: ASR 0.383 [0.271, 0.510], n=60 (out/rerun_fixed.jsonl)
- Defense grid (out_g2.jsonl): no-defense 0.20 → monitor-only 0.05 → monitor+gate 0.00
  (monitor verifiably engaged: 12–13 protected calls filtered per 20 episodes; 0 voids)
- Calibration: gpt-4o-2024-05-13 hit 4/5 on the same susceptible task at t0.0/t0.7 —
  the harness lands attacks where models are vulnerable.

## Status of archived logs
out/episodes_*.jsonl predate the verdict-key fix; their verdict columns are constant
and serve as coverage/seed provenance only. All reported numbers come from the
post-fix runs above.

## Reproduce
pip install agentdojo==0.1.35 openai
python3 g2.py   # defense grid; rerun susceptibility with run_campaign.py
