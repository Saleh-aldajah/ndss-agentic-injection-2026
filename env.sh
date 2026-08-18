# Amendment-2 roster — source this AFTER editing (never commit a real key)
# Open-weight arms (verified tool-calling on 2026-08-14):
export OW_BASE_URL=http://100.79.114.58:11434/v1
export OW_LARGE_MODEL=qwen3:32b
export OW_MID_MODEL=qwen3-coder:latest     # ow-mid   (transportability)
export OW_API_KEY=ollama                    # Ollama ignores the value; must be non-empty

# Frontier tier — DEFERRED (Amendment 3). Fill only when you have a hosted key:
# export FRONTIER_API_KEY=...              # in your shell only, NEVER in chat/commit
# export FRONTIER_BASE_URL=https://api.openai.com/v1
# export FRONTIER_MODEL=gpt-4o-mini-2024-07-18
