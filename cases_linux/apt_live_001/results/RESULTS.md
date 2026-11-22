# Results — apt_live_001 (first live APT-Agent → ARGUS case)

Case: `cases_linux/apt_live_001/` — live Metasploitable 2 attack, 2026-09-09.
Raw capture: `captures/run_20260909_131524/`. **No ARGUS mechanism changes** — inputs only.

## Verdict (identical with and without the LLM)
| | disposition | severity | claims | hypotheses |
|---|---|---|---|---|
| Deterministic engine | **malicious** | 0.542 | 70/70 | T1210 0.64, T1110 0.44 |
| + Ollama proposer (`gpt-oss:120b-cloud`) | **malicious** | 0.542 | 70/70 | same |

## Ground truth (from APT-Agent's own log)
T1046 recon · **T1110 brute force = SUCCESS** · T1210 vsftpd backdoor = FAIL · T1041 exfil = FAIL · objective not reached.

## Reading of the result
- **T1110 (0.44) correct** — the one technique that actually landed.
- **T1210 (0.64) inflated by INPUT noise** — 42 `session_opened`/`privileged_command` claims, mostly ~12 h of pre-attack cron/msfadmin baseline in the captured auth.log, not real exploitation. Fix at capture (clean log), not in the engine.
- **T1041 did not fire** — exfil ran inside the MSF session shell, never touched auth.log. Real coverage gap, not an engine miss.

## LLM layer (Ollama Cloud) — trust boundary held
- Proposer: ran live (not a test double), `proposed 0`, `hallucination_rate 0.0` — nothing to decompose (auth events, no command lines); verdict unmoved.
- Verbalizer (`explain_ollama.txt`): model wrote the narrative, and ARGUS **dropped 1 ungrounded sentence** (`[1 sentence(s) dropped: not traceable to the decision]`) — span-verified grounding working.

## Files in this dir
- `triage_deterministic.json` — engine-only decision (full JSON)
- `triage_ollama.json` — decision + `llm` proposer report
- `explain_ollama.txt` — LLM-written analyst narrative (grounding-gated)
- `claims.txt` — all 70 extracted claims

## How these were produced
```bash
cd <repo root> && source .venv/bin/activate
export PYTHONPATH="source code"
export OLLAMA_BASE_URL=https://ollama.com OLLAMA_API_KEY=<rotated-key>
python -m argus.cli triage  cases_linux/apt_live_001
python -m argus.cli triage  cases_linux/apt_live_001 --llm ollama --llm-model gpt-oss:120b-cloud
python -m argus.cli explain cases_linux/apt_live_001 --llm ollama --llm-model gpt-oss:120b-cloud
```
