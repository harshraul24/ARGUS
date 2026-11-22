# Learned rules vs. dumping into an LLM vs. hand-written rules (lab diagnostic, 8 October 2026)

**Question.** Is it better to have an LLM *write rules* that ARGUS checks and then runs
(ARGUS S3), or to *dump the telemetry into an LLM* and ask for a verdict, or to rely on rules
an analyst writes by hand?

**Status.** This is a diagnostic on design and excluded data, not a test result. No test
operation exists yet, and nothing in ARGUS was changed. Results are in
`eval_runs/2026-10-08-comparison/`.

## The four approaches

| arm | what it is |
|---|---|
| **Old ARGUS** | ARGUS as it was on 8 October before the Linux-only cut (from the backup): hand-written rules plus a novelty score learned on the CITAR Windows machines |
| **Hand-written rules** | Current ARGUS with only its hand-written rules. This stands for "the analyst writes the rules" |
| **ARGUS + learned rules** | Current ARGUS with the 10 active rules the LLM wrote from run 1, each passing checks C1–C5 |
| **Dump to LLM** | The same model as rule learning (`gpt-oss:120b-cloud`), one call per window. It gets every event plus the process and parent, as ARGUS does, with secrets redacted and nothing else filtered. It is asked for a verdict and the events it thinks are attack activity. Run twice (seeds 7 and 8). Tool: `tools/llm_dump_lab.py` |

**Data.** Two captures, used differently:
- **Run 1** (20 windows, 36 attack steps) is in-sample for the learned rules: they were written
  from it, and its labels drove the simulated analyst review. This favours ARGUS.
- **Smoke** (14 windows, 68 attack steps) was excluded from design and test, and nothing was
  learned from it. **Smoke is the fair comparison.**

All arms are graded the same way, as in `tools/eval_lab.py`.

## Results

| | Old ARGUS | Hand-written | **ARGUS + learned** | Dump to LLM (seed 7 / seed 8) |
|---|---|---|---|---|
| **Run 1 (in-sample for learned rules)** | | | | |
| attack windows flagged | 8/8 | 1/8 | **8/8** | 8/8 / 8/8 |
| flagged on real attack evidence | 8/8 | 1/8 | **8/8** | 8/8 / 8/8 |
| benign windows flagged | 10/12 | 1/12 | **1/12** | 10/12 / 10/12 |
| attack steps detected | 30/36 | 2/36 | 28/36 | **32/36** / 30/36 |
| event precision | 0.009 | 0.010 | 0.135 (learned rules 1.0) | 0.219 / 0.071 |
| **Smoke (unseen by every arm)** | | | | |
| attack windows flagged | 7/8 | 0/8 | 7/8 | 8/8 / 8/8 |
| flagged on real attack evidence | 7/8 | 0/8 | **7/8** | 4/8 / 4/8 |
| benign windows flagged | 5/6 | 0/6 | **0/6** | 0/6 / 1/6 |
| attack steps detected | **64/68** | 0/68 | 12/68 | 22/68 / 22/68 |
| event precision | 0.109 | — | **1.0** | 0.854 / 0.814 |

**Cost and repeatability:**

| | ARGUS + learned rules | Dump to LLM |
|---|---|---|
| Model calls | 57, **once** (learning from run 1); triage then uses no model | 1 per window, **every capture**: 34 per pass |
| Model input | about 116k tokens, once | about 350k tokens per pass (about 10k per window) |
| Same input, same answer | **yes**: today's re-score reproduced every number | no: 3 of 34 windows changed verdict between seeds; run 1's cited events went from 347 to 1,004 |
| Evidence trail | the rule, its checks, and the exact events | the model's one-sentence reason; 2 cited event ids did not exist |

**Analyst workload:**

| | what the analyst does |
|---|---|
| Hand-written rules | Writes every rule. To cover what the learned rules cover, the analyst would read the 45 novel episodes from run 1 (461 events) and write the rules. The existing hand-written rules alone found 1/8 and 0/8 attack windows |
| ARGUS + learned rules | **Once:** decides on rules awaiting review. On run 1 that was 22 decisions after reading 90 alerts (simulated from design labels). **Per capture:** opens the flagged cases, each with its evidence: 9 on run 1, 7 on smoke |
| Dump to LLM | **Per capture, every time:** checks every flagged window, because the verdict carries no checkable evidence and changes between runs. 18 on run 1, citing 347–1,004 events, and 8–9 on smoke |

## What it shows

1. **False alarms.**
   - **On run 1** the dump flags 10 of 12 benign windows with both seeds. It judges each window
     alone, so the benign script's routine admin reads as an attack: `sudo cat /etc/shadow`,
     copying logs to `/tmp`, installing `sshpass`, SSH to peers. Its reasons say "credential
     dumping" and "exfiltration".
   - **ARGUS + learned rules flag 1 of 12.** The learned rules were checked against each host's
     own history (C4). Rules for exactly this routine activity were rejected or retired.
   - **This part is in-sample.** On smoke, both are near zero: 0/6 for ARGUS, 0/6 or 1/6 for
     the dump.
2. **The right verdict for the wrong reason.**
   - **The dump:** on smoke it flags all 8 attack windows, but in the four 12:30 windows it
     cites only the lab's own audit-log copy, a benign capture step. It misses every attack
     event in those windows (45, 45, 45 and 3).
   - **ARGUS + learned rules** flag 7 of 8, every one on genuine attack events.
   - **The dump also invented attribution.** It called CALDERA's agent "a known Cobalt Strike
     payload".
3. **Recall.**
   - **The dump finds more attack steps:** 22 against 12 of 68 on smoke, and 30–32 against 28 of
     36 on run 1. When it does see the attack, it cites every event of the agent's chain,
     whereas a rule selects only the events it describes.
   - **The learned rules are narrow.** Many name run 1's exact commands, the Q3 risk
     already noted in `LAB_RUN1.md` §8.
4. **Precision.** On smoke, 1.0 for the learned rules against 0.81–0.85 for the dump.
5. **Repeatability and cost.**
   - **The dump is not repeatable.** The same input with a different seed changed 3 of 34
     verdicts and tripled the cited events on run 1.
   - **The dump pays every time.** It costs about 10k tokens per window on every capture, for
     as long as it runs.
   - **ARGUS pays once.** The learned rules cost 57 calls once and then run with no model,
     identically every time.
6. **Hand-written rules alone are quiet but blind here.** They found 1 of 8 and 0 of 8 attack
   windows. The learned rules supplied the coverage without the analyst writing anything.
7. **Old ARGUS shows why amendments A1 and A2 were made.** It has high recall, but its novelty
   score, learned on Windows machines, flags 10/12 and 5/6 benign windows.

## Verdict

**Learned, checked rules beat dumping into an LLM** on five counts:
- false alarms (clearly on run 1, which is in-sample; equal on smoke);
- flagging on real evidence (7/8 against 4/8 on smoke);
- precision;
- repeatability;
- running cost.

They also beat hand-written rules on coverage, with far less analyst writing.

**Dumping into an LLM finds more attack steps** on the unseen operation.

None of this is test evidence. The numbers are small (one design operation and one excluded
smoke run) and run 1 favours ARGUS. The pre-registered test (Q1 and Q3, `LAB_EVAL_PLAN.md`)
decides.

## Reproduce

From the ARGUS root:
```
.venv/bin/python tools/eval_lab.py --operations run1 --out <dir>
.venv/bin/python tools/eval_lab.py --operations smoke --out <dir>
.venv/bin/python tools/llm_dump_lab.py --operations run1 smoke --repeats 2 --out <dir>
```
- **The dump replays from `.argus_cache/llm_dump` without a key.**
- **Old ARGUS** is the 8 October backup's `tools/eval_lab.py`, run on the same `cases_lab`
  windows. Its CITAR corpus and library come from the backup. Its outputs are in
  `old_argus_*.json` and `old_argus_*.log`.
