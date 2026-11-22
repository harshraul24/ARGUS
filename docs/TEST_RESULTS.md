# ARGUS: every test run so far (except the retired CITAR work)

*Compiled 21 October 2026. Every number comes from a file in `results/` (named in each section)
or from the project's reports. The Windows/CITAR evaluation is excluded: amendment A1 removed
it from the thesis's scope.*

**Status.** All results are **design data or diagnostics**. The pre-registered test operations
have not run, so nothing here is a test result.

---

## 0. At a glance

| # | test | date | data | headline |
|---|---|---|---|---|
| 1 | Software test suite | ongoing | real lab captures only | **110 tests pass** |
| 2 | Smoke capture | 6 Oct | 14 windows, pipeline check | old ARGUS: 7/8 attack, but **5/6 benign** flagged (novelty alone) |
| 3 | Run 1, three stages | 7–8 Oct | 20 windows, design 1 | hand rules 1/8 attack → **learned rules 8/8, 1/12 benign, 28/36 steps** |
| 4 | Rule learning (S3 on Linux) | 8 Oct | run 1 | 57 model calls; 42 rules written; **10 active** after merging duplicates |
| 5 | Learned rules on an unseen operation | 8 Oct | smoke | **7/8 attack, 0/6 benign, precision 1.0**, but 12/68 steps |
| 6 | Four-way comparison | 8 Oct | run 1 + smoke | learned rules beat dump-to-LLM on false alarms, evidence, precision, repeatability and cost |
| 7 | Rule checks made consistent (A3) | 14 Oct | run 1 replay | same 10 active rules, detection unchanged |
| 8 | Burn-in: benign only | 15 Oct | 60 windows, 4 hosts | **0 of 42 clean windows flagged**, both arms |
| 9 | Run 2 (partial) | 15–21 Oct | app01 only | capture incomplete; not imported; to recapture |
| 10 | Ad-hoc live run (adhoc1) | 21 Oct | live, 4 hosts | **all 4 agents flagged within 0.5 s** of their first event |
| 11 | **Everything pooled into one test** | 21 Oct | 94 lab windows + 12 earlier attack captures | learned rules: **24/28 attack units, 4/78 benign windows (0/50 clean), 40/104 steps** |

---

## 1. Software test suite

- **110 tests pass** (`ADGUS/source code/tests`, 17 files), all on real lab captures, with no
  synthetic telemetry.
- **They cover:**
  - the converter and the capture gate;
  - lineage and the engine;
  - rules and checks C1–C5;
  - learning, feedback and Sigma import;
  - the workbench (import, learning, review);
  - the live engine;
  - the log receiver;
  - the dump-to-LLM baseline;
  - that the API key is never stored.
- **History:** 102 tests at the end of the CITAR work (1 Oct), 83 after the Linux-only cut,
  110 today.

## 2. Smoke capture (6 Oct; pipeline check, excluded from design and test)

The ARGUS of that day, before any lab fix:

| attack windows | benign windows | steps | event precision |
|---|---|---|---|
| 7/8 | **5/6** | 59/60 | 0.11 |

Re-scored on 8 October with the corrected labels, which add the agent's deployment and
bootstrap steps (`results/2026-10-08-comparison/old_argus_smoke.*`): 7/8, 5/6, 64/68 steps,
precision 0.11.

Every detection came from novelty alone, with a baseline learned on other machines. This was
the evidence for fixes F1 (per-host baselines) and F2 (novelty never decides alone).

## 3. Run 1: the first design operation (`results/2026-10-08-lab-run1*`)

- **The lab:** 4 victims and 20 windows, 8 of them attack; 11 pass the capture gate.
- **The attack:** discovery only. The chain stalled on a FreeBSD ability that needed `sudo`.

| | Linux-only ARGUS | after A2 (hand-written floor) | + learned rules |
|---|---|---|---|
| attack windows flagged | 8/8 | 1/8 | **8/8** |
| benign windows flagged | 7/12 | 1/12 (gate-pass 0/3) | **1/12** (gate-pass 0/3) |
| attack steps detected | 8/32 | 2/36 | **28/36** (95% CI 0.62–0.88) |
| event precision | 0.007 | 0.010 | 0.135 overall; **learned rules 1.0** |

- **The step count grew from 32 to 36** when A2 began labelling the agent's deployment as
  attack activity.
- **A2's precision fix** made weak primitives context-only, so they never decide alone. It
  moved benign flags from 7/12 to 1/12, but the hand-written layer could then not see this
  attack. That gap is what the learned rules close.
- **Not evidence of generalisation:** the model saw these windows, and approval was simulated
  from their labels.

## 4. Rule learning on run 1 (`results/2026-10-08-lab-induce`)

- **Model and cost:** `gpt-oss:120b-cloud`, 57 calls, 0 errors, about 116k tokens in.
- **Volume:** 45 novel episodes produced 42 rule attempts.
- **Outcome:**
  - 14 were repaired;
  - 3 were rejected by C4 (they fired on 50–100% of the host's history);
  - 2 were retired by the simulated analyst (the lab's log pull and routine `/etc/shadow`
    reads);
  - 20 became active, and **10 remain after merging duplicates**.

| rule set (design data) | rules | attack windows | benign windows | steps | event precision |
|---|---|---|---|---|---|
| C1–C3 survivors | 28 | 8/8 | 12/12 | 28/36 | 0.26 |
| C1–C4 (shadow + active) | 25 | 8/8 | 9/12 | 28/36 | 0.59 |
| **C1–C5 active** | 20 | 8/8 | **0/12** | 28/36 | **1.0** |

Each check removed noise without losing a step.

## 5. Learned rules on an unseen operation (smoke)

| | hand-written rules | + learned rules |
|---|---|---|
| attack windows | 0/8 | **7/8** |
| benign windows | 0/6 | **0/6** |
| steps | 0/68 | 12/68 |
| event precision | — | **1.0** |

Precision carried over and recall did not: many rules name run 1's exact commands. This is
the generalisation risk (Q3) the test operations are designed to measure.

## 6. Four-way comparison (`results/2026-10-08-comparison`, `10_COMPARISON_REPORT.md`)

Same windows and same model. The dump arm sends the LLM each window's events and process tree
and asks for a verdict, two runs with different seeds.

| | old ARGUS | hand-written | **ARGUS + learned** | dump to LLM |
|---|---|---|---|---|
| run 1: benign flagged | 10/12 | 1/12 | **1/12** | 10/12 both seeds |
| run 1: steps | 30/36 | 2/36 | 28/36 | 30–32/36 |
| smoke: attack flagged on real attack evidence | 7/8 | 0/8 | **7/8** | 4/8 |
| smoke: benign flagged | 5/6 | 0/6 | **0/6** | 0/6, then 1/6 |
| smoke: steps | 64/68 | 0/68 | 12/68 | 22/68 |
| smoke: event precision | 0.11 | — | **1.0** | 0.81–0.85 |
| model calls | 0 | 0 | 57, once | 1 per window, every capture |
| same answer twice | yes | yes | yes | no: 3 of 34 verdicts changed |

**What the comparison shows:**
- **The dump calls the lab's routine admin an attack** (`sudo` reads, log copies, `sshpass`
  installs) because it judges each window alone.
- **The dump is sometimes right for the wrong reason.** On smoke it flagged 4 attack windows
  only for the lab's own log copy, and once named CALDERA's agent "Cobalt Strike".
- **The dump does find more steps** on the unseen operation.
- **Old ARGUS** flags most benign windows from a novelty score learned on Windows machines.
  That is why amendments A1 and A2 were made.

## 7. The rule checks made consistent (A3, 14 Oct)

- **What changed:**
  - one definition per check;
  - status always follows the check record;
  - an analyst's approval is recorded as the C5 pass;
  - only sources that may decide can confirm, each quiet by C4's bar.
- **Replay of run 1's learning from cache** (57 of 57 calls): the same 42 rules and the **same
  10 active rules**.
- **Detection unchanged:**
  - run 1: 8/8 attack, 1/12 benign, 28/36 steps;
  - smoke: 7/8, 0/6, 12/68.
- **The three `ip neighbour` rules** were previously confirmed by the discovery primitive.
  They now wait for analyst review.

## 8. Burn-in: benign only (`results/2026-10-15-burnin`, `tools/eval_benign.py`)

- **The data:** 60 windows (app01 24, web01 23, ws-dev01 6, ws-fin01 7), 34,401 events, no
  CALDERA agent present.
- **What the personas did:** 2,624 discovery-style surveys, 217 downloads, 217 port-check
  look-alikes, 54 archives, 27 history clears and 27 mistyped logins.

| | all 60 windows | 42 clean windows (no protocol activity) |
|---|---|---|
| hand-written rules | **0 flagged** | **0** |
| + learned rules | 3 flagged | **0** |

- **The 3 flags** are app01's and web01's last windows: the experimenter's log pull and the
  `ip addr show` run right after a reboot. They come from two learned rules that are too broad
  (any `sudo … cat`; any `ip … show`).
- **No look-alike action caused a flag.**
- **Context primitives fired constantly and decided nothing:** discovery in 59/60 windows,
  beacon in 51.
- **Found and fixed:**
  - audit serials restart at each boot, which made the converter merge about 700 events per
    rebooted host;
  - the capture gate didn't recognise the campaign's protocol commands.

  Both are now fixed, and run 1's decisions are unchanged.
- **Known limits:**
  - ws-dev01 and ws-fin01 recorded only 2–2.7 hours;
  - no network capture;
  - auditd restarts and reboot gaps are **not yet reported as blind spots** (prerequisite P3).

## 9. Run 2: partial, not part of the evaluation

- **The capture:** the end-of-run SSH pull fetched only app01's audit log. Only 10 of 37
  CALDERA steps could be matched to a process.
- **Not imported:** run 2 would have been permanently recorded as design 2 with 3 of 4 hosts
  missing.
- **Scored on app01 alone, as a diagnostic:**

| app01 only | hand-written | + learned |
|---|---|---|
| attack windows | 1/2 | 2/2 |
| benign windows | 0/25 | 2/25 |
| steps | 1/10 | 3/10 |

The same two broad rules raised the false alarms, one of them on a clean window.

**Consequence:** log collection was replaced. Victims now stream their logs to the Mac as they
are written (`forward-logs.sh`, `log_receiver.py --check`), and run 2 will be recaptured.

## 10. Ad-hoc live run: adhoc1 (`results/2026-10-21-adhoc1`)

- **The setup:** the live engine (`argus/live`) triaged logs streamed from the four victims
  while CALDERA ran `ad-hoc-test-1`. The snapshot was taken at 02:44:38 UTC, before a later
  server restart.
- **Scale:** 251 cases decided across the four hosts, **12 flagged malicious**, 3 per host.

| host | agent's process tree | flagged at its first event + | discovery cases flagged |
|---|---|---|---|
| web01 | malicious, severity 0.80 | 0.36 s | 2 (severity 0.51) |
| ws-dev01 | malicious, severity 0.80 | 0.16 s | 2 |
| ws-fin01 | malicious, severity 0.80 | 0.34 s | 2 |
| app01 | malicious, severity 0.80 | 0.50 s | 2 |

- **Each agent was flagged within half a second of its first event,** about a minute before
  the operation's first step (02:28:34 UTC). It was flagged as a user-writable program
  connecting out.
- **The discovery steps raised their own cases** within about a second of running.
- **Caveats:**
  - the 239 unflagged cases have **not yet been graded against labels**;
  - abilities that ran inside an agent's already-flagged tree are not counted separately;
  - this run is not the planned ad-hoc test (`08_ADHOC_TEST_PLAN.md`), whose measures T1–T8 are
    still to be produced.


## 11. Everything pooled into one test (`results/2026-10-21-cumulative`, `tools/eval_cumulative.py`)

**What ARGUS has been tested on:**
- **47,173 events** in total:
  - 44,950 in 94 lab windows (run 1 8,818, smoke 1,731, burn-in 34,401);
  - 2,223 in the live run.
- **1,162 claims** from the 12 earlier real Linux attack captures (`cases_linux`).
- **Not counted:** the 172 claims of `cases_benign`, which were generated by a script and are
  not real; run 2's partial capture, which is not stored as cases; and CITAR.

All real data with ground truth, pooled and scored by the same code:

| | hand-written rules | + learned rules |
|---|---|---|
| attack windows flagged (lab) | 1/16 | **15/16** |
| earlier attack captures flagged | 9/12 | 9/12 |
| **all attack units flagged** | 10/28 | **24/28** |
| benign windows flagged | 1/78 | 4/78 |
| benign windows flagged, clean windows only | **0/50** | **0/50** |
| benign windows per 20 host-windows | 0.26 | 1.03 |
| attack steps detected | 2/104 | **40/104** (95% CI 0.30–0.48) |
| event precision | 0.01 | 0.17 |

**Reading it:**
- **The learned rules lift detection** from 10 to 24 of 28 attack units, and from 2 to 40 of
  104 steps.
- **No clean benign window is flagged in either arm.** The 4 benign flags are protocol windows
  (the experimenter's log pull and reboot) plus run 1's kill chain on the benign script.
- **The false-alarm rate across all benign windows** (1.03 per 20) sits just above the plan's
  bar of 1. It drops to 0 on clean windows.
- **Run 1 is in-sample** for the learned rules (28 of its 36 steps). On the unseen smoke
  operation they find 12 of 68.
- **The earlier attack captures need network and identity evidence** (brute force, exploited
  services) that the hand-written rules cover. Learned rules add nothing there.
- **Computed on the current code,** which includes the live engine added after the last freeze.
  The per-capture numbers are identical to the frozen results in §3, §5 and §8.

### 11.1 Scored per event (`results/2026-10-22-events`, `tools/eval_events.py`)

The same 94 lab windows, with each event as one unit. Positive = an event CALDERA's labels
mark malicious; flagged = an event an alerting rule selected. Burn-in events are all benign.

| | hand-written rules | + learned rules |
|---|---|---|
| **Run 1** (design, in-sample; 8,818 events, 93 attack) | | |
| precision | 0.01 | 0.13 |
| recall | 0.03 | **0.49** (95% CI 0.40–0.59) |
| F1 | 0.02 | 0.21 |
| normal events flagged (FPR) | 3.4% | 3.4% |
| **Smoke** (unseen; 1,731 events, 208 attack) | | |
| precision | – (nothing flagged) | **1.00** (16/16; CI 0.81–1.00) |
| recall | 0.00 | 0.077 (CI 0.05–0.12) |
| F1 | – | 0.14 |
| normal events flagged | 0/1,523 | **0/1,523** |
| **Burn-in** (benign only; 34,401 events) | | |
| normal events flagged | 0 | 11 (0.03%), all in protocol windows |
| clean windows only (23,622 events) | 0 | **0** (95% upper bound 0.02%) |
| **Pooled** (44,950 events, 301 attack) | | |
| precision / recall / F1 | 0.01 / 0.01 / 0.01 | 0.17 / 0.21 / 0.19 |
| normal events flagged | 0.66% | 0.69% |

- **All 295 false-positive events in run 1 come from one hand-written rule** (KILLCHAIN, two
  ws-fin01 windows). The learned rules add 43 correct events there and no wrong ones.
- **Dump to LLM** (§6, same scoring, seeds 7 / 8): on smoke, precision 0.85 / 0.81, recall
  0.34 / 0.34, F1 0.48 / 0.48, normal events flagged 0.8% / 1.1%. On run 1, normal events
  flagged 3.1% / 10.7%: the two reruns disagree.
- **Old ARGUS** (before fixes) on run 1: recall 0.62, precision 0.008, normal events flagged 78%.

---

## 12. Not tested yet

- **The test operations themselves** (Q1–Q3, and Q4 timeliness), scored once after the final
  freeze.
- **Log clearing, seen two ways (Q2):** needs prerequisites P3 (log-tampering reasoning) and P4
  (two views).
- **Brute force and port scan in lab windows:** need `auth.log` and Zeek ingested (P1, P2).
- **Cross-host stories (P8), clock health (P6) and per-host baselines (P7).**
- **Design runs 2 and 3,** to be captured with log streaming.

## 13. Integrity

- **Every result names its frozen code:** `ARGUS_FREEZE_*.json` holds the hash of every source
  file.
- **Model calls are cached** and replay without a key.
- **Tests and evaluations use real captures only.**
- **Changes to the plan are dated amendments,** each made before any test operation existed:
  A1 Linux-only, A2 precision, A3 checks, A4 ad hoc.
