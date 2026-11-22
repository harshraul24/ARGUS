# ARGUS

**Coverage-aware, ad-hoc SOC triage of Linux intrusions, with LLM-written detection rules that
must pass label-free checks before they may decide anything.**

ARGUS (*Analyst Reasoning Graph for Unified SOC Triage*) decides whether activity on a Linux
host is an attack, from auditd, `auth.log` and Zeek telemetry. It decides while an incident is
still under way, on the evidence that has arrived so far, and revises as more arrives. It was
built for a Master of Cyber Security capstone (CYBR7902, The University of Queensland, 2026).

Three ideas set it apart:

- **Silence is qualified.** ARGUS knows what each sensor was configured to record. Missing
  evidence counts against an attack only if the sensor could have seen it. If the sensor was
  blind, missing, stopped, or its log was cleared, ARGUS reports a **blind spot** instead of
  reading the silence as innocence. This uses the *rebut / undercut / undermine* vocabulary of
  structured argumentation (ASPIC+).
- **The LLM is kept off the decision path.** A deterministic engine makes every decision. An
  LLM only *proposes* rules from process activity that is new to a host. A rule must pass five
  checks (C1–C5) before it may decide, and the model never sees labels.
- **Every claim records how much of it the attacker controls** (L0 kernel-recorded … L3
  attacker can suppress it), and evidence is discounted accordingly.

## Results so far

All numbers are **design data or diagnostics**. The pre-registered held-out test operations
have not been run yet. Learned-rule results on run 1 are in-sample, because the rules were
learned from it.

Pooled over all real telemetry with ground truth (47,173 events; 28 attack units, 78 benign
windows; `eval_runs/2026-11-16-coverage/`):

| | hand-written rules | + learned rules |
|---|---|---|
| attack units flagged | 10/28 | **24/28** |
| benign windows flagged | 1/78 | 1/78 |
| clean benign windows flagged | 0/50 | **0/50** |
| attack steps detected | 2/104 | **37/104** |

- **Unseen operation (smoke):** the learned rules flagged 7/8 attack windows and 0/6 benign
  windows at event precision 1.0, but found only 12/68 steps. Rules written from one operation
  generalise poorly; that is the open question the test operations measure.
- **Benign burn-in:** 0 of 60 windows flagged in either arm (34,401 events).
- **Comparison with sending each window to the same LLM** (8 October, 10-rule library;
  `docs/plan/LAB_COMPARISON.md`): the LLM flagged 10/12 benign windows on run 1, changed 3 of 34
  verdicts when re-run, and costs a model call per window. ARGUS made 57 model calls once, for
  learning.
- **Live:** in the first live run, ARGUS flagged each of four CALDERA agents within half a
  second of the agent's first recorded event.

Full results: [docs/TEST_RESULTS.md](docs/TEST_RESULTS.md). The 2026-11-16 changes are recorded
in the log of [docs/plan/LAB_EVAL_PLAN.md](docs/plan/LAB_EVAL_PLAN.md).

## Quick start

Python 3.11 or newer.

**macOS:** double-click `Setup ADGUS.command`, then `Start ADGUS.command` (the workbench opens
in your browser on port 8766).

**Any platform:**

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
cd "source code" && ../.venv/bin/python -m argus.cli ui --port 8766
```

In the workbench:
- **Cases:** the lab windows, ranked by priority, each with its verdict, blind spots,
  evidence, defeaters and process tree.
- **Rules:** the learned rule library, each rule with its C1–C5 record.
- **Coverage:** the blind spots across the triaged cases.

**Re-run the evaluation** (from the repo root; LLM calls replay from `.argus_cache/` without a
key):

```bash
.venv/bin/python tools/eval_lab.py --operations run1 --out out/run1
.venv/bin/python tools/eval_lab.py --operations smoke --out out/smoke
.venv/bin/python tools/eval_benign.py --operation burnin --out out/burnin
.venv/bin/python tools/eval_cumulative.py --out out/cumulative
.venv/bin/python tools/llm_dump_lab.py --operations run1 smoke --repeats 2 --out out/dump
```

**Tests:**

```bash
cd "source code" && ../.venv/bin/python -m pytest -q
```

90 tests run from this repository. 29 more need the raw lab captures, which are not included
(see [Data](#data)), and are skipped.

## How it works

```
victims ─stream─► log receiver ─► windows (post hoc) or live cases (ad hoc)
   ─► claims + control levels ─► process lineage, episodes ─► hypotheses
   ─► coverage-aware decision (verdict, defeaters, blind spots) ─► workbench
                         ▲
   LLM rule writer ─► checks C1–C5 ─► rule library (active rules decide)
```

| check | question |
|---|---|
| C1 valid | Can ARGUS run the rule as written? |
| C2 own evidence | Does it fire on its own episode, with values that occur there? |
| C3 robust | Does it still fire when programs are renamed or run by full path? |
| C4 quiet | Is it silent on at least 75% of its host's other windows? |
| C5 confirmed | Does a deciding hand-written rule, a quiet Sigma rule of level medium or higher, or the analyst agree? |

Architecture in detail: [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

## Repository layout

| path | contents |
|---|---|
| `source code/argus/` | the engine, collectors, live triage, rule learning, workbench |
| `source code/tests/` | the test suite (real lab captures only; nothing synthetic) |
| `tools/` | evaluation, rule learning from a terminal, Sigma import, capture conversion |
| `Test Setup/lab/` | the lab: victim builder, personas, log forwarding and receiver, campaign notes |
| `cases_lab/` | the converted lab windows (run 1, smoke, burn-in) with labels |
| `cases_linux/`, `cases_benign/` | the earlier Linux attack captures, and script-generated benign cases (not used in results) |
| `eval_runs/` | every result, by date; `lab_library.json` is the installed rule library |
| `.argus_cache/` | cached LLM calls, so learning and the LLM baseline replay without a key |
| `intel/snapshots/lab/` | the converted Sigma rules and behaviour vocabulary used by ARGUS |
| `ARGUS_FREEZE_*.json` | freeze manifests: the SHA-256 of every source file a result used |
| `lab_split.json` | design/test split, by capture order |
| `docs/` | architecture, results, evaluation plan and amendments, lab notes, bibliography |

## Data

- **Included:**
  - the converted lab windows (`cases_lab/`), which are all the evaluation reads;
  - the CALDERA reports needed for labels;
  - every result file.
- **Not included:**
  - the raw captures (`Test Setup/lab/captured/<run>/<host>/audit.log`, `auth.log`, packet
    captures), about 130 MB;
  - the victims' disk images;
  - the full intelligence sources (SigmaHQ, GTFOBins, MITRE ATT&CK).

  `tools/intel_snapshot.py` rebuilds the intelligence snapshot from the commits pinned in
  `intel/snapshots/lab/MANIFEST.json`.
- **All telemetry is from an isolated lab.** The victims are local virtual machines attacked
  by MITRE CALDERA's own published abilities. Users, hosts and addresses are lab-internal.
  The lab's login password has been replaced by a placeholder in the published windows and
  scripts (`make-victim.sh` reads it from `LAB_PASSWORD`), and ARGUS redacts passwords in
  command lines before reasoning over them.

## Evaluation integrity

- **Pre-registered.** The evaluation plan, its questions and its split were written on
  6 October 2026, before any design capture. Every change since is a dated amendment (A1–A4)
  or a log entry.
- **Frozen code.** Every result names a freeze manifest, and the evaluation tools report
  whether the current code matches it.
- **Labels kept apart.** Ground truth comes only from the CALDERA operation report and is
  never read by triage.

## Safety

ARGUS is a defensive, decision-support tool. The lab scripts start CALDERA agents and benign
user personas on virtual machines you build yourself; run them only on an isolated network you
control. ARGUS takes no containment actions, and model API keys are typed per run and never
stored.

## Credits

- **SigmaHQ rules** (Detection Rule License 1.1). ARGUS's converted rules and behaviour
  vocabulary are derived from them; the source commit is pinned in
  `intel/snapshots/lab/MANIFEST.json`.
- **GTFOBins** (GPL-3.0).
- **MITRE ATT&CK®** and **MITRE CALDERA™**, trademarks of The MITRE Corporation.
- **Theory:**
  - Modgil & Prakken, *The ASPIC+ framework for structured argumentation* (2014);
  - Dung (1995);
  - Reiter (1987);
  - Jøsang (2001).

  See [docs/BIBLIOGRAPHY.md](docs/BIBLIOGRAPHY.md).

Author: Harsh Rajesh Raul.

## License

MIT, for this project's own code, data and documentation. The Sigma-derived rules and
vocabulary keep their own licences (DRL 1.1, GPL-3.0); see [LICENSE](LICENSE) and [NOTICE](NOTICE).
