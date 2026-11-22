# Lab evaluation plan — pre-registered (2026-10-06)

**Status:** fixed before any design or test capture exists. The smoke capture
(`cases_lab/smoke_*`, 2026-10-06) is a pipeline check only: it is excluded from design and
test, and nothing in ARGUS was changed because of it.

**Reference freeze:** `ARGUS_FREEZE_2026-10-08-a2.json` (aggregate `e90472c9de76097c`),
replacing `ARGUS_FREEZE_2026-10-06-lab.json` by amendments A1 and A2 (below). Every change allowed in
§4 produces a new, dated freeze. The test (§6) runs against exactly one of them, named in
the result.

**Scope (amendment A1, 2026-10-08):** ARGUS is Linux-only. The Windows/CITAR work is not
part of the thesis evaluation.

---

## 1. Questions

1. **Q1 — learned rules.** On Linux hosts, does ARGUS with rules its LLM loop wrote from the
   design operations (S3) detect multi-host attacks in the test operations without false
   alarms, beyond what its hand-written reasoning finds alone?
2. **Q2 — log deletion.** When an attacker clears logs on a victim:
   - does ARGUS report the blind spot (local-only view);
   - and still find the attack when a forwarded copy exists (forwarded view)?
3. **Q3 — generalisation.** Do rules learned on design operations fire on test operations
   that use different adversary profiles and different victims?

## 2. Corpus

- **Estate:** the multi-victim lab (`LAB_MULTI_VICTIM.md`). Each host has its own role,
  users and software.
- **Sensors per victim:** auditd (execve + network connect + writes to sensitive paths) or
  Sysmon for Linux, `auth.log`, forwarded copies on Kali. Plus a network capture on the
  host-only bridge.
- **Windows:** fixed 30-minute grid per host, aligned to the hour, decided without labels.
  Converter: `argus/collectors/lab_capture.py`, run from the workbench's Import capture sheet or
  `tools/apt_capture/auditd_to_windows.py`.
- **Ground truth:** the CALDERA operation report only. A step's process plus its
  descendants is malicious, and so is the agent's process tree. Hosts are matched by host,
  PID and time, with each host's measured clock offset corrected for.

**Capture validity gates.** A run that fails one is re-captured, never patched:
- every victim's clock is within 5 s of Kali (measured offset recorded in the metadata);
- every step in the report matches a process (as the smoke test did: 60/60);
- no collection or admin activity inside a window being scored;
- every sensor present in every window. A missing sensor is recorded, never silently
  absent.

## 3. Split (fixed now)

| set | contents | what may use it |
|---|---|---|
| **burn-in** | the first ≥ 10 windows per host, benign only | each host's history and baseline (label-free) |
| **design** | **the first 3 CALDERA operations**, and the benign windows of their days | rule writing (S3), analyst feedback (simulated from design labels), fixes in §4 |
| **test** | **every operation after the third**: at least 4, which must include at least 2 adversary profiles **not used in design**, at least 1 victim set different from design, and at least 2 log-clearing operations; plus every benign window of the test days | scored **once**, after the final freeze |

The adversary profile and victim set of each operation are written to its capture manifest
**before** it runs. An operation is assigned to design or test by its order alone, never by
its result.

## 4. Changes allowed during design (and only then)

ARGUS may change only within these items, using only burn-in and design data. Each change
is made, measured on design data, and written up before the next.

| # | change | why (evidence) |
|---|---|---|
| F1 | **Per-host novelty with warm-up.** Each host's baseline is learned from its own burn-in, label-free. A host without enough history yields "insufficient history" (abstain), never an alert | smoke test: a baseline from other machines flagged 5/6 benign windows; P3's baseline was chosen with labels |
| F2 | **Novelty never decides alone.** Novelty raises priority and scope; a malicious/suspicious disposition needs a behaviour indicator as well | smoke test: every detected step came from novelty alone (precision 0.11) |
| F3 | **OS-aware behaviour vocabulary.** Command decomposition maps Linux and Windows commands to the same behaviour categories (account discovery, process discovery, archive, transfer, log tampering…), so one rule describes a behaviour, not a platform's spelling. Mechanism built 2026-10-07 from Sigma tactic tags (`behaviour.tactics`, `INTEL.md`), off by default; its use in rules is decided on design data | smoke test: `whoami`, `ps`, `cut /etc/passwd` matched nothing; S3: rules key on spellings |
| F4 | **Whole-word token matching** in `contains_any` | open since S1 (`"ver "` matched inside other words) |
| F5 | **Sensor contracts and time health.** Each sensor declares what it records; a missing type is a blind spot. A clock offset to the estate above a threshold is a reported sensor defect | smoke test: auditd recorded only execve; ws-fin01 was 17.5 min off |
| F6 | **Log-tampering reasoning on Linux.** Truncation or deletion of a log, audit rules removed or the audit daemon stopped invalidate that host's evidence before that time (the engine's `invalidated_before`) | Q2 |
| F7 | **Cross-host linking.** One estate episode links per-host episodes through logons and connections between victims, so lateral movement is one story, not several | multi-victim corpus; ARGUS windows are per host |
| F8 | **S3 loop on Linux design episodes.** Rules are confirmed by a hand-written rule, by analyst approval (simulated from design labels), or by a Sigma rule from the `lab` snapshot that is itself quiet in history (C4) **and rated `level >= medium`**. The level filter was added on 2026-10-07, after CITAR design data showed both false Sigma confirmations came from `low` rules (`INTEL.md` step 3); this lab test is its first clean evaluation | Q1, Q3 |

**Not allowed:** thresholds tuned to test results; rules or tokens copied from test
operations; re-splitting after seeing results.

## 5. Arms (all frozen before the test)

| arm | what it is |
|---|---|
| `argus_lab_ref` | ARGUS at the reference freeze (`ARGUS_FREEZE_2026-10-08-a2.json`), unchanged (the floor) |
| `argus_f1_f7` | ARGUS with the design fixes, no LLM rules |
| `argus_f1_f7_s3` | + the LLM rule library learned on design (active rules), shadow measured |
| `argus_f1_f7_s3_forwarded` / `_local` | log-clearing operations, scored from the forwarded copy and from the victims' own logs |

## 6. Metrics (computed once on test)

- **Primary:**
  - attack steps detected, with 95% Wilson intervals;
  - benign windows flagged (false-alarm rate per host-day);
  - event precision.
- **Q2:** for each log-clearing operation, whether the local view reports a blind spot
  covering the cleared interval, and the steps detected in each view.
- **Q3:** steps detected by LLM rules on test operations whose profile was not used in
  design.
- **Also reported:**
  - steps found by cross-host episodes (F7);
  - undecidable windows;
  - per-check rule survival;
  - model calls and cost;
  - every rejected and shadow rule's test precision (what the checks cost).

**Success is stated now:** `argus_f1_f7_s3` beats `argus_lab_ref` on test steps detected,
with benign windows flagged no higher than 1 per 20 host-windows. Anything else is
reported as it is.

## 7. Integrity

- Every test result names its freeze and the sha256 of its rule library.
- Test windows are scored by one command, once; a rerun must reproduce it exactly.
- All model calls are cached and replayable without a key.
- Deviations from this plan are listed in the result, with the reason.

---

## Log

| date | operation | set (by order) | notes |
|---|---|---|---|
| 2026-10-07 | run 1 (CALDERA `test2`, 4 victims) | design 1 | discovery only; the chain stalled on a sudo prompt; 9/20 windows fail the admin/collection gate (recorded, not dropped). `LAB_RUN1.md` |
| 2026-10-08 | — | — | amendment A1 (Linux-only scope) recorded below; run 1 re-scored at the new reference freeze: `eval_runs/2026-10-08-lab-run1/` |
| 2026-10-08 | — | — | amendment A2 (precision) recorded below; run 1 re-scored: `eval_runs/2026-10-08-lab-run1-a2/` |
| 2026-10-08 | run 1 | design 1 | S3 rules learned (`eval_runs/2026-10-08-lab-induce/`); duplicates merged label-free, 20 → 10 active (`ARGUS_FREEZE_2026-10-08-dedupe.json`); detection on run 1 unchanged |
| 2026-10-08 | — | — | rule learning moved into the workbench (`argus/rules/learn.py`, shared with `tools/rules_induce.py`, which replays the run-1 library exactly); analyst approve/retire in the page (`ARGUS_FREEZE_2026-10-08-ui-learn.json`); no detection change |
| 2026-10-08 | — | — | capture import moved into the workbench: the converter is now `argus/collectors/lab_capture.py` (run 1 reconverts to the same windows; only lineage key order was hash-seed dependent and is now sorted); an import with a CALDERA report appends the run to `lab_split.json` before converting it, so its role follows from capture order alone (`ARGUS_FREEZE_2026-10-08-import.json`); no detection change |
| 2026-10-08 | run 1, smoke | design 1, excluded | diagnostic comparison, not a test: old ARGUS, hand-written rules, ARGUS + learned rules and dump-to-LLM (`tools/llm_dump_lab.py`, same model, 2 seeds) on the same windows (`LAB_COMPARISON.md`, `eval_runs/2026-10-08-comparison/`); no test operation used, nothing in ARGUS changed |
| 2026-10-14 | — | — | amendment A3 (one definition for each rule check) recorded below; run 1's learning replayed from cache: the same 10 active rules, detection on run 1 and smoke unchanged (`ARGUS_FREEZE_2026-10-14-checks.json`) |
| 2026-10-14 | — | — | capture campaign for the rest of the plan written before any of its captures: burn-in, design 2–3, tests 1–4, the scopes each exercises and prerequisites P1–P11 (`LAB_TEST_SUITE.md`); adds to this plan, changes nothing in it |
| 2026-10-15 | burn-in | history (triage only) | 60 benign windows (app01 24, web01 23, ws-dev01 6, ws-fin01 7); hand-written ARGUS flags 0/60, with learned rules 3/60, all 3 in protocol windows (log pull, reboot); 0/42 gate-pass windows flagged in either arm (`eval_runs/2026-10-15-burnin/`, `tools/eval_benign.py`). Converter fixes found on it: audit events grouped by time and serial (serials restart at boot), and the gate recognises the campaign's protocol commands (`ARGUS_FREEZE_2026-10-15-burnin.json`); run 1's decisions unchanged |
| 2026-10-21 | run 2 | — (not imported) | the SSH pull fetched only app01's audit log (3 of 4 hosts missing), so run 2 is not imported and will be recaptured. Log collection replaced: victims stream their logs to the Mac as they are written (`Test Setup/lab/forward-logs.sh`, `log_receiver.py`, with a completeness `--check`); no change to ARGUS |
| 2026-10-21 | — | — | amendment A4 (ad-hoc triage) recorded below, before any test operation: adds Q4 and an ad-hoc scoring of every run beside the post-hoc one; test plan `LAB_ADHOC_TEST.md`; thesis reframed (`THESIS.md`); no change to Q1–Q3, the split or the post-hoc criterion |
| 2026-11-16 | — | — | design-phase fixes before the freeze, no test operation used (`ARGUS_FREEZE_2026-11-16-coverage.json`, `eval_runs/2026-11-16-coverage/`). **Coverage (F5, part of F6):** a sensor a hypothesis expects but that is not in the capture (no `auth.log`, no Zeek logs, or no health record) is an undercut and a blind spot, where it was read as a working sensor and rebutted; intervals in which the audit daemon was stopped or an audit rule was unloaded are read from the audit log itself and reported as blind spots per window and per live case (`meta.sensor_gaps`, added to existing windows by `tools/sensor_gaps.py` without touching their events). 37 of 94 lab windows now carry such a blind spot (burn-in 33: the hourly sub-second restarts and the two 7-minute reboots); **no disposition changes on any existing case in either arm**. Log clearing (`invalidated_before`) is still not set by any collector. **Rule library:** the analyst retired two over-broad active rules on burn-in evidence (any `sudo … cat`; any `ip … show`): a burn-in holds no attack, so its alerts are false without any label. 10 → 8 active rules (the 8 October library is kept as `eval_runs/lab_library_2026-10-08.json`). With learned rules: burn-in 3/60 → **0/60** flagged; run 1 8/8 attack, 1/12 benign, steps 28/36 → **25/36**; smoke unchanged (7/8, 0/6, 12/68, precision 1.0); pooled benign 4/78 → **1/78** (0.26 per 20 host-windows), attack units 24/28, steps 40/104 → 37/104 |

## Amendment A1 — Linux-only scope (2026-10-08, before any test operation)

Made before any test operation exists, so no test result can have informed it.

- **Removed.**
  - The Windows collectors, the Windows command decomposer, PowerShell canonicalisation and
    Windows principal weighting.
  - The LLM command proposer, the Odin rule converter, the CITAR corpus, its results and
    the CITAR-learned rule library, and the Windows intelligence sources (LOLBAS, the
    `citar` snapshot).
  - Every hand-written Windows/SMB technique rule, the Windows command-list LOLBin primitive,
    and the T1041 sensitive-file command signature (command rules are the S3 loop's job).

  Backup: `ARGUS_backup_2026-10-08_pre-linux-only.tar.gz` beside the ARGUS folder.
- **Kept, hand-written.**
  - T1110 brute force (auth.log), T1046 port scan and T1210 exploited service (Zeek). These
    are network and identity shapes that a process-tree episode cannot teach the LLM.
  - The kill chain, and novelty. Novelty has no baseline until F1.
  - Discovery, staging, exfiltration and beacon primitives, re-keyed on the Linux behaviour
    vocabulary (F3) and on sensor-measured network facts. No hand-written command lists.
- **F3** is now in use by those primitives. Vocabulary: the `lab` snapshot's Linux Sigma tags,
  shipped in `argus/normalize/behaviour_vocab.json`.
- **F5, sensor-contract half, done.** Each lab window declares the types its sensor was
  configured to record, from the audit rules the host had loaded (`sensor_contract`). A
  contracted type with no events is a blind spot. The clock-health half is still open.
- **F8.** `tools/rules_induce.py` reads only the design operations in `lab_split.json`, with
  C4 on each host's own other windows. C5 accepts a hand-written primitive, or a `lab`
  Sigma rule rated `level >= medium` that is itself quiet in history. Agreement between LLM
  rules is recorded, never promotes.
- **Split file.** `lab_split.json` lists operations in capture order. The first three are
  design, every later one test.
- **Known effect on the earlier Linux captures (`cases_linux`).**
  - `apt_ssh_bruteforce_001` is no longer flagged malicious: it was caught only by the
    removed T1041 signature.
  - The other detections there are unchanged.

## Amendment A2 — precision of the hand-written layer (2026-10-08, design data only)

Made from design operation 1 (run 1; `LAB_RUN1.md`), before any test operation. No
threshold was changed. Each item is a definition that holds on any Linux host:

1. **Beacons and exfiltration count only sessions that leave the host:** not loopback, not
   the unspecified address, not a port-0 `connect()` (a UDP route lookup, which opens no
   session).
   - Evidence: 8 of the 12 run 1 beacon alerts were the benign script's `curl` to
     localhost; 2 more were `sudo` and `sshd` non-sessions.
2. **A session hub is judged over its recorded life.** The lineage map records each
   process's distinct child programs up to the window's end. A login shell that launched
   many programs is a hub even in a window where it launched two.
   - Evidence: on run 1's 13:30 windows the kill chain fused the agent's steps with the
     benign script under the login shell that started both.
3. **Weak primitives never decide alone.** Discovery, staging, exfiltration, beacon and
   novelty are reported as context and still count as kill-chain stages. Deciding are: the
   kill chain, T1110, T1046, T1210, and active learned rules. This generalises F2 to every
   primitive the code itself calls "individually only suspicious".
4. **Labels: the agent's deployment is attack activity.** The commands its parent ran in
   the two minutes before launching it that name its file or its CALDERA server (download,
   `chmod`, launch) are labelled malicious, as a separate "Agent deployment" step. The
   earlier convention (only the agent's own tree) labelled the download benign.
5. **F8's analyst path is wired.** `tools/rules_induce.py` simulates the analyst on design
   data from the design labels: every alert of a shadow rule is reviewed, approval on
   complete review.

**Effect on run 1 (design data):**

| | before A2 | after A2 |
|---|---|---|
| benign windows flagged | 7/12 | 1/12 |
| benign windows flagged (gate-pass) | 1/3 | 0/3 |
| attack windows flagged | 8/8 | 1/8 |
| attack steps detected | 8/32 | 2/36 |

Notes on the "after" numbers:
- **The remaining benign alarm** (ws-fin01, 13:00) is the benign script itself: it surveys
  the host and SSHes to a peer on a loop. Only a per-host history (F1, burn-in) can tell
  that from reconnaissance.
- **Recall is low, as intended.** The hand-written layer alone no longer pretends to detect
  this discovery-only attack. Detection is meant to come from learned rules (Q1).

## Amendment A3 — one definition for each rule check (2026-10-14, design data only)

Made before any test operation, from inspecting the checks' records on run 1. Nothing was
tuned: one threshold (C4's 25%) now means the same thing everywhere.

1. **The five checks are defined once** (`argus/rules/checks.py`: C1 valid, C2 own evidence,
   C3 robust, C4 quiet, C5 confirmed). The code, the library's records, the workbench and
   the documents use those names. Libraries written earlier are read in this form, their
   statuses unchanged.
2. **Checks run in order and record only what they reached.** A check that could not run is
   "not reached", not failed: C3 when a rule never fires, C5 when C4 failed.
3. **The status follows the record.** A rule becomes shadow only with C1–C4 passed and active
   only with C5 passed; the library refuses anything else. An analyst's approval is a C5
   pass and is recorded as one. Before A3, 9 of the 10 active run-1 rules showed C5 as
   failed while being active by approval.
4. **C5 confirms only with a source that may decide on its own, held to C4's bar.**
   - Confirmers are the hand-written rules that decide (kill chain, T1110, T1046, T1210),
     Sigma rules rated medium or higher, and the analyst.
   - Context-only primitives no longer confirm. They never decide alone (A2), so they must
     not confirm a written rule into deciding.
   - A confirmer counts only on a host where it is itself quiet: it fires on at most 25% of
     that host's windows. This is C4's bar, measured on the whole history, because a
     confirmer was not written from any of those windows. Earlier, hand-written confirmers
     had no bar, and Sigma confirmers were measured on all hosts' windows together.
   - Agreement with another written rule is a note inside C5. It never confirmed, and is no
     longer shown as if it were a check.
   - Evidence: the run-1 report shows the old hand-written confirmers flag 8 of 12 benign
     windows themselves.

**Effect on run 1 (design data; learning replayed from cache, 57 of 57 calls):**
- **The same 42 rules, statuses and 10 active rules.**
- **The three `ip neighbour` rules** were confirmed automatically by the discovery primitive
  and a kill chain that fires on routine activity. They now wait for review and are approved
  by the (simulated) analyst on complete review, 4 of 4 alerts.
- **Detection is unchanged:**
  - run 1: 8/8 attack windows, 1/12 benign, 28/36 steps;
  - smoke: 7/8, 0/6, 12/68, precision 1.0.
- **A first definition was rejected.** It measured a confirmer's quietness excluding the
  window where it agrees. On 5-window hosts that admitted a Sigma rule firing on half of all
  windows, and 4/12 benign windows were flagged. It was replaced before any result was
  recorded.

## Amendment A4 — ad-hoc triage (2026-10-21, before any test operation)

The thesis is reframed from post-hoc triage (deciding once a capture is complete) to **ad-hoc**
triage: deciding while an operation is still running, on whatever telemetry has arrived, and
revising as more arrives. Made before any test operation exists, so no test result can have
informed it. Run 1 and the burn-in have only been scored post hoc.

- **Added:** Q4, timeliness. While an operation runs, does ARGUS alert early enough to matter,
  without paging the analyst for nothing, and do its ad-hoc decisions end where the post-hoc
  ones do? Measures T1–T8 are defined in `LAB_ADHOC_TEST.md` §2.
- **Added:** every operation is scored twice from the same telemetry and frozen code: ad hoc
  (from ARGUS's revisions as they were made) and post hoc (from the complete capture).
- **Success, stated now:**
  - every closed window's ad-hoc decision identical to post hoc;
  - median time to first alert ≤ 5 minutes, 90th percentile ≤ 15 minutes;
  - benign windows flagged at any revision ≤ 1 per 20 host-windows;
  - a cleared host's blind spot within 5 minutes.
- **Integrity:**
  - a live result can't be rerun, so test revisions are written append-only and a replay of
    the captured stream must reproduce them;
  - while a test operation is live, and until all are scored, the workbench is read-only (no
    learning, rule decisions or feedback).
- **Allowed during design (L1–L6 of `LAB_ADHOC_TEST.md`, design data only):** live windows,
  re-triage on a 1-minute tick, live coverage, the timing record, replay, and the test-time
  lock.
- **Unchanged:** Q1–Q3, their post-hoc metrics, the design/test split, the arms, and the
  post-hoc success criterion.

