# Lab test suite: real-time benign activity on four victims, log clearing, every ARGUS scope

**What this is.** The capture campaign that completes `LAB_EVAL_PLAN.md`: design operations 2
and 3, a benign burn-in, and the test operations. It says what each capture must contain so
that every part of ARGUS is exercised, how each part is graded, and what must be in place
first. It adds to the pre-registered plan and changes nothing in it. Where the two differ,
`LAB_EVAL_PLAN.md` wins.

**Rules that hold throughout:**
- **Attacks come only from CALDERA's own published stockpile**, selected by ATT&CK technique
  ID (`Test Setup/lab/build_linux_profile.py`). No attack command is written for this suite.
- **The lab stays isolated** while any operation runs. There is no internet route, and no
  real credentials exist anywhere in the lab.
- **Each operation's role** (design or test) follows from its import order alone
  (`lab_split.json`). Its profile and victim set are written down before it runs.
- **Test operations are scored once,** after the final freeze, by one command. Their cases are
  not opened in the workbench before then.
- **API keys** are typed per run at a hidden prompt or in the workbench, and are never saved.

---

## 1. What the suite must exercise

| # | ARGUS scope | What it is | What the captures must contain | Graded by | Ready? |
|---|---|---|---|---|---|
| S1 | Process lineage and episodes | Commands linked into stories by the process tree; login shells never join two stories | Agent and benign activity in **separate sessions** (§4.2) | The episode root of every attack window is the agent or its deployment; no episode joins an agent step to a benign action | yes |
| S2 | Learned rules, detection (Q1) | Rules the LLM wrote from design operations, checked C1–C5 | Design operations 2 and 3 with abilities **different from run 1** | Test steps detected and benign windows flagged, against the hand-written floor (plan §6) | yes |
| S3 | Learned rules, generalisation (Q3) | Rules firing on operations they were not written from | At least 2 test profiles not used in design, and at least 1 different victim set | Steps detected by learned rules on unseen profiles and victims | yes |
| S4 | Rule checks C1–C5 and review | Label-free checks; analyst approval as the C5 pass (A3) | Design data with enough per-host history for C4 (burn-in, §3) | Per-check survival; in-sample precision of approved rules; review workload | yes |
| S5 | Kill chain | Several tactics linked in one non-hub process tree | An operation that reaches discovery → collection/staging → exfiltration over the C2 channel | Kill-chain steps detected; no kill chain on benign windows | yes |
| S6 | Context primitives | Discovery, staging, exfiltration and beacon: reported, never deciding alone | Benign look-alikes of each (§4.3) | No benign window flagged because of a primitive; primitives reported as context in attack windows | yes |
| S7 | Brute force (T1110) | Failed logins followed by success, from `auth.log` | Benign failed logins (typos), plus a stockpile T1110 ability if one exists for Linux | Detected if the ability ran; benign typo windows not flagged | **needs P1** |
| S8 | Port scan (T1046) | Many destination ports from one source, from Zeek | Benign service checks, plus a stockpile T1046 ability if one exists for Linux | Same as S7 | **needs P2** |
| S9 | Exploited service (T1210) | A service process spawning a shell after an inbound session | Not produced by this lab's stockpile profiles | Reported as untested here; covered by the earlier Metasploitable captures (`cases_linux`) | out of scope |
| S10 | Log clearing, two views (Q2) | Evidence before a log clear is invalidated, and the gap is a blind spot | At least 2 operations that run stockpile T1070.002/T1070.003 abilities, with logs **forwarded to Kali** (§3.3) | Local view reports a blind spot covering the cleared interval; forwarded view still detects the steps | **needs P3, P4, P5** |
| S11 | Sensor contract and blind spots | A sensor type that should record but doesn't is reported, never read as innocence | A **benign, scheduled sensor maintenance** (auditd restart) and any audit-rule removal | Blind spot reported for exactly that interval; no malicious verdict from it | **built 2026-11-16** for stops, restarts and rule removal: the burn-in's hourly maintenance and its 7-minute reboot gaps are reported as blind spots (`tests/test_sensor_health.py`); log clearing still needs P3 |
| S12 | Clock health (F5, clock half) | A host clock off the estate is a reported sensor defect | One host with a known, recorded offset in one **design** run | Offset reported as a defect on that host's windows | **needs P6** |
| S13 | Per-host novelty (F1) | Each host's baseline learned from its own burn-in; abstains without history | The burn-in (§3.4) | Novelty is context only; "insufficient history" before 10 windows | **needs P7** |
| S14 | Cross-host stories (F7) | One episode across hosts via SSH | A stockpile T1021.004 ability that moves between victims | Lateral steps linked into one estate episode | **needs P8** |
| S15 | Trust and renamed programs | Attacker-written fields count less; rules survive renaming (C3) | The agent deployed **under a different file name** on each victim and in each run | Learned rules still fire on a differently named agent (part of Q3) | yes |
| S16 | Capture validity | Protocol activity never inside a scored window | Experimenter actions logged (§6) | Gate results per window, never dropped | yes |
| S17 | Workbench | Import, triage, learning, review, feedback, coverage | Every run imported through the workbench | Acceptance checks in §7.3 | yes |
| S18 | Reproducibility | Same input, same output | All runs | A rerun of the test scoring reproduces it exactly; model calls replay from cache | yes |

---

## 2. Prerequisites

Design-phase work only, done and measured on design data, then frozen. Captures may start
before these are finished, but the **test is not scored until all that apply are done.**

| # | What | Done when |
|---|---|---|
| P1 | **`auth.log` in lab windows.** The converter reads each host's `auth.log` into the same windows (logins, failures, sudo) | T1110 and logon facts appear in lab windows; run 1 still converts to its current events plus the new ones |
| P2 | **Zeek in lab windows.** Zeek's `conn.log`, and `http.log` where present, joined to windows by host address and time | T1046 and network-session facts appear; the agent's C2 connection, which auditd sees only once, becomes visible |
| P3 | **Log-tampering reasoning on Linux (F6).** A truncated, deleted or rotated log, removed audit rules, or a stopped audit daemon sets that host's `invalidated_before` | On a design run with log clearing, evidence before the clear is invalidated and reported as a blind spot |
| P4 | **Two views in Import.** The Import sheet can import one run as its *local* view (the victims' own logs) and as its *forwarded* view (the copies on Kali) | Both views import as separate corpora with the same window grid |
| P5 | **Audit coverage of log files.** The victims' audit rules record deletion, renaming and truncation inside `/var/log`, plus audit-config changes (already watched), **without** recording every ordinary log append | A `logrotate` run and a stockpile log-clear both appear as file events; normal logging adds no events |
| P6 | **Clock health (F5).** A host whose measured offset exceeds a threshold, fixed on design data, is reported as a sensor defect | Run 1's sub-second offsets report nothing; the design run with a known offset reports it |
| P7 | **Per-host baselines (F1).** Novelty learned from each host's own burn-in windows, abstaining below 10 | The burn-in yields a baseline per host; no baseline is learned from another host |
| P8 | **Cross-host episodes (F7).** Per-host episodes linked through logons and connections between victims | On a design run with lateral movement, the two hosts' episodes become one estate episode |
| P9 | **Profile builder fixed.** It keeps only abilities whose Linux executor runs at the privilege the agent will have on its hosts, refuses abilities written for another platform's files (run 1's FreeBSD `/etc/master.passwd`), can be given the ability IDs to use, and prints its choice for review before creating the profile | A dry run lists only runnable abilities; the chosen ability IDs are saved in the run's manifest |
| P10 | **Benign activity as a service** (§4) | Persona activity runs in its own session from boot, independent of any login or of the agent |
| P11 | **The burn-in as history.** `lab_split.json` names history captures (label-free, never design or test). Learning measures C4 and episode novelty on each host's history plus its design windows, and still writes rules only from design operations | C4 on run 1's rules is measured against 20+ windows per host instead of 4 |

---

## 3. The estate

### 3.1 Victims

The same four distinct victims (`LAB_MINIMAL_LINUX.md`), plus one more for the "different
victim set" the test requires:

| host | user | role | in |
|---|---|---|---|
| web01 | www | web application | design and test |
| app01 | svc | internal application server | design and test |
| ws-dev01 | bob | developer workstation | design and test |
| ws-fin01 | alice | finance workstation | design and test |
| **ws-hr01** (new) | **carol** | HR workstation: documents, mail-like file traffic, a different package set | **test only** (the new victim set) |

ws-hr01 is built with `make-victim.sh` from the same base image, with its own identity,
persona and burn-in. At most four victims run at once: the "different victim set" test
operation swaps ws-hr01 in for one of the others.

### 3.2 Sensors, per victim

| sensor | records | change from run 1 |
|---|---|---|
| auditd | every program run, every outbound connection, watched sensitive paths | add P5 (log-file deletion, rename, truncation) |
| auth.log | logins, failures, sudo | none; ingested once P1 is done |
| Zeek on the bridge | connections, HTTP, DNS between all hosts | none; ingested once P2 is done |
| chrony | time from Kali | offsets recorded per window (already done) |

### 3.3 Forwarding (the second view for Q2)

Every victim streams its audit log, `auth.log` and the persona's activity log to the Mac
**as they are written**, by its own rsyslog (`Test Setup/lab/forward-logs.sh`, set up once
before the `burned-in` snapshot), over the isolated network. On the Mac,
`Test Setup/lab/log_receiver.py <run>` writes them straight into the run's capture folder,
so nothing is pulled at the end. Lines a victim cannot send wait in a disk queue.

A log cleared on a victim then survives on the Mac, and the same run can be scored from both
views. The receiver's copy is the forwarded view, and the victims' own logs, pulled into
`<run>-local`, are the local view.

Check before each run: every victim's test line reaches the receiver. During the run, every
victim's audit-log count keeps rising. Run 2's SSH pull lost three of four hosts' audit
logs, which is why the pull was replaced.

### 3.4 Burn-in (once, before design operation 2)

- **Length:** 20 windows per host (10 hours) of benign activity only. This builds each host's
  own history for C4, F1 and benign scoring.
- **Content:** every persona task and every benign look-alike of §4.3, including at least one
  log rotation and one scheduled sensor maintenance per host.
- **Then:** snapshot every victim as `burned-in`. Every later run starts from this snapshot.
- **Role:** the burn-in is imported without a CALDERA report, so it is triage-only and never a
  design or test operation. Its windows are each host's history (`LAB_EVAL_PLAN.md` §3),
  read by learning once P11 exists.

---

## 4. Benign activity in real time

### 4.1 What "real time" means

Benign activity never stops: before, during and after every operation, at a human pace,
with irregular gaps. In run 1 it ran only while the operation was paused. Each run's
timeline:

```
 ≥2 benign windows    operation (≤ 2 h)          ≥2 benign windows
├─────────────────┼──────────────────────────┼─────────────────┤
  personas active    personas still active      personas active
```

### 4.2 Separate sessions (the run-1 flaw)

- **Persona activity** runs as a per-user service started at boot (P10). It is never launched
  from an interactive login.
- **The CALDERA agent** is deployed from its own session: a separate SSH login by the
  experimenter, logged in §6. That login, the download and the launch are labelled as the
  agent's deployment (A2).
- **The result:** no process is an ancestor of both the agent and the persona. S1 is graded on
  exactly this.

### 4.3 Personas and benign look-alikes

Each persona does its role's ordinary work plus **benign look-alikes**: legitimate actions
that resemble an attack technique. They are the false-alarm half of the test, and every one
is written with a timestamp to the persona's activity log, which is also forwarded.

| look-alike | resembles | on |
|---|---|---|
| admin surveys the host (`uname`, `id`, `ip`, `ss`, `ps`, `df`) | discovery (TA0007) | all |
| SSH to a peer for a real task (copy a report, check a service) | lateral movement (T1021.004) | app01, ws-dev01 |
| a mistyped password, then success | brute force (T1110) | ws-fin01, ws-hr01 |
| archiving a work folder (`tar`/`zip`) | staging (T1074, T1560) | ws-fin01, ws-dev01 |
| uploading the archive to a lab file share | exfiltration (TA0010) | ws-fin01 |
| downloading an update or package from the lab mirror | ingress tool transfer (T1105) | all (burn-in), web01 |
| scheduled `logrotate` (rotates and truncates logs) | log clearing (T1070.002) | all |
| a user clearing their own shell history | history clearing (T1070.003) | ws-dev01 |
| scheduled auditd restart for maintenance (a short sensor gap) | indicator removal / sensor tampering | app01 |
| a service health check probing a few local ports | port scan (T1046) | web01 |

Per window, the number of persona actions should vary: a quiet half-hour on one host, a busy
one on another. Per-host differences are what F1 and C4 rely on.

---

## 5. The operations

**Adversary profiles** are lists of ATT&CK technique IDs. The fixed builder (P9) picks
CALDERA's own Linux abilities for them, and the chosen ability IDs are recorded before the
run.
- **A profile "not used in design"** differs from every design profile, and at least half of
  its abilities appear in no design profile. The stockpile often has one Linux ability per
  technique, so complete disjointness is not always possible. Q3 is graded on the steps of
  those new abilities.
- **Privilege.** Agents run as each host's normal user, except on the hosts a run clears logs
  on. There the agent is deployed as root, because clearing system logs needs it. ARGUS's
  model calls this an attacker who can suppress evidence (L3). The manifest records which
  hosts ran a root agent.

| profile | tactics (ATT&CK) |
|---|---|
| A (run 1) | discovery: T1082, T1033, T1016, T1049, T1087.001, T1518 |
| B | discovery (other abilities than A) + credential access T1552.001/.004 + collection T1005, T1074.001, T1560.001 + exfiltration over C2 T1041 |
| C | discovery + lateral movement T1021.004 + T1070.003 + T1070.002 |
| D (test only) | discovery T1057, T1083 + credential access T1552.003 + archive T1560.001 + exfiltration over another protocol T1048 |
| E (test only) | discovery T1069 + lateral movement T1021.004 + collection T1005 + T1070.002 + file deletion T1070.004 |

**The runs**, in this order (the order decides the role):

| run | role | profile | victims | log clearing | special condition | scopes chiefly exercised |
|---|---|---|---|---|---|---|
| burn-in | history (triage only) | none | the four design victims, then ws-hr01 | none | look-alikes; 1 rotation and 1 sensor maintenance per host | S4, S6, S11, S13 |
| run 2 | **design 2** | B | web01, app01, ws-dev01, ws-fin01 | none | agent under a new name | S1, S2, S4, S5, S15 |
| run 3 | **design 3** | C | web01, app01, ws-dev01, ws-fin01 | on 2 hosts (root agent there), forwarded | ws-dev01's clock deliberately offset | S10, S11, S12, S14 |
| test 1 | test | B (seen) | **ws-hr01**, app01, ws-dev01, ws-fin01 | none | new victim set | S2, S3 (new victim), S16 |
| test 2 | test | **D** (unseen) | web01, app01, ws-dev01, ws-fin01 | none | agent under another name | S2, S3, S5, S15 |
| test 3 | test | **E** (unseen) | web01, app01, ws-dev01, ws-fin01 | on 2 hosts (root agent there), forwarded | — | S3, S10, S14 |
| test 4 | test | C (seen) | web01, **ws-hr01**, ws-dev01, ws-fin01 | on 2 hosts (root agent there), forwarded | — | S10, S11, S14 |

This meets the plan's test requirements:
- 4 operations;
- 2 profiles not used in design (D and E);
- 2 runs with a different victim set (tests 1 and 4);
- 3 log-clearing operations (at least 2 required).

Design runs 2 and 3 cover log clearing, lateral movement and clock offset, so P3, P6 and P8
are built on design data, never test data. If the stockpile has a Linux ability for T1110 or
T1046, add it to profiles C and E before run 3, and record that in the manifest. If not,
S7 and S8 are reported as untested.

---

## 6. Each run, step by step

**Before:**
1. Revert every victim to `burned-in`, then confirm:
   - clocks within 5 s of Kali (except the planned offset in run 3);
   - audit rules loaded (`/var/log/argus-sensor-check.txt`);
   - forwarding works (§3.3).
2. Write the run manifest: name, role, profile and its ability IDs, victims, log clearing
   yes/no, special conditions, and the agent's file name per victim.
3. Install nothing from here on. Package installs belong to the burn-in.
4. Start the network capture (`capture.sh start <run>`).

**During:**

5. Leave at least 2 benign windows, then deploy agents from a separate session (§4.2) and start
   the operation in CALDERA. Do not pause it.
6. Log every experimenter action with a UTC time in the run manifest: logins, deployments,
   operation start and stop, anything touched. The capture gate is checked against this log.

**After:**

7. Leave at least 2 benign windows after the operation ends.
8. After the last scored window has closed:
   - stop the network capture and the receiver;
   - `log_receiver.py <run> --check` must report every host complete, otherwise recapture;
   - on log-clearing runs, pull the victims' own logs into `<run>-local` (the local view);
   - run Zeek over the pcap;
   - collect the CALDERA operation report and `ground_truth.json`.
9. In the workbench: **Import capture**, with the report, as the run's name. For a
   log-clearing run, also import the forwarded view once P4 exists. Check the role line
   (design or test) before clicking Import.
10. Design runs only: **Learn new rules** in the workbench, then review the rules awaiting
    review. Test runs: do not open their cases.

**A run is re-captured, never patched, if:**
- a gate fails beyond the logged protocol actions;
- a CALDERA step matches no process;
- an operation stalls before its last tactic, as run 1 did.

---

## 7. Grading

### 7.1 Primary (unchanged from `LAB_EVAL_PLAN.md` §6)

- Attack steps detected, with 95% Wilson intervals.
- Benign windows flagged, per host-day.
- Event precision.

**Success, stated in advance:** the learned-rules arm beats the hand-written floor on test
steps detected, with at most 1 benign window flagged per 20 host-windows.

### 7.2 Per scope

| scope | pass | fail |
|---|---|---|
| S1 | every attack window's episode is rooted at the agent or its deployment | any episode joins agent and persona activity |
| S5 | the kill chain detects multi-tactic steps in tests 2 and 3 | the kill chain fires on a benign window |
| S6 | no benign look-alike window is flagged | a look-alike window is flagged malicious or suspicious |
| S7, S8 | the ability is detected and benign typo/health-check windows are not flagged | either fails, or the ability didn't run (then untested) |
| S10 | **local view:** a blind spot covering the cleared interval on every cleared host, and that interval is never called benign; **forwarded view:** steps detected at least as many as the local view, with the cleared hosts' pre-clear steps detected at least as often as the same run's uncleared hosts' steps | a cleared interval called benign with no blind spot |
| S11 | the maintenance gap is reported as a blind spot and the window is not flagged | the gap is silent, or read as an attack |
| S12 | run 3's offset host reported as a sensor defect | no report |
| S13 | novelty abstains before 10 windows and never decides | novelty flags a window by itself |
| S14 | lateral steps linked into one estate episode in tests 3 and 4 | stories split per host |
| S15 | learned rules fire on the differently named agent | they only match run 1's name |
| S18 | the scoring rerun is byte-identical | any difference |

**Also reported, whatever the result:**
- undecidable windows;
- rules surviving each check;
- analyst review workload (rules reviewed, alerts read);
- model calls;
- the dump-to-LLM arm (`tools/llm_dump_lab.py`) on the test operations, as a comparison only.

### 7.3 Workbench acceptance (S17)

Each is checked once on a design run:
- the Import sheet converts the run and shows its correct role;
- **Triage all** completes;
- a case shows its verdict, blind spots, process tree and timeline;
- a learning run completes with a typed key, and the key appears in no file;
- **Approve** records C5 as "analyst";
- **Retire** stops a rule deciding;
- feedback is written to disk;
- Coverage lists the maintenance gap.

---

## 8. Ground truth and records per run

| file | from | used for |
|---|---|---|
| CALDERA operation report | CALDERA | attack steps, processes, times (labels) |
| `ground_truth.json` | CALDERA | bootstrap abilities |
| persona activity logs | each victim, forwarded | which windows hold benign look-alikes; benign labels |
| run manifest | the experimenter, before and during the run | profile, ability IDs, victims, conditions, experimenter actions with times |
| local and forwarded logs | victims, Kali | the two views (S10) |
| pcap and Zeek logs | the Mac's bridge, Zeek | network facts (P2) |

Labels are read only to grade; nothing above reaches ARGUS's reasoning. The log-clear times
for S10 come from the CALDERA report's T1070 steps.

---

## 9. Order of work

1. P9, P10 and P5, then the burn-in (§3.4).
2. Design run 2.
3. P1, P2, P7, P11, measured on burn-in and design data.
4. Design run 3.
5. P3, P4, P6, P8, measured on design run 3.
6. Learning with memory, review, then the **final freeze**.
7. Tests 1–4, captured in this order and imported in this order. Not opened.
8. Score all test operations once; report Q1–Q3, S1–S18 and the success criterion.
