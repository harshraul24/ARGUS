# ARGUS status report: 25 September to 8 October 2026

What changed, the lab as it stands, every result so far, milestones, what remains, and the
architecture in words. Every date and number below comes from the project's records:
- freeze manifests (`ARGUS_FREEZE_*.json`, including those kept in the 8 October backup);
- `S1_RESULTS.md`, `S2_RESULTS.md`, `S3_DESIGN.md`, `INTEL.md`, `LAB_RUN1.md` and `LAB_EVAL_PLAN.md`;
- the result folders in `eval_runs/`.

**The held-out test has not run.** That is deliberate: it is scored once, after the final
freeze (§6).

---

## 1. In one paragraph

On 25 September, ARGUS was a Windows-focused research prototype measured on the CITAR
dataset, and its detection code was being edited while it was being evaluated. By 8
October it is:
- **Linux-only**;
- **evaluated under a pre-registered plan**, with every result tied to a hash of the code
  that produced it;
- **able to learn its own rules** with an LLM behind five label-free checks;
- **tested on a real four-victim attack lab;**
- **usable entirely from a browser:** import a capture, triage, learn rules and review them,
  with no terminal.

On the first lab design run, the learned rules took ARGUS from 1 of 8 to 8 of 8 attack windows
flagged, and from 2 to 28 of 36 attack steps. One benign window was flagged both before
and after. These are design (in-sample) numbers; the test will show whether they hold.

---

## 2. Update log

### Starting point (as of 25 September)

No changes are recorded between 18 and 30 September. The state on 25 September is the
state of 17 September:
- **Phases P0–P5** had added an evaluation harness, tactic-level behaviour primitives,
  kill-chain correlation, novelty scoring and two LLM hypothesis proposers. All were measured
  on **CITAR**, CALDERA-emulated APT campaigns on Windows 10.
- **Odin**, a separate LLM rule-induction experiment, had been compared with ARGUS on CITAR.
  Its induced rules found real attacks but also promoted benign background noise.
- **Weaknesses an examiner would find:**
  - code was changed during evaluation;
  - the novelty baseline had been learned on a test campaign;
  - five attack windows cannot support a detection rate.

### 1 October: making the results defensible, then teaching ARGUS to learn rules

| step | what changed | result |
|---|---|---|
| **S1: frozen, held-out evaluation** | A freeze manifest (hashes of every detection file), checked on every run. Design campaigns APT29, FIN6 and OilRig; held out Wizard Spider and menuPass. Recall per attack step (110 steps) with 95% Wilson intervals | Held out: 2/2 attack windows, 0/16 benign, **39/48 steps** (0.68–0.90), event precision 0.75 |
| **S2: process lineage and sensor blindness** | The kill chain must link through one process tree; canonical command forms; sensor blind spots reported on every decision | Held out: 38/48 steps, event precision up to **0.80**; design precision 0.81 → 0.89 |
| **S3 step 1: rules as data** | One JSON rule format, executed by the engine | Hand-written rules reproduced with 0 mismatches |
| **S3 step 2: the checks** | C1–C5 applied to Odin's 67 LLM rules | **0 of 67 survive C1–C5**: no benign alarm, where Odin's own screens let through up to 17/18 |
| **S3 step 3: the learning loop** | Novel episodes, then the LLM writes rules, then the checks, with up to two repairs. Rule library with lifecycle; shadow scoring | On design: 6 active rules, 0/17 benign, precision 1.00 (requiring a non-LLM confirmation) |
| **S3 step 4: held-out look** | The frozen library on Wizard Spider and menuPass | Safe but narrow: active rules precision 1.00, 0/16 benign, but **1/48** steps. ARGUS overall unchanged (38/48) |
| **S3 step 5: feedback and memory** | Analyst verdicts, value-of-information questions, rule memory in prompts | Value-ranked review finds noisy rules 2–4× faster than random. Final library: 6 active, 30 shadow |

**Lesson:** the checks select safe rules, not general ones. CITAR (five campaigns, one tool,
one host) was too narrow to show generalisation. Fresh data was needed.

### 6 October: a real lab, a pre-registered plan, community intelligence

- **The Linux lab was built** (`LAB_MINIMAL_LINUX.md`): four distinct Debian victims on one
  Mac, attacked by CALDERA from Kali (§3).
- **Smoke capture:** a pipeline check only, excluded from design and test. ARGUS flagged 7/8
  attack windows but **5/6 benign windows**. Every detected step came from novelty alone
  (event precision 0.11). The novelty baseline had been learned on other machines. This
  became the evidence for fixes F1 and F2.
- **`LAB_EVAL_PLAN.md` was pre-registered before any design capture:**
  - questions Q1–Q3;
  - the design/test split by capture order;
  - the allowed fixes F1–F8;
  - the success criterion.
- **Community intelligence:** Sigma rules imported from dated snapshots, as an independent
  confirmation source for C5. On CITAR design data, letting quiet Sigma rules confirm LLM
  rules raised the active LLM rules from 6 to 14. Their steps found rose from 11/62 to 18/62,
  at the cost of 1/17 benign windows.

### 7 October: behaviour vocabulary, a workbench, the first design run

- **F3, the behaviour vocabulary.** Program names are mapped to ATT&CK tactics using Sigma's
  own tags, so a rule can say "a discovery program" instead of listing commands.
- **C5 tightened.** A Sigma rule confirms only if it is rated medium or higher. Both false
  confirmations on CITAR had come from `low` rules.
- **The analyst workbench (v1)** in the browser:
  - a case queue ranked by priority;
  - the case view: verdict, blind spots, evidence, process tree, timeline, sensors;
  - shadow rules;
  - feedback saved to disk;
  - the rule library.
- **Run 1 captured.** CALDERA operation `test2` ran against all four victims.

### 8 October: Linux-only, precision, learned rules, a usable product

| change | what and why | effect |
|---|---|---|
| **Converter fixes** | An auditd parsing bug dropped enriched fields (users, connections). Added network and sensitive-file events, ancestor folders, sensor contracts, and capture-gate detection | Every CALDERA step matched to a process; clocks within 1 s |
| **Run 1 scored** at the Linux freeze | | 8/8 attack, but **7/12 benign**, 8/32 steps, event precision 0.007 |
| **Amendment A1: Linux-only** | Windows code, the CITAR corpus and Windows intelligence deleted (backup kept). Hand-written rules kept only for network and identity shapes | Narrower thesis scope |
| **Amendment A2: precision** | Four definitions, no threshold tuned: beacons must leave the host; login shells are judged over their whole life; weak primitives never decide alone; the agent's deployment is labelled attack | Benign **7/12 → 1/12**, but attack 8/8 → 1/8. The hand-written layer cannot see a discovery-only attack |
| **S3 on Linux** | 57 model calls, 45 episodes, 42 rule attempts, 20 active rules | 8/8 attack, 1/12 benign, **28/36 steps** |
| **Duplicate merge** | Rules firing on identical events merged, label-free | 20 → **10 active rules**, no detection change |
| **Learning in the browser** | Learn new rules, approve, retire. The API key is typed per run and never stored | No terminal for learning |
| **Import capture in the browser** | Converter moved into ARGUS. Choose a capture folder or copy one in, add the CALDERA report; the run is added to the split in capture order | No terminal for conversion |
| **Black-and-white redesign** | Apple-style workbench; light and dark mode; phone width | |
| **Documentation** | Architecture diagram (published page), `THESIS.md` (short thesis draft), this report | |

**Software tests:** 102 tests at the end of the CITAR work (1 October). 83 remained after the
Linux-only cut, all on real Linux data, and now **94** pass.

---

## 3. The test lab today

```
                     Mac (Apple Silicon), one isolated virtual network
 ┌─────────────────────────────┐            ┌──────────────────────────────────────────────┐
 │ Kali VM (UTM)               │  commands  │ 4 Debian 12 victims (QEMU, copy-on-write      │
 │  CALDERA server  ───────────┼──────────► │ overlays on one base image, cloud-init)       │
 │  operation report (JSON)    │            │                                              │
 │                             │            │  web01    www    web application             │
 └─────────────────────────────┘            │  app01    svc    internal app server, SSH     │
                                            │  ws-dev01 bob    developer workstation        │
 tcpdump on the Mac's bridge ◄──────────────│  ws-fin01 alice  finance workstation          │
   → campaign.pcap → Zeek logs   traffic    │                                              │
                                            │  each runs: CALDERA agent (as a normal user),│
                                            │  benign persona script, auditd, auth.log      │
                                            └──────────────────────────────────────────────┘
 capture.sh pull ──► Test Setup/lab/captured/<run>/<host>/{audit.log, auth.log} + report
                 ──► ARGUS workbench: Import capture
```

| part | what it is |
|---|---|
| **Victims** | Four distinct machines, not clones: each has its own hostname, user, role, software and benign behaviour, set by cloud-init on first boot. They share one base disk through copy-on-write overlays (about 0.7 GB each) |
| **Attacker** | MITRE CALDERA on Kali, using its own published abilities. One agent per victim, running as that host's normal user |
| **Endpoint sensor** | auditd, with rules for every program run (`execve`), every outbound connection (`connect`), and access to sensitive paths: accounts, sudoers, cron, systemd units, SSH keys, audit config and audit logs |
| **Identity sensor** | `auth.log`: SSH logins and sudo use |
| **Network sensor** | tcpdump on the Mac's bridge, then Zeek. Captured, but not yet read by the lab windows |
| **Benign activity** | `benign.sh`, per persona: ordinary admin and user tasks, logged with timestamps |
| **Isolation** | By procedure, internet only for first-boot package installs, with the default route dropped during attack runs. Run 1 still saw public NTP traffic and a package install during capture |
| **Ground truth** | Only from the CALDERA report (plus `ground_truth.json` for bootstrap abilities). A step's process and its descendants, the agent's process tree, and the agent's deployment |
| **Validity gates** | Clocks within 5 s; every step matched to a process; no admin or collection activity in a scored window; every sensor present. A failed gate is recorded per window, never dropped |
| **Flow into ARGUS** | `capture.sh pull` copies the logs to `Test Setup/lab/captured/<run>/`. In the workbench, **Import capture** turns them into one case per host per 30 minutes |

**Known lab problems from run 1, to fix before run 2:**
- The profile builder picked a FreeBSD ability that waited for a `sudo` password, so the attack
  stalled after discovery.
- The benign script shared the agent's login shell and ran only while the operation was
  paused.
- There was no benign burn-in before the attack.

---

## 4. Test results

### 4.1 Lab (Linux, current scope)

**Smoke capture, 6 October.** A pipeline check, excluded from design and test, scored with
the pre-lab ARGUS:

| attack windows | benign windows | steps | event precision |
|---|---|---|---|
| 7/8 | 5/6 | 59/60 | 0.11 (every step from novelty alone) |

**Run 1, design operation 1.** 4 hosts, 20 windows, 8 of them attack; 11 pass the capture
gate.

| | Linux freeze (7–8 Oct) | after A2: hand-written floor | + learned rules |
|---|---|---|---|
| attack windows flagged | 8/8 | 1/8 | **8/8** |
| benign windows flagged | 7/12 | 1/12 (gate-pass 0/3) | **1/12** (gate-pass 0/3) |
| attack steps detected | 8/32 | 2/36 | **28/36** (95% CI 0.62–0.88) |
| event precision | 0.007 | | learned rules 1.0; overall 0.13 (0.26 gate-pass) |

**Notes on these numbers:**
- **The step count grew from 32 to 36** when A2 began labelling the agent's deployment as
  attack activity.
- **The remaining benign alarm** is the kill chain firing on the benign script, which surveys
  the host and SSHes to a peer on a loop. Per-host history (F1) is meant to tell these apart.
- **Learned-rule precision of 1.0 holds by construction.** The model saw these windows, and
  the simulated analyst approves only rules whose alerts are all labelled malicious.

**The learned library on the unseen smoke operation (a diagnostic; nothing was changed
because of it):**

| attack windows | benign windows | event precision | steps |
|---|---|---|---|
| 7/8 | 0/6 | 1.0 | 12/68 |

Precision carried over; recall did not. Many rules name run 1's exact commands.

### 4.2 Earlier results on CITAR (Windows; retired by amendment A1)

Kept for the history of the method, not part of the thesis evaluation:

| result | value |
|---|---|
| S1, held-out campaigns, hand-written ARGUS | 2/2 attack, 0/16 benign, 39/48 steps, precision 0.75 |
| S2, with process lineage | 2/2, 0/16, 38/48, precision 0.80 |
| S3, Odin's 67 LLM rules through C1–C5 | 0 survive; 0/18 benign alarms |
| S3, active LLM rules on held-out campaigns | precision 1.00, 0/16 benign, 1/48 steps |

### 4.3 Software tests

**94 tests pass**, all on real captures (run 1, smoke, earlier Linux cases) with no synthetic
data. They cover:
- the converter;
- lineage;
- rules and checks;
- learning and feedback;
- Sigma and the behaviour vocabulary;
- the workbench, including learning, rule review and capture import;
- the API key never being stored.

---

## 5. Milestones

| # | milestone | date | status |
|---|---|---|---|
| M1 | Frozen, held-out, per-step evaluation (S1) | 1 Oct | done |
| M2 | Process lineage and sensor blind spots (S2) | 1 Oct | done |
| M3 | LLM rule-learning loop with label-free checks C1–C5 (S3, steps 1–5) | 1 Oct | done |
| M4 | Four-victim Linux attack lab, with a smoke capture | 6 Oct | done |
| M5 | Pre-registered lab evaluation plan | 6 Oct | done |
| M6 | Sigma intelligence as an independent confirmation (C5) | 6–7 Oct | done |
| M7 | Analyst workbench in the browser | 7 Oct | done |
| M8 | Design operation 1 captured and scored | 7–8 Oct | done |
| M9 | Linux-only scope (A1) and precision fixes (A2) | 8 Oct | done |
| M10 | Rules learned on Linux; duplicates merged (10 active) | 8 Oct | done |
| M11 | No-terminal product: import, learning and review in the browser | 8 Oct | done |
| M12 | Architecture diagram and short thesis draft | 8 Oct | done |
| M13 | Design operations 2 and 3, with burn-in | — | **next** |
| M14 | Remaining design fixes: F1, F6, F7, Zeek/auth.log in windows, F4, F5 clock half | — | open |
| M15 | Final freeze | — | open |
| M16 | Test: at least 4 operations, scored once | — | waiting, by choice |
| M17 | Thesis completed with test results | — | open |

**Status of the allowed design fixes:**
- **Done:** F2 (folded into A2), F3, F8.
- **Half done:** F5 (sensor contracts done; clock health open).
- **Open:** F1, F4, F6, F7.

---

## 6. Remaining steps before completion

1. **Fix the lab:**
   - an attack profile of Linux abilities that run at the agent's privilege, with no `sudo`
     for a user agent;
   - a benign burn-in of 10 or more windows per host, from a session separate from the agent;
   - packages installed before capture;
   - no pauses;
   - logs pulled after the last window.
2. **Capture design operations 2 and 3** with abilities different from run 1. Import each
   in the workbench. Learn rules with the library's memory, and review them.
3. **Finish the design fixes,** measured on design data only:
   - F1, per-host baselines from the burn-in;
   - F6, log-tampering reasoning on Linux (needed for Q2);
   - F7, cross-host episodes;
   - read `auth.log` and Zeek into lab windows;
   - F4, whole-word token matching;
   - F5, clock health.
4. **Final freeze.** One manifest, named in every test result.
5. **Test.** At least four operations, including at least two adversary profiles not used in
   design, at least one different victim set, and at least two log-clearing runs. Score them
   once and report Q1–Q3 against the pre-stated criterion: learned rules beat the floor on
   steps, with no more than 1 benign window per 20 host-windows.
6. **Thesis.** Add the test results, a literature search before any novelty claim, and author
   details. Also update the README's stale Results section.

---

## 7. ARGUS architecture in words

This follows the published diagram (https://claude.ai/artifact/7EobTkTsZkLADaTMmtRQMV),
lane by lane.

### Figure 1: the whole workflow

**1. Lab capture (top lane).**
- **CALDERA server on Kali.** It plays the attacker, sends commands to its agents and writes
  an operation report.
- **The four victim VMs.** Each records what happens on it: auditd logs every command run,
  every network connection and every touch of a sensitive file; auth.log records SSH logins
  and sudo. Each victim runs the CALDERA agent and benign admin and user scripts.
- **Network capture.** A capture on the bridge between the VMs turns traffic into Zeek logs.
  Raw-log cases read these; lab windows do not use them yet.

**2. Import (second lane).** The analyst clicks **Import capture** in the workbench; the arrow
up the left edge of the diagram starts the converter. The converter:
- rebuilds which process launched which;
- cuts the capture into one folder per host per 30 minutes;
- checks the clocks and the capture;
- writes everything to a staging area and moves it in only when complete.

Each window folder holds:
- **`events.jsonl`:** what happened;
- **`lineage.json`:** the process tree, each program's folder and its children;
- **`meta.json`:** what the sensor should record, the clock offset, the capture checks;
- **`labels.json`:** ground truth from the CALDERA report, drawn dashed because only the
  evaluation reads it.

**3. Triage engine (middle left).** Every window flows through five boxes in a row:
1. **Load and normalise.** Events become claims with typed facts and the process that did
   them. Secrets are redacted, programs are tagged with Sigma tactics, and sensor health is
   computed.
2. **Process lineage.** Builds the tree and finds episode roots. Login shells are session
   hubs and never join two stories.
3. **Hypotheses.** Deciding: the kill chain, brute force, port scan, exploited service, and
   active learned rules. Context only: the primitives and novelty.
4. **Reasoning engine.** Scores the evidence, trusts attacker-written text less, and never
   treats a blind sensor's silence as proof.
5. **Decision.** The verdict, severity and priority, what ARGUS could not see, next steps, and
   the episode to inspect.

**5. Rule learning loop (middle right).** It reads **design runs only**, bottom to top:
1. **Episodes:** process trees that are new to the host's own history.
2. **The LLM writes rules:** up to three JSON rules per episode, with attacker text fenced
   off and identities hidden. It talks to the model service, whose key is typed per run and
   whose answers are cached.
3. **C1–C3:** the rule is valid, fires on its own episode, and survives renaming. A failure
   loops back to the LLM to fix and retry, at most twice.
4. **C4 + C5:** the rule is quiet in the host's other windows, and is confirmed by a source
   that may decide on its own (a deciding hand-written rule or a Sigma rule from a dated
   snapshot, each itself quiet on that host) or by the analyst. Since amendment A3
   (14 October) an approval is recorded as the rule's C5 pass.
5. **Rule library:** active, awaiting review, or retired; duplicates are merged and analyst
   decisions are kept.

An arrow carries the library into the Hypotheses box: active rules decide, and shadow rules
are only measured.

**4. Analyst workbench (bottom lane).** It opens with a double-click on Start ARGUS:
- **Import capture:** pick a lab capture folder or copy one in, and add the CALDERA report.
- **Coverage:** blind spots that left cases undecided, ranked.
- **Cases:** the queue ranked by priority. The Decision box's arrow, "verdict + reasons",
  lands here. The case view shows the verdict, blind spots, evidence, process tree and
  timeline, and takes the analyst's verdict.
- **Rules:** Learn new rules, then approve or retire each one. The "start a run" arrow goes up
  to the learning loop.
- **Other ways in:** the HTTP API, TheHive through Cortex, and the command line.

**Thesis evaluation (dashed bottom band, never read by triage):**
- `labels.json` (ground truth);
- `lab_split.json`, filled by Import in capture order (runs 1–3 design, later runs test);
- `eval_lab`, which scores every window once, after the freeze;
- `ARGUS_FREEZE_*.json`, the hash of every source file a result used.

### Figure 2: inside one decision

For each hypothesis, ARGUS looks at every piece of evidence the attack would leave:
- **Seen.** It supports the hypothesis, discounted by how much the attacker controls it: ×1.00
  for kernel facts, down to ×0.85 for a command line the attacker wrote.
- **Missing, and the sensor was blind.** The type is outside its contract, the log was
  cleared, or data was lost. The absence counts for nothing (an undercut), is reported as a
  blind spot, and lowers the case's priority by 20%.
- **Missing, and the sensor was working.** The absence counts against the hypothesis (a
  rebut), by 0.12 times how often that sensor actually emits that evidence.

Only deciding hypotheses set the verdict. The top one's severity-weighted score gives
**malicious** at 0.50 or above, **suspicious** at 0.25 or above, otherwise **benign**. A case
that would be benign while some hypothesis has partial support blocked by a blind spot is
**undecidable**: ARGUS will not call a case benign when it could not see.

### Figure 3: a learned rule's life

A rule is born a **candidate**:
- Passing C1–C4 makes it **shadow**: it runs on every case and is measured, but cannot change
  a verdict.
- Passing C5, through an independent confirmation or the analyst's **Approve**, makes it
  **active**: it decides like a hand-written rule.
- An active or shadow rule can be **retired** by the analyst, or as a duplicate of another
  rule.
- A rule that fails a check is **rejected** and kept with its reason.

Every move is recorded. A judged rule is never edited: a better rule is a new rule.
