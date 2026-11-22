# ARGUS architecture

*As of 21 October 2026 (code at `ADGUS/source code/argus`, 110 tests passing). The diagram in
`figures/architecture-diagram.html` shows the post-hoc pipeline. The ad-hoc (live) mode added
by amendment A4 is described in §3 and §4 below.*

ARGUS is a triage engine for Linux hosts. It turns host telemetry into a decision an analyst
can act on, says plainly what its sensors could not see, and learns new detection rules with
a language model that must pass five label-free checks before any rule may decide.

It runs in two ways on the same engine:

| mode | when it decides | unit of decision | status |
|---|---|---|---|
| **post hoc** | once a capture is complete | a window: one host, 30 minutes | evaluated (run 1, smoke, burn-in) |
| **ad hoc** (A4) | while an operation runs, again whenever new evidence arrives | a case: one process tree under its session root | built; first live run (adhoc1); test planned |

---

## 1. Lab and telemetry

- **Estate:**
  - four distinct Debian 12 victims (web01, app01, ws-dev01, ws-fin01), plus ws-hr01 for test
    runs;
  - QEMU virtual machines on one Mac, built from one base image with copy-on-write overlays,
    and given their identities and personas by cloud-init;
  - Kali running CALDERA as the attacker.
- **Sensors per victim:**
  - auditd: every program run, every outbound connection, and access to sensitive paths;
  - `auth.log`;
  - a packet capture on the bridge, read with Zeek.
- **Benign activity:** a persona service per victim, started at boot in its own session. It
  does the role's work plus benign look-alikes of attack techniques.
- **Log collection:** each victim's rsyslog streams `audit.log`, `auth.log` and the persona log
  to the Mac **as they are written** (`forward-logs.sh`). `log_receiver.py` writes them into
  `captured/<run>/<host>/`, and `--check` confirms each host's copy covers the operation. This
  replaced the end-of-run SSH pull, which lost three of four hosts' logs in run 2.
- **Ground truth:** the CALDERA operation report, read only for grading.

## 2. Ingest

- **Post hoc** (`argus/collectors/lab_capture.py`; the workbench's **Import capture**):
  - rebuilds the process tree;
  - cuts each host's log into 30-minute windows;
  - records what the sensor was configured to record (the sensor contract) and the capture
    gate (protocol activity is recorded per window, never dropped);
  - writes labels only when a CALDERA report is given.

  Audit records are grouped by time and serial, because serials restart at every boot.
- **Ad hoc** (`argus/live/feed.py`, `HostFeed`):
  - reads each host's audit log as it grows;
  - holds a partial line until it completes, and releases an event once its last record
    (PROCTITLE) has arrived;
  - parses it with the batch converter's own code, so a live event and the same event
    converted afterwards are identical.

## 3. Cases

- **Post hoc:** one window = one case.
- **Ad hoc** (`argus/live/loop.py`, `LiveTriage`): each event joins the case of its process
  tree under the session root. A session hub such as a login shell never joins two stories.
  A case whose evidence changed is decided again, polled every second. Every revision is kept
  with **two clocks**: the newest event it saw, and when the decision was made.

## 4. The triage engine (`argus/reason`, `argus/models.py`)

1. **Claims.** Events become claims: typed facts plus the process that produced them, with
   secrets redacted. Programs carry tactic tags from Linux Sigma rules.
2. **Trust.** Each fact records how much of it the attacker controls:
   - L0, kernel-recorded (×1.00);
   - L1, chosen from a fixed set (×0.95);
   - L2, written by the attacker, like a command line (×0.85);
   - L3, the attacker can suppress it (×0.70).
3. **Lineage.** The process tree links commands into episodes. Hubs are judged over a
   process's recorded life.
4. **Hypotheses:**
   - **Decide:** the kill chain (stages sharing one non-hub process tree), brute force (T1110),
     port scan (T1046), exploited service (T1210), and every active learned rule.
   - **Context only:** discovery, staging, exfiltration, beacon and novelty. They never decide
     alone (amendment A2).
5. **Coverage.** For each piece of evidence a hypothesis expects but doesn't find:
   - **Sensor blind** (outside its contract, data lost, or log cleared): the absence counts for
     nothing, is reported as a blind spot, and lowers priority by 20%.
   - **Sensor working:** the absence counts against the hypothesis by 0.12 × how often that
     sensor emits that evidence.

   In live mode, a type is blind for a host at a given moment when that host's loaded audit
   rules don't record it.
6. **Decision.** The top deciding hypothesis's severity-weighted score gives:
   - **malicious** at 0.50 or above;
   - **suspicious** at 0.25 or above;
   - **benign** below that;
   - **undecidable** when the case would be benign but support was blocked by a blind spot.

   The decision includes severity, priority, blind spots, next steps and the episode to
   inspect.

## 5. Rule learning (`argus/rules`)

1. **Episodes:** process trees new to a host's own history, from design operations only.
2. **Writing:** the model (`gpt-oss:120b-cloud`) writes up to 3 JSON rules per episode.
   Attacker text is fenced, and addresses and names are hidden.
3. **Checks** (amendment A3; one definition, in `checks.py`), run in order. A check never
   reached is "not reached", not failed:

| check | question |
|---|---|
| C1 valid | Can ARGUS run the rule as written? |
| C2 own evidence | Does it fire on its own episode, with values that occur there? |
| C3 robust | Does it still fire when programs are renamed, run by full path, or create renamed files? |
| C4 quiet | Is it silent on at least 75% of its host's other windows? |
| C5 confirmed | Does a source that may decide on its own agree: a deciding hand-written rule or a medium-or-higher Sigma rule, each itself quiet on that host, or the analyst? |

   - A rule that fails C1–C3 is repaired up to twice, with the findings sent back to the model.
   - Agreement with another learned rule is a note inside C5, never a confirmation.
4. **Lifecycle:**
   - candidate → shadow (C1–C4 passed; measured, never decides) → active (C5 passed) →
     retired;
   - rejected at any failed check;
   - an analyst's approval is recorded as the C5 pass;
   - the library refuses any state its checks don't support;
   - rules firing on exactly the same events in every window are merged.
5. **Memory:** a new learning run keeps every earlier decision, and its prompt carries what
   earlier rules taught.

## 6. The analyst workbench (`argus/api`, in the browser)

Everything an analyst does is in the browser, with no terminal:

- **Import capture:** pick a capture folder, add the CALDERA report, and see its role (design,
  test, or triage only).
- **Cases:**
  - a queue ranked by priority;
  - per case: the verdict, blind spots, evidence, process tree, timeline, sensors and shadow
    rules;
  - the analyst's verdict and feedback.
- **Live:** start or stop ad-hoc triage on a run being received (`/workbench/live`).
- **Rules:**
  - learn new rules, with the API key typed per run and never stored;
  - approve or retire rules;
  - each rule's C1–C5 shown as passed, failed or not reached.
- **Coverage:** the blind spots that left decisions undecided.

Other ways in are the HTTP API, a TheHive/Cortex analyzer and the command line. Startup is a
double-click on `Start ARGUS.command`.

## 7. Evaluation layer (never read by triage)

- **`labels.json`:** from the CALDERA report (each step's process and descendants, the agent's
  tree, and its deployment).
- **`lab_split.json`:** operations in import order; the first 3 are design, later ones test.
- **Freeze manifests** (`ARGUS_FREEZE_*.json`): the hash of every source file a result used.
- **Tools:**
  - `tools/eval_lab.py`: post-hoc scoring per arm;
  - `tools/eval_benign.py`: benign-only captures;
  - `tools/llm_dump_lab.py`: the dump-to-LLM baseline;
  - `tools/rules_induce.py`: learning from a terminal, replayable from cache.
- **Plans:**
  - `LAB_EVAL_PLAN.md`: pre-registered, with amendments A1 (Linux-only), A2 (precision), A3
    (checks) and A4 (ad hoc);
  - `LAB_TEST_SUITE.md` and `LAB_ADHOC_TEST.md`: the capture campaign and the live test.

## 8. Code map

| module | role |
|---|---|
| `collectors/lab_capture.py` | capture → windows; shared parsing for live |
| `collectors/events.py` | window → claims, sensor contract → health |
| `live/feed.py`, `live/loop.py` | ad-hoc ingest and live cases |
| `normalize/` | behaviour vocabulary (Sigma tactic tags), redaction |
| `reason/lineage.py`, `reason/hypotheses.py`, `reason/engine.py` | process tree, hypotheses, coverage-aware decision |
| `rules/` | rule format, checks C1–C5, episodes, learning loop, library, feedback, Sigma import |
| `llm/` | cached, redaction-gated model client (key never stored) |
| `api/workbench.py`, `api/static/` | the workbench |
| `Test Setup/lab/` | victims, personas, profile builder, log forwarding and receiver |
