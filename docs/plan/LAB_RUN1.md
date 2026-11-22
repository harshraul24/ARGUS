# Lab run 1 — first design operation (captured 2026-10-07, scored 2026-10-08)

**Role under the plan.** By order alone, run 1 is **design operation 1** (`LAB_EVAL_PLAN.md`
§3): it may inform the F1–F8 fixes. It is not test data, and nothing below was tuned on it.

**Freeze.** Scored at `ARGUS_FREEZE_2026-10-08-linux.json`, the Linux-only ARGUS of amendment A1
(`LAB_EVAL_PLAN.md`). Result: `eval_runs/2026-10-08-lab-run1/summary.json`. §7 re-scores it
after amendment A2 (`ARGUS_FREEZE_2026-10-08-a2.json`, `eval_runs/2026-10-08-lab-run1-a2/`). Windows:
`cases_lab/run1_*` (20). An earlier scoring with the Windows+Linux ARGUS is superseded and
was removed with the CITAR material.

## 1. What ran

| | |
|---|---|
| Operation | CALDERA `test2`, adversary `ARGUS-Linux-CITAR` (21 abilities planned), planner atomic |
| Victims | web01 (www), app01 (svc), ws-dev01 (bob), ws-fin01 (alice); agents as normal users |
| Executed per host | 6 discovery abilities (T1082, T1033, T1016, T1049, T1087.001, T1518) + the bootstrap history clear (T1070.003) + 1 credential-access attempt (T1003.008) |
| Never ran | the other 14 abilities: credential access, collection, staging, exfiltration, lateral movement, log clearing |
| Sensors | auditd execve + connect + watched paths (new rules), auth.log, Zeek over the bridge pcap |

**Why the chain stopped.** At 13:48 every agent ran `sudo cat /etc/master.passwd`. The
agents run as normal users, so sudo waited for a password, the link never returned (status −3)
and CALDERA marked all four agents untrusted. Every later ability was skipped ("Agent not
trusted" or "Fact dependency not fulfilled"). That ability is a FreeBSD one. The profile
builder takes the first stockpile ability for each ATT&CK id (`build_linux_profile.py`), and
for T1003.008 that was the wrong platform. The operation was also paused from 12:57 to 13:44.
During the pause `sshpass` was installed and `benign.sh` ran (13:15–13:42).

## 2. Capture-validity gates (§2)

| gate | result |
|---|---|
| clocks within 5 s of CALDERA | **pass**: 0.1, 0.3, 0.7 and 0.8 s (ws-fin01 was 1056 s off in the smoke test) |
| every report step matches a process | **pass**: 32/32 (24 reported + 4 status −3 matched by command text + 4 bootstrap) |
| no collection/admin activity in a scored window | **fail in 9 of 20 windows**: package install (4 × 13:00), log pull (4 × 14:00), first boot (ws-fin01 12:00). Recorded per window in `meta.json` `capture_gate`, never dropped |
| every sensor in every window | auditd **pass**, and its sensor contract (execve + connect rules loaded) is met in all 20 windows. auth.log and Zeek were captured but are **not ingested**: the window path reads only `events.jsonl` |

## 3. Converter changes (input fitting; labels from CALDERA only)

- **Parser bug fixed.** `splitlines()` also splits at `\x1d`, the byte auditd writes before
  its enriched fields, so `SYSCALL=connect`, `UID="www"` and `SADDR={…}` were silently dropped.
  Users had been numeric uids. The smoke windows were regenerated with the fixed converter.
- **New event types:**
  - `network_connection` from `connect()` to inet/inet6 addresses, with `dst_ip` and `dst_port`;
  - `file_read`/`file_write`/`file_create`/`file_delete`/`file_rename` from the watch rules,
    with `file_path` and `audit_key`.

  Each is attributed to the process holding that pid and exe. A child forked without execve
  is attributed to its parent.
- **Steps with no pid in the report** (status −3) are matched by their exact `sh -c` command
  text. **Bootstrap abilities** are not in the report, so they are read from the run's
  `ground_truth.json` and matched by command text on the host whose agent was created at that
  time (marked `bootstrap: true`).
- **Gate detection** uses the protocol's own command text: the `capture.sh` pull, cloud-init
  `runcmd`, and `apt-get install` from a login.
- **Sensor contract.** Each window records the audit rules its host had loaded by the window's
  end and the types those rules record (`sensor_contract`); smoke windows contract only
  process creation, run1 windows process creation and connections.
- **Ancestor folders.** `lineage.json` carries each process's path, so a process launched in an
  earlier window (the agent, started at 12:52) keeps its folder in later windows. Before this,
  every 13:45 discovery step had lost its "ancestor runs from a user-writable folder" signal.
- Tests on the real capture: `source code/tests/test_lab_capture.py` (7). Suite: 83 pass, all
  on real Linux data (run1, smoke, `cases_linux`).

## 4. Results (Linux-only ARGUS; no LLM rule library exists yet, so this is the floor)

| | all 20 windows | 11 gate-pass windows |
|---|---|---|
| attack windows flagged | 8/8 | 8/8 |
| benign windows flagged | **7/12** | **1/3** |
| attack steps detected | 8/32 (95% CI 0.13–0.42) | 8/32 |
| event precision | **0.007** | 0.017 |

All 8 steps are found by the kill chain on the four 13:30 windows. Steps by CALDERA status:
success 8/20, failed 0/8, no result 0/4, bootstrap history clear 0/4. Novelty is off (no
Linux baseline until F1).

## 5. Findings (design evidence for the remaining fixes)

1. **The 8 detected steps are a protocol artefact.** The kill chain fires on an episode rooted
   at the login shell that started both the agent and `benign.sh`. It links `benign.sh`'s
   loopback `curl` "beacon" and its discovery programs with the agent's steps. The agent's own
   subtree fires no stage at all. With separate sessions this detection would vanish.
2. **The beacon rule (TA0011) fires on routine traffic.** It fires in 12 of 20 windows, never
   on the agent:
   - 8 on `benign.sh`'s `curl http://localhost/` every 10–30 s;
   - 2 on ws-fin01's chrony polling public NTP servers;
   - 1 on `sudo` resolving its own host;
   - 1 on `sshd`.

   It cannot see the real C2: the Go agent keeps one HTTP connection alive (one `connect()`
   per agent). Zeek's `http.log` sees the
   beacons, but the window path does not read it. This is **not covered by F1–F8**: a fix needs
   a plan amendment with this evidence.
3. **The discovery primitive (TA0007) fires on benign activity.** Sigma's Linux tags call
   `cat`, `ls`, `grep`, `head` and `apt-get` discovery programs. A package install plus
   `benign.sh` reaches four distinct programs in all four 13:00 windows. Counting distinct
   *programs* is too coarse with this vocabulary.
4. **The exfiltration primitive (TA0010) found the dropper, which the labels call benign.**
   On every 12:30 window it flagged the `curl` that downloaded the agent from CALDERA:
   - the program is tagged exfiltration;
   - it reached a non-loopback address.

   That is attack activity, but the labelling convention marks only the agent's own process
   tree, not the shell that fetched and started it. The convention undercounts attack events.
5. **Q2 (log deletion) is untested.** Only the bootstrap bash-history clear ran, and nothing
   flagged it. The log-clearing abilities were among those skipped.
6. **Protocol problems:**
   - the agent and `benign.sh` share a login shell (finding 1);
   - benign activity ran only while the operation was paused;
   - there was no ≥10-window burn-in before the attack.

## 6. Before design operation 2

- Fix the profile: one ability per technique whose executor is Linux and that runs at the
  agent's privilege. No FreeBSD/macOS abilities, and no `sudo` for a user agent.
- Install packages before the capture starts. Run the burn-in (≥10 windows per host) before
  the operation, from a session separate from the agent's (e.g. a systemd user unit or another
  login). Don't pause the operation, or log the pause.
- Pull logs after the last scored window ends.
- Add each new run to `lab_split.json` before converting it.
- ARGUS side (design phase):
  - F1 per-host baselines from the burn-in;
  - F2 novelty never decides alone;
  - F6 Linux log tampering;
  - read Zeek and auth.log into lab windows;
  - F8: run `tools/rules_induce.py --install` once there is burn-in history.
  - Decide by plan amendment whether to fix:
    - the beacon's false alarms on routine traffic;
    - the discovery primitive's program count;
    - the labelling of the dropper.

## 7. After amendment A2 (precision)

The fixes are in `LAB_EVAL_PLAN.md` A2:
- beacons are sessions that leave the host;
- hubs are judged over a process's life;
- weak primitives never decide alone;
- the deployment is labelled attack.

| | all 20 windows | 11 gate-pass windows |
|---|---|---|
| attack windows flagged | 1/8 | 1/8 |
| benign windows flagged | 1/12 | 0/3 |
| attack steps detected | 2/36 | 2/36 |

What A2 shows:
- **The false alarms of §4 came from weak primitives deciding alone.** One primitive at a
  time is not evidence of an intrusion on a host with routine automation.
- **The hand-written layer cannot see this attack on its own.** The agent's subtree fires no
  stage.
- **Detection has to come from learned rules (Q1).** A feasibility check, not a result
  (written after seeing labels, so never used): a rule of the shape the loop is asked for,
  "a shell launched by a program in a user-writable folder", fires on:
  - 8/8 attack windows and 0/12 benign;
  - 32/32 selected events malicious;
  - 32/36 steps.

  It passes C4 at exactly the 25% limit, because run 1 has only five windows per host. A
  burn-in of ≥10 windows per host gives C4 real room. Then C5 decides: no quiet Sigma rule
  confirms it on run 1, so promotion needs the analyst path (F8).

## 8. Rules learned on Linux (S3, design operation 1)

`tools/rules_induce.py --install`:
- model `gpt-oss:120b-cloud`, 57 calls, 0 errors, freeze `ARGUS_FREEZE_2026-10-08-a2.json`;
- results in `eval_runs/2026-10-08-lab-induce/`; library installed at `eval_runs/lab_library.json`.

**What happened to the rules.** 45 episodes → 42 rule attempts:
- **Repaired:** 14 (superseded).
- **Rejected by C4:** 3. These fired on 50–100% of the host's other windows: an `apt-get install iproute2` fallback, `/etc/passwd` read to a file, and `sudo` reading `/etc/shadow`.
- **Retired by the simulated analyst:** 2. These are the log pull (`cp auth.log /tmp/`) and `/etc/shadow` reads: protocol and routine activity.
- **Retired as exact duplicates:** 3.
- **Active:** 20.
  - Promoted by a hand-written primitive: 3 (`ip neighbour`).
  - Promoted by the simulated analyst (F8): 17.
  - Promoted by Sigma: 0. No medium-or-higher Sigma rule is quiet in run 1's history.

The 20 active rules describe about 7 behaviours:
- bash-history clearing;
- a user-writable program connecting out;
- a user-writable program launched with `-server`;
- `whoami`/`env` under a user-writable ancestor;
- `ip neighbour`;
- `/etc/passwd` read to `/tmp`;
- `/etc/master.passwd`.

**Run 1 with the library (design data, `eval_runs/2026-10-08-lab-run1-s3/`):**

| | hand-written only | + learned rules |
|---|---|---|
| attack windows flagged | 1/8 | 8/8 |
| benign windows flagged | 1/12 (gate-pass 0/3) | 1/12 (gate-pass 0/3) |
| attack steps | 2/36 | 28/36 (95% CI 0.62–0.88) |
| learned rules' event precision | — | 1.0 |

**Not evidence.** The model saw these windows, and the simulated analyst approves a rule
only when every one of its alerts is labelled malicious. Zero benign alerts and precision
1.0 on run 1 therefore hold by construction. The one benign alarm left is the kill chain on
the benign script (ws-fin01, 13:00). It also pulls the overall event precision to 0.13 (all
windows) or 0.26 (gate-pass): learned-rule events are all malicious, the kill chain's are not.

**Diagnostic on the smoke operation (excluded from design and test; nothing changed because of it):**

| | result |
|---|---|
| attack windows | 7/8 |
| benign windows | 0/6 |
| event precision | 1.0 |
| steps | 12/68 |

- **Found:** the deployment, the history clear, and `whoami` under the agent.
- **Missed:** `cut -d: -f1 /etc/passwd` (run 1's account rules require `/tmp/` or `cat`) and `ps aux` (run 1 had no process discovery).

So precision carried over to an unseen operation; recall did not. Many active rules key on
the literal commands of run 1's CALDERA abilities. This is the Q3 risk the test design
covers: ≥2 test profiles not used in design.

**Before the test:**
- design operations 2 and 3 with other abilities and a burn-in;
- re-run induction with `--memory-from`;
- freeze, then score the test operations once.

**Duplicates merged (2026-10-08).** Rules that fire on exactly the same events in every
design window are one detection. They were merged label-free, keeping the most general
copy (`tools/rules_dedupe.py`; `rules_induce.py` now does it itself): 20 → 10 active rules.
Run 1 and the smoke diagnostic score identically before and after.
