# Ad-hoc triage test: ARGUS deciding while the attack runs, on the current lab

**What this is.** The test for the thesis's ad-hoc framing (amendment A4, `LAB_EVAL_PLAN.md`):
- **Ad hoc:** ARGUS decides at the moment a decision is needed, while an operation is still
  running, on whatever telemetry has arrived so far, and revises as more arrives.
- **Post hoc** (everything measured so far): ARGUS decides once a capture is complete.

The lab and the planned runs stay exactly as they are (`LAB_TEST_SUITE.md`,
`Test Setup/lab/RUN_CAMPAIGN.md`). Every run is scored twice: **ad hoc, as it happens**, and
**post hoc, afterwards**, from the same telemetry and the same frozen code.

**Rules that hold throughout** (as in `LAB_TEST_SUITE.md`):
- Attacks come only from CALDERA's own published abilities, picked by ATT&CK technique ID.
- The lab stays isolated while any operation runs.
- API keys are typed per run and never saved.
- Roles follow capture order (`lab_split.json`).
- Nothing is tuned on test operations.

---

## 1. The lab, as it is now

```
 Kali VM (UTM)                          4 Debian victims (QEMU)                    the Mac
 CALDERA server ── commands ──►  web01 · app01 · ws-dev01 · ws-fin01      log_receiver.py
                                  (+ ws-hr01 in tests 1 and 4)       ──►  captured/<run>/<host>/
                                  auditd · auth.log · persona       stream    │
                                  forward-logs.sh streams each new line        ▼
                                  as it is written                         ARGUS ad-hoc loop
                                                                          (live windows, re-triage
 tcpdump on the bridge ── pcap ── Zeek afterwards (post hoc only)          every minute) ─► workbench
```

What already exists:
- **The streaming:** every victim pushes `audit.log`, `auth.log` and its persona log to the
  Mac as they are written (`forward-logs.sh`, `log_receiver.py`).
- **Revisable decisions:** ARGUS's case store records every revision of a decision with its
  cause (`argus/api/store.py`).

What does not exist yet is listed in §3.

---

## 2. What the test answers

**Q4, timeliness** (added by A4). While an operation runs, does ARGUS raise its alerts early
enough to matter, without paging the analyst for nothing, and do its ad-hoc decisions end where
the post-hoc ones do?

| # | measure | definition |
|---|---|---|
| T1 | time to first alert | for each attack step the post-hoc arm detects: minutes from the step's start (CALDERA report time, offset-corrected) to the first ad-hoc revision whose alert includes that step's events. Reported as the median and 90th percentile |
| T2 | operation warning | minutes from an operation's first step to the first host flagged |
| T3 | caught in time | the share of detected steps whose host was flagged **before the operation ended** |
| T4 | agreement | at every window's close, its ad-hoc verdict and evidence against the post-hoc verdict on the same window. Same telemetry and same code, so any difference is a live-windowing defect |
| T5 | live false alarms | benign windows flagged **at any revision**, even if benign at close. The analyst would have been paged |
| T6 | flips | verdict changes (benign ↔ flagged) per window during its live revisions |
| T7 | blind spot in time | on log-clearing runs: minutes from the clear (report time) to the cleared host's blind spot appearing |
| T8 | analyst load | cases newly flagged per host-hour, as the analyst saw them live |

**Success, stated now, before any ad-hoc data exists:**

| measure | pass |
|---|---|
| T4 agreement | every closed window identical to post hoc |
| T1 time to first alert | median ≤ 5 minutes, 90th percentile ≤ 15 minutes |
| T5 live false alarms | no more than 1 per 20 host-windows (the post-hoc bar, counted at any revision) |
| T7 blind spot in time | ≤ 5 minutes on every cleared host |

Q1–Q3 keep their post-hoc definitions and are reported unchanged.

---

## 3. What ARGUS needs first (design-phase only)

Built and measured on the burn-in, run 1 and the design runs only, then frozen with
everything else.

| # | what | done when |
|---|---|---|
| L1 | **Live windows.** The receiver's growing files are converted on a fixed tick (1 minute) on the same 30-minute grid and with the same converter. The open window is rebuilt each tick; a window is final once its 30 minutes and a grace period have passed | a replay (L5) of a captured run ends with windows byte-identical to the post-hoc import |
| L2 | **Re-triage on each tick.** Each host's open window is decided again whenever new events arrived; every revision is kept with its cause and both clocks (§4). The workbench queue updates while the run goes on | in a replay, a host's case visibly moves from benign to flagged as its attack steps arrive |
| L3 | **Live coverage.** A host whose stream goes quiet beyond its normal gap, or whose audit daemon stops or log is cleared, is reported as a blind spot "since hh:mm" in its open window. Builds on P3 and P5 (`LAB_TEST_SUITE.md`) and the receiver's per-host arrival times | in a replay with a host's stream cut, the blind spot appears within 2 ticks |
| L4 | **Timing record.** Every revision stores the wall-clock time it was made and the latest event time it had seen. A scoring tool computes T1–T8 from the revisions and the CALDERA report | T1–T8 computed for a replayed design run |
| L5 | **Replay.** A captured run is streamed through the receiver at its original pace, or accelerated, from the captured files. It is the development and verification bench | run 1 replayed gives the same final decisions as its post-hoc scoring |
| L6 | **Test-time lock.** While a test operation is live, and until every test operation is scored, the workbench is read-only: no learning, approval, retirement or feedback. Watching is allowed; changing is not | the buttons are disabled and the API refuses those calls while the lock is on |

Prerequisites P1–P11 of `LAB_TEST_SUITE.md` still apply. Zeek stays post hoc (run over the
pcap afterwards), so network-based hypotheses (T1046, T1210) are ad-hoc only once Zeek runs
live, which is out of scope here.

---

## 4. Two clocks

Each revision records:
- **event time:** the newest audit record it includes;
- **decision time:** when ARGUS made it.

T1 uses the decision time against the step's start. The decision time minus the event time is
ARGUS's own lag: streaming plus the tick plus triage. It is reported separately, so a slow
network is not mistaken for a slow engine.

---

## 5. The runs

No new attack operations are needed: the campaign's planned runs (`RUN_CAMPAIGN.md` §3) each
give an ad-hoc and a post-hoc result.

| run | role | ad hoc |
|---|---|---|
| burn-in (already captured) | history | replay (L5) for T5 and T6 on benign activity only; design data |
| run 2 (recapture) | design 2 | live during the run; develops L1–L4 |
| run 3 | design 3 | live; log clearing → develops L3 and T7 |
| tests 1–4 | test | live at the final freeze, under the L6 lock; scored once |

**A live result can't be rerun.** So for test operations:
- the revisions are written append-only as they happen;
- after the run, a replay (L5) must reproduce the same decisions in the same order (only
  decision times may differ). If it does not, the run is reported as a defect, not re-scored.

---

## 6. Each run, step by step

Everything in `RUN_CAMPAIGN.md` §2 applies. On top of it:

**Before:**
1. Start `log_receiver.py <run>` as usual, then start ARGUS's ad-hoc loop on that run (L2).
   For a test operation, switch on the L6 lock first.
2. Confirm in the workbench that every victim's open window appears and updates each minute.

**During:**

3. Run the operation as usual. Do not touch ARGUS: no learning, no rule decisions, no restarts.
   If the loop stops, note the time in the manifest. The gap is reported, never filled in.

**After:**

4. Stop the loop after the last window has closed and its grace period has passed.
5. Run the post-hoc path exactly as before: `log_receiver.py <run> --check`, then Import capture.
6. Score T1–T8 from the revisions and the report (L4), and T4 against the post-hoc import.
7. Test operations only: replay (L5) and confirm the decisions reproduce.

---

## 7. Reporting

For every run, report:
- the post-hoc results (Q1–Q3, as planned);
- T1–T8, with their pass/fail against §2's bars.

Also report, whatever the result:
- the slowest-detected step and why;
- every transient false alarm (T5) with the evidence behind it;
- every verdict flip (T6);
- ARGUS's own lag (§4) separately from the streaming delay.
