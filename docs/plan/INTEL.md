# Community intelligence in ARGUS (2026-10-06)

**Status:** steps 2–3 done. Sources downloaded (with your approval), dated snapshots made, and
Sigma converted to ARGUS rules and checked on real data. Sigma is used only as a second,
non-LLM confirming source in C5 (step 3), never to raise alerts on its own.

## Sources (`intel/sources/`, full history)

| source | what | licence |
|---|---|---|
| SigmaHQ/sigma | community detection rules | Detection Rule License 1.1 |
| GTFOBins | how Linux binaries can be misused | GPL-3.0 |
| LOLBAS | how Windows binaries can be misused | GPL-3.0 |
| MITRE ATT&CK v13.1 and v19.2 | techniques and procedure examples | ATT&CK Terms of Use |

## Snapshots (`tools/intel_snapshot.py`, `intel/snapshots/<name>/MANIFEST.json`)

Intelligence is never read live. A capture may only be scored with a snapshot taken
before it was recorded.

| snapshot | as of | Sigma commit | Sigma / GTFOBins / LOLBAS files | ATT&CK | for |
|---|---|---|---|---|---|
| `citar` | 2023-07-01 | `f0dc10327b` | 2,645 / 379 / 184 | v13.1 | CITAR (first capture 2023-07-25) |
| `lab` | 2026-10-06 | `ca24243a6e` | 3,151 / 478 / 248 | v19.2 | the lab corpus (no design or test capture exists yet) |

## Sigma → ARGUS (`argus/rules/sigma.py`, `tools/sigma_import.py`)

- **Exact or refused, and narrow, never broaden.** An alternative needing a field ARGUS
  lacks is dropped, and the rule is marked `narrowed`. The same field anywhere else refuses
  the rule, with the reason.
- **Matching:** every value becomes a case-insensitive anchored regex, keeping Sigma's
  matching semantics including wildcards.

| snapshot | converted | narrowed | refused | main refusal reasons |
|---|---|---|---|---|
| `citar` | 1,148 | 403 | 1,496 | logsource ARGUS has no data for (675), field not in ARGUS telemetry (374), not Windows/Linux (373) |
| `lab` | 1,594 | 541 | 1,556 | logsource (701), not Windows/Linux (524), field (253) |

**Checked on real data** (`tests/test_sigma.py`):
- every converted rule validates, and every refusal has a reason;
- no rule postdates its snapshot;
- the whoami rule fires on exactly the whoami launches of three real CITAR attack windows;
- real rules that AND a known field with a missing one are refused, not broadened. A
  deliberate broadening bug is caught.

**First look (pipeline check, not an evaluation):**
- APT29's attack window: 21 Sigma rules fire, almost all on attack events.
- A benign window: 4 fire (WMI loads, tasklist, account discovery, systeminfo).
- Sigma alone raises false alarms, which is why it confirms rules in C5 rather than
  raising alerts.
- Speed: all 1,148 rules take about 7–8 s per window.

## Step 3 — Sigma as a second C5 source (CITAR design data, 2026-10-07)

`tools/rules_sigma_c5.py` → `eval_runs/2026-10-06-intel-step3/`. The step-5 library's 36
shadow and active LLM rules, with C5 sources: the hand-written rules, plus `citar`-snapshot
Sigma rules. Decided before running: a Sigma rule confirms only if it is itself quiet in
history (C4, at most 25% of design windows). 54 of 1,148 Sigma rules fire on design windows;
50 are quiet.

Design data; labels used only to grade:

| C5 sources | active LLM rules | attack windows | benign windows | event precision | attack steps |
|---|---|---|---|---|---|
| hand-written only (before) | 6 | 3/3 | 0/17 | 1.00 | 11/62 |
| hand + Sigma (quiet), as pre-stated | 14 | 3/3 | **1/17** | 0.87 | **18/62** |
| hand + Sigma (any) | 14 | same | same | same | same |

**Newly promoted by Sigma agreement:**
- 6 correct rules, each with precision 1.00 and no benign windows: curl upload, cscript
  `.vbs`, a plink reverse tunnel (two rules), a Startup-folder shortcut, WMIC remote
  execution.
- 2 wrong rules: `cmd` deleting OneDrive files or folders (routine maintenance).

**Why the 2 wrong rules got in:** both were confirmed only by Sigma rules the community
rates **low** ("File Deletion Via Del", "Directory Removal Via Rmdir"). Every correct
confirmation came from **medium or high** rules. Requiring Sigma `level >= medium`
removes both. On this data that gives 12 active rules, 0/17 benign windows, precision
1.00 and 18/62 steps.
- That filter was chosen **after** seeing these labels, so it is not claimed as a CITAR
  result. It is pre-registered for the lab test (`LAB_EVAL_PLAN.md` F8).

**What it shows:** a second, non-LLM source lifts C5's autonomy limit. Correct LLM rules
for behaviour no hand-written rule watches now get confirmed, and attack steps found by
trusted LLM rules rise from 11 to 18 of 62. As with LLM–LLM agreement, the confirming
source's own trustworthiness matters.

## F3 — behaviour vocabulary from Sigma tactic tags (2026-10-07)

`tools/behaviour_vocab.py` → `intel/snapshots/<name>/behaviour_vocab.json`;
`argus/normalize/behaviour.py`; rule field `behaviour.tactics`.

- **What it is:** for every Windows/Linux process-creation Sigma rule, the programs it
  selects are credited with the rule's ATT&CK tactic tags. Detection metadata only; no
  labels, nothing written by hand.
- **Split credit:** a rule naming twelve programs (the web-shell rules) gives each 1/12, so
  a long list cannot stamp its tactic on every program it names.
- **General-purpose programs:** a tactic is kept for a program only when it carries at
  least 25% of that program's weight.
- **Size:** `citar` covers 718 programs (748 rules, sha256 `c66fc64a…`); `lab` covers 822
  (739 rules, `79d88ce1…`).
- **Results:** `whoami`, `id`, `hostname`, `ps`, `net` → discovery on both platforms;
  `cmd`, `powershell`, `bash` → execution. Community quirks are kept, not hand-edited: in
  `lab`, `tasklist` leans credential-access (a Sigma rule about finding `lsass`).
- **Off by default:** without a loaded vocabulary the field is None. A rule asks for
  `"behaviour.tactics": "discovery"`, and it matches any program carrying that tag.
- **Attacker control:** the field is looked up by program name, which the attacker chooses
  for anything run from a user-writable folder. It is therefore control level L2, and C3's
  rename test exercises it.

**Real-data profile** (process launches tagged *discovery*):

| data | attack launches | other launches |
|---|---|---|
| CITAR design (Windows, 2023 vocab) | 22% | 5% |
| lab smoke (Linux, 2026 vocab; pipeline check only) | 34% | 10% |

One vocabulary works across both platforms. It is evidence for rules, not a detector.

**Tests** (`tests/test_behaviour.py`, real data):
- discovery programs share a tactic on both platforms;
- credit splitting holds (removing it fails 3 tests);
- the field is absent without a vocabulary;
- one rule finds `whoami` on Windows (OilRig) and Linux (lab).

Writing these tests also exposed that the Sigma whoami test was vacuous on two of its three
windows. It now requires a window with real whoami launches.

**Not yet wired into ARGUS's tactic rules or the LLM prompt.** That is F3's design-phase
use (`LAB_EVAL_PLAN.md`): measured on lab design captures, frozen before the test.

## Next

1. ~~Sigma as a C5 source on CITAR design data~~ (done above).
2. ~~Shared behaviour vocabulary (F3)~~: built from Sigma tactic tags (above). GTFOBins/LOLBAS are downloaded but not used.
3. ATT&CK procedure examples in the rule-writing prompt.

The lab test uses the `lab` snapshot, frozen with ARGUS before scoring.
