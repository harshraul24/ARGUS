# S3 — ARGUS rules written by an LLM, judged without ground truth (design)

**Date:** 2026-10-01. **Status:** build steps 1–5 done (§10–§14); a test on fresh data is next.
**Builds on:** `S1_RESULTS.md` (frozen held-out evaluation), `S2_RESULTS.md` (process
lineage, canonical commands, sensor blindness), and the Odin experiments
(`odin/ODIN_V2_DESIGN.md` §22–24, `odin/REPORT_2026-09-17_steps1-3.md`).

---

## 1. The problem, stated precisely

ARGUS's detection logic is its hypothesis library, and a human wrote all of it, the
tactic-level primitives (P1–P3) included, with the CITAR data in view (S1 §5). The goal
of S3 is that an LLM writes the rules, and ARGUS decides which ones to trust, without
anyone labelling the data.

**The key distinction:** writing a rule does not need ground truth. The model brings its
knowledge of attacker behaviour, plus the telemetry it is shown. *Judging* a rule — is it
correct, general, robust, quiet on normal activity — is what normally needs labels. S3
replaces labels with checks that need none.

## 2. What the evidence already says

| finding | source |
|---|---|
| **Writing works.** Shown rare CITAR activity with no labels, the model wrote correct rules for the attack in every campaign: agent-spawned shells, discovery, Run-key persistence | Odin §22 |
| **Judging by frequency fails.** "Keep rules that fire on many captures" kept 13 background rules: held-out precision 0.00, 17/18 benign windows flagged | Odin §22 |
| **Judging by independent agreement works.** Keeping only rules that another independent induction confirmed on the same events: precision 1.00, 0/18 benign | Odin §23 |
| **The same principle guards ARGUS's LLM.** P5's corroboration gate cut P4's benign false positives from 2/5 to 0/5 | P5_RESULTS.md |
| **LLM rules copy names.** 65 of 67 Odin rules failed static rename analysis; the best keyed on the Caldera agent's name | Odin §24.7 |
| **7 of 67 rules could not match their own evidence**, all from copying errors (escaping, letter case, a Unicode hyphen, the wrong field), none invented | Odin §24.7 |
| **The pipeline around induction lost correct rules:** window boundaries counted as independent sightings, rules that selected the right events but never scored, and a router that hid the events convergence needed | Odin §24.8 |
| **ARGUS has the structure Odin lacked:** process-tree episodes, canonical commands, coverage and blind spots | S2 |

## 3. Judging rules without labels

A rule is trusted only after passing every check. Each check is deterministic, so each
decision can be explained.

| # | check | question it answers | catches | ready? |
|---|---|---|---|---|
| C1 | **Validity** | Can the interpreter run it safely? | unknown fields and operators, malformed rules | Odin `dsl.validate`; ported in step 1 |
| C2 | **Own evidence** | Does every literal occur in the evidence it was written from, and does the rule *fire* there? | copying errors, invented values, rules that select but never score | Odin `trust.verify`; the activation check is new |
| C3 | **Robustness** | Does it still fire on its own evidence when every executable running from a user-writable folder is renamed, and when commands are respelled equivalently? Both transforms are label-free (§11) | rules keyed on a name the attacker chose | `argus/rules/checks.py`; static rename analysis is reported as a flag, not a gate |
| C4 | **Rare in history** | Does it fire on at most 25% of this host's other captures? The history is assumed *mostly* benign, so a rule that generalises to the few other attacks passes | background rules, false-alarm generators | `argus/rules/checks.py` (§11) |
| C5 | **Independent agreement** | Does an independent source of a different kind flag the same events? Agreement between LLM rules is recorded but cannot promote on its own (§12) | misreadings, coincidences | `tools/rules_induce.py`; sources are below |

**Independent sources for C5**, strongest first:
1. A rule of a different origin (hand-written, imported Sigma, or LLM-written from
   another capture) firing on the same claims.
2. The same process-tree episode (S2), when the rule's hits descend from an episode root
   that other rules fired on.
3. A second, independent LLM induction reaching the same events (Odin §23). Independence
   is defined by process tree or capture, **never by window id** (Odin §24.8 defect 1).
4. A matching ATT&CK procedure example, drawn only from intelligence published before the
   capture.

**Assumptions stated, not hidden.** C4 assumes the reference period is mostly benign.
That is standard in detection engineering and already the basis of P3, and it is the one
place a false assumption can pass a bad rule. C5 assumes the independent sources don't
share a failure mode: two LLM runs share a model, which is why sources 1 and 2 rank
above 3.

## 4. How the system learns

The model's weights do not change. The **system** learns, at three levels:

1. **Rule library as memory (build now).** Every rule is stored with its checks, verdicts
   and history (Odin's store: semantic identity, lifecycle, reasons). The next prompt
   includes relevant outcomes, e.g. "a rule keyed on the agent's image failed C3; prefer
   lineage and canonical fields".
2. **Feedback (on deployment).** Analyst verdicts arrive through ARGUS's existing
   `/feedback` endpoint and update each rule's measured precision. ARGUS asks about the
   rules whose verdict would change the most decisions, instead of at random.
3. **Weights (later, optional).** Once hundreds of accepted and rejected rules exist, they
   form a preference dataset for fine-tuning a smaller model. It is not worth doing before
   that.

## 5. Architecture

```
telemetry ─► ARGUS claims + process lineage (S2)
          ─► WHERE TO LOOK: unexplained episodes and novelty, i.e. whole process trees
             no active rule accounts for (not "rarest events": rare ≠ malicious)
          ─► LLM WRITES a rule in the ARGUS rule format (§6), citing claim ids; the prompt
             steers it to L0/L1 fields, canonical commands and lineage structure, and
             fences attacker-written text as untrusted
          ─► CHECKS C1–C5 (§3)
          ─► LIFECYCLE: candidate → shadow → active → retired
                shadow = runs on live data, cannot move a verdict, measured
                every transition recorded with its reason
          ─► ARGUS ENGINE scores active rules exactly like hand-written ones:
             defeaters, coverage and blind spots, episodes, explanations
          ─► OUTCOMES + ANALYST FEEDBACK ─► the rule library ─► the next prompt
```

**Where the LLM can and cannot act:**
- **Can:** propose rules, and explain why.
- **Cannot:** set a verdict, bypass a check, edit a rule that is active, or remove another
  rule.
- **Recall floor (from ARGUS's LLM-1):** an LLM rule may add detections, but its
  exclusions may not suppress claims another active rule fires on. This closes the
  poisoning path in which attacker text persuades the model to exempt the attacker.

**Two operating modes:**
- **Autonomous** (the research claim): promotion is decided by C1–C5 alone.
- **Approval** (how real SOCs run detection-as-code): an analyst approves shadow → active.

Both use the same machinery. The thesis evaluates the autonomous mode.

## 6. One rule format

Hand-written, LLM-written and imported rules all use one JSON format, interpreted by
`argus/rules/`. Nothing is `eval`'d; operators come from fixed tables.

This is Odin's rule language, adapted to ARGUS claims (Odin reproduced ARGUS's original
16 matchers in it exactly), plus what the tactic primitives need:
- **`contains_any`:** substring tokens on the lower-cased text, and on its canonical form
  when S2's canonical matching is on. P1's semantics exactly.
- **`categories` + `distinct_categories`:** counting distinct behaviours (the discovery
  burst).
- **`affine` scorer:** P1's `a + b·n` strengths.
- **`sum` with a default**, for event counts.
- **Multi-valued fields:** `provenance.sensor_id` matches if any provenance matches.
- **Baseline fields:** `baseline.image_seen` and `baseline.lineage_seen` read the host's
  benign baseline (P3).
- **`chain`:** a rule made of other rules' indicators, with a kill-chain score and an
  `episode` scope that requires one process-tree root (S2).

A rule loads as an ordinary ARGUS `Hypothesis`, so the engine is unchanged.

**Engine change needed before step 3:** results are keyed by technique id. LLM rules
can share a technique, so they must be keyed by unique rule id.

## 7. Evaluation protocol

1. **Induce on the design campaigns only** (APT29, FIN6, OilRig): no labels, no campaign
   names in prompts.
2. **Freeze** the rule library and ARGUS (freeze manifest).
3. **Score once on the held-out campaigns** (Wizard Spider, menuPass), per attack step,
   with `tools/eval_heldout.py`. Compare against:
   - hand-written P1–P3 (S2);
   - pre-CITAR ARGUS;
   - imported Sigma rules, if built.
4. **The headline question:** do the label-free checks select good rules? Labels are used
   only here, to measure that selection.

**Also report:**
- rule survival per check;
- model calls and cost;
- robustness under the S2 transforms;
- precision of rules the checks rejected, which shows what the checks cost.

**Known risks:**
- **Leakage.** The model may know Caldera's public emulation plans. Mitigations: never
  name a campaign in a prompt, and confirm on DARPA OpTC, attacked with a different tool.
- **Small n.** Two held-out attack windows (48 steps). Report intervals.
- **One host with a scripted user.** C4's quiet-history assumption is easy to satisfy
  here and harder on a real, busy host.

## 8. What this does not change

- **ARGUS's engine, defeaters, coverage and explanation layers.** Rules are data fed into
  them.
- **The original seven technique hypotheses stay in Python for now.** Their Odin port
  predates the 2026-09-10 edit to T1210 and must be redone against current ARGUS claims.
- **P4/P5 (LLM hypotheses gated by corroboration)** stay as they are. S3's LLM writes
  reusable rules; P4 narrates one case.

## 9. Build order

| step | work | model calls | status |
|---|---|---|---|
| 1 | **One rule format.** `argus/rules/` interpreter + validator + loader; port the seven tactic hypotheses (TA0007, TA0009, TA0010, TA0011, TA0005, KILLCHAIN, NOVELTY) to JSON; prove exact parity with the Python versions on all CITAR windows, with lineage and canonical matching on and off | none | **done** (§10) |
| 2 | **Checks C1–C4** in ARGUS, run first on Odin's 67 existing LLM-written CITAR rules (converted to the ARGUS format) as a ready-made test set; C5 was added early, because two of its sources need no model calls | none | **done** (§11) |
| 3 | **Episode-driven induction** + lifecycle with shadow mode + C5, on design campaigns; rules keyed by unique id | yes | **done** (§12) |
| 4 | **Held-out evaluation** against hand-written P1–P3 (§7) | none | **done** (§13) |
| 5 | **Feedback loop** and rule memory in prompts | yes | **done** (§14) |

---

## 10. Step 1 results — one rule format (2026-10-01)

**Built.**
- `argus/rules/dsl.py` (interpreter and validator) and `argus/rules/loader.py` (JSON →
  `Hypothesis`).
- `argus/rules/builtin/tactics_p1_p3.json`: the seven tactic hypotheses as data, with
  token lists copied programmatically from the Python tuples so none could be mistyped.
- The validator's error messages name the valid alternatives, because in step 3 an LLM
  will repair rules from them.
- The engine is unchanged: rules load as ordinary hypotheses.

**Parity is exact** (`tools/rules_parity.py`, `eval_runs/rules_parity.json`). Every
indicator of the seven hypotheses, Python against JSON, was compared across:
- 64 captures (44 CITAR windows, 12 Linux, 8 synthetic benign);
- lineage on and off × canonical matching on and off;
- plus a mode that injects the real connection counts, so the beacon primitive fires,
  which it otherwise never does on CITAR.

| | comparisons | with a non-zero score | mismatches |
|---|---|---|---|
| indicator strength and hit set | 3,456 | 464 (192 of them beacon) | **0** |
| whole decision (disposition, severity, priority, scores, episodes, blind spots) | 432 | — | **0** |

Strengths are compared for equality, not within a tolerance. One documented difference
remains: P1's discovery burst lists a claim once per category it matches, while the
interpreter lists it once. Hit sets and scores are identical; only the rationale's
printed claim count and the 40-claim support display can differ.

**The evaluation is identical too.** `argus_rules_json` (the seven tactic hypotheses
loaded from JSON) equals `argus` on every metric, on both splits
(`eval_runs/2026-10-01-s3-step1/`).

**Two S2 bugs found by the parity check, and fixed.** Freeze
`ARGUS_FREEZE_2026-10-01-s3.json`:
1. **`canonical_token("/domain")` returned `domain`.** The switch was reduced as if it
   were a program path, so the discovery rule's domain category matched any command
   mentioning a domain (`%userdomain%`). On two benign windows (APT29 w07, menuPass w04)
   the discovery hypothesis scored 0.17, below the alert threshold.
2. **Switching canonical matching off did not fully switch it off.** The Python
   primitives used the extended token lists regardless of the switch.

   After both fixes, **no reported metric changed**, for any arm or split (checked
   field by field against `eval_runs/2026-10-01-s2/`). The two benign windows now score
   0, and the S2 ablation arms are true off switches.

**Tests.**
- ARGUS: 68 pass, of which 22 are new (`tests/test_rules.py`, plus 2 regression tests
  for the S2 bugs).
- A mutation check broke nine interpreter properties in turn:
  - canonical matching;
  - multi-valued fields;
  - sum defaults;
  - lowercased grouping;
  - distinct categories;
  - the affine offset;
  - episode scope;
  - field-path validation;
  - the kill-chain order bonus.

  All nine are caught. Two needed new tests first: multi-sensor claims and chain
  ordering.

**Still Python.** The seven original technique hypotheses (§8) stay in Python.

**Next (step 2).** Checks C1–C4, run first on Odin's 67 LLM-written CITAR rules converted
to this format.

---

## 11. Step 2 results — the checks on Odin's 67 LLM-written rules (2026-10-01)

`argus/rules/checks.py` (C1–C5), `argus/rules/convert.py` (Odin → ARGUS import), and
`tools/rules_checks.py`, output in `eval_runs/2026-10-01-s3-step2/`. No model calls.
Freeze `ARGUS_FREEZE_2026-10-01-s3-step2.json`.

**The test set.** 67 rules written by `gpt-oss:120b` through Odin, from Wizard Spider
and OilRig windows, with no labels. All 67 imported. Odin's split is used, so the
comparison with Odin's own screens is like-for-like:
- history (C4) = the other Wizard Spider and OilRig windows;
- held out = FIN6, menuPass, APT29.

The checks read no labels. Labels are used only afterwards, to grade.

### Found first: ARGUS never saw file paths on CITAR

The eCAR collector kept facts named `path` and `target`. eCAR calls them `file_path` and
`target_image`, so ARGUS had never received a file path, a process-access target or an
access mask; process creations also lacked `image_path`. The collector now carries every
eCAR fact under its own name, except the per-event count, which is carried as
`dedup_count`: the beacon reads `count` (S2 §4). **Every S2 and S3-step-1 metric was
re-checked and is unchanged**, and the beacon guard test still passes.

### Result

| set (Odin's split) | rules | held out: attack windows | benign windows | event precision | attack steps |
|---|---|---|---|---|---|
| all 67 LLM rules | 67 | 3/3 | 18/18 | 0.002 | 24/52 |
| Odin's reproduction screen | 13 | 3/3 | 17/18 | 0.00 | 0/52 |
| Odin's convergence screen (§23) | 3 | 2/3 | 0/18 | 1.00 | 21/52 |
| ARGUS C1–C4 (shadow) | 9 | 2/3 | 8/18 | 0.00 | 0/52 |
| **ARGUS C1–C5 (active)** | **0** | 0/3 | **0/18** | — | 0/52 |

**Where rules fail** (first failed check):
- C4 rare history: 29 (background recurring through the host's history);
- C2 own evidence: 18
  - 12 **dead scores**: the rule selects its evidence but its floor is never reached;
  - 6 broken literals: over-escaped 3, letter case 1, Unicode hyphen 1, wrong field 1;
- C3 robustness: 11;
- C5 agreement: 9.

### What it shows

1. **The checks promote nothing false.** Odin's reproduction screen promoted 13
   background rules; the checks reject all of them.
2. **The three rules labels call perfect are tied to one tool, and C3 finds that without
   labels.** Odin's convergence set scores precision 1.00 on CITAR, but all three rules
   key on the parent `splunkd.exe`, which runs from `C:\Users\Public`.
   - C3 renames every executable seen running from a user-writable folder, a set decided
     from `image_path`, never from ground truth. All three stop firing on their own
     evidence.
   - Their CITAR precision is a property of one emulation tool: all five campaigns share
     that agent name. A different operator would evade them.
3. **One rule is correct and robust but unconfirmed.** `registry-run-key-addition`
   (Emotet persistence via `reg.exe` from System32) passes C1–C4 and sits in shadow.
   C5 finds no independent source: the hand-written P1–P3 have no persistence
   primitive, and no second LLM rule found it. Shadow is the intended state for it: the
   rule runs and is measured, but cannot move a verdict.
4. **C5 is load-bearing.** The other 8 shadow rules are background (OneDrive, Windows
   Update, error reporting, Defender) rare enough to pass C4. Only C5 stops them, the
   same pattern as Odin §23.
5. **Static rename analysis cannot be a gate.** It also rejects four of ARGUS's seven
   hand-written tactic rules, whose detection S1/S2 measured as unaffected by renaming,
   because it counts every command token as renameable. It is now a reported flag, and
   C3 gates on the dynamic transforms.
6. **C4's limit matters less than C5.** Sensitivity of the C1–C4 set on held-out windows:
   - at 0.10: 6 rules, 1/18 benign;
   - at 0.25: 9 rules, 8/18 benign;
   - at 0.50: 10 rules, 14/18 benign.

   Precision is 0.00 at every limit, because C4 alone never isolates attack rules.

**Conclusion for step 3.** The checks work as a filter: nothing false got through, and
brittle and background rules were rejected for stated reasons. But the rule *supply* is
the bottleneck: none of Odin's 67 rules is correct, robust and confirmed. Step 3 must
change how rules are written, not how they are judged:
- **episodes as the unit:** show the model whole process trees;
- **steer away from renameable names:** prompt the model toward lineage, system-binary
  behaviour and canonical commands, and give it C3 findings in the repair loop;
- **repair dead scores** with the C2 diagnosis;
- **more independent sources for C5:** a second induction per episode, and episode
  membership.

**Caveats.**
- C5's hand-written source was designed with CITAR in view.
- The user-writable rule treats `C:\ProgramData` as writable, so Defender's own binaries
  count as renameable. That affects only background rules here.
- One LLM run: the Odin rules' supply is one sample of what this model writes.

**Tests.**
- ARGUS: 78 pass (10 new in `tests/test_checks.py`).
- A mutation check broke seven properties in turn, and all seven are caught:
  - trusted directories;
  - dead-score detection;
  - the C3 gate;
  - C5 independence;
  - over-escape diagnosis;
  - the C4 rate;
  - respelling.

---

## 12. Step 3 results — an LLM writes rules from novel episodes (2026-10-01)

`tools/rules_induce.py`; output in `eval_runs/2026-10-01-s3-step3/` (run 1 kept in
`…-run1/`). Freeze `ARGUS_FREEZE_2026-10-01-s3-step3.json`. Model `gpt-oss:120b`
(Odin's), temperature 0, seed 7, every call cached. **Design campaigns only** (APT29,
FIN6, OilRig: 23 windows). Wizard Spider and menuPass were never loaded.

### Built

- **Episodes** (`argus/rules/episodes.py`). A process launch is novel when its
  (parent > image) pair occurs in at most 25% of the host's other captures. Novel launches
  climb to their highest ancestor that is not a session hub and did something in the
  capture: the episode root. Lone novel events are skipped.
  - No labels: the only reference is the host's other captures.
  - Result: 36 episodes. The attacker's tree is the most novel tree in each of the three
    attack windows (37, 31 and 45 novel launches).
- **Rendering.**
  - Attacker-written strings are fenced as «untrusted data».
  - IP addresses, account SIDs, and user and host names are redacted.
  - No campaign or window name reaches the model.
  - Rendering is independent of Python's hash seed: prompts are cache keys, and the first
    launch was stopped before any call when a 2-character difference showed they were not.
- **Write–check–repair** (`argus/rules/induce.py`).
  - The model writes up to 3 rules per episode, and C1–C3 run on the episode.
  - Failing rules go back, at most twice, with the checks' own findings. Only failing
    rules are sent back.
  - Written rules may not read the P3 baseline (chosen with labels) or use chains.
- **Lineage fields in the rule language:** `lineage.user_writable`,
  `lineage.parent_user_writable` and `lineage.ancestor_user_writable`. They say "spawned by
  something in a user-writable folder" without naming it. They survive C3's rename by
  construction, but not relocation by an administrator.
  - `user_writable` is now shared by C3 and the DSL, with carve-outs for folders inside
    `C:\Windows` that users can write (`Temp`, `Tasks`, `Tracing`, …). Step 2 reproduces
    exactly with it.
- **Library** (`argus/rules/library.py`):
  - candidate → shadow → active → retired, or rejected;
  - every transition is recorded with its reason;
  - a judged rule cannot be edited; a fix is a new rule.
- **Engine.**
  - Results are keyed by unique rule id.
  - `Config.shadow` rules are scored into `Decision.shadow` and cannot change any other
    field of the decision (tested).
- **Unchanged:** Python–JSON parity (0 mismatches), step 2 (identical), and the held-out
  evaluation (identical to step 1).

### Two runs, one prompt defect

| | run 1 | run 2 (the result) |
|---|---|---|
| model calls | 60 | 43 |
| round-0 rules failing C1 | 39 of 45 | 0 of 34 |
| episodes the model declined as routine | 18 of 36 | 22 of 36 |
| C1–C3 / C1–C4 / active | 40 / 24 / 2 | 32 / 24 / 6 |

**Run 1:** my grammar labelled its example clauses (`{"literal": {...}}`), and the model
copied the label as an operator. The repair loop fixed most rules, at the cost of a round
on almost every episode. The examples are now plain clauses (a test checks each validates),
and the prompt warns that short `contains_any` tokens ("a", "-f", "http") match almost
every command: C4 had rejected rules built on them at 91–95%. **Before run 2 it was decided
that run 2's library is the step 3 result**, whatever it scored.

### Result (design data — the model saw these windows; step 4 is the test)

| set | rules | attack windows | benign windows | event precision | attack steps |
|---|---|---|---|---|---|
| C1–C3 (after repair) | 32 | 3/3 | 17/17 | 0.12 | 35/62 |
| C1–C4 | 24 | 3/3 | 12/17 | 0.74 | 32/62 |
| C1–C5, as designed (any independent source) | 8 | 3/3 | **3/17** | 0.65 | 12/62 |
| **C1–C5, a non-LLM source required (adopted)** | **6** | **3/3** | **0/17** | **1.00** | 12/62 |
| hand-written P1–P3 | 6 | 3/3 | 0/17 | 0.82 | 51/62 |
| hand-written + the 6 active LLM rules | 12 | 3/3 | 0/17 | 0.83 | 51/62 |

**The six active rules**, each confirmed by a hand-written rule on the same events:
- PowerShell download (`invoke-webrequest` / `-outfile`);
- PowerShell download-and-execute with `-executionpolicy bypass` and `downloadstring`;
- ingress tool transfer via `invoke-multipartformdataupload`;
- `cmdkey` credential manipulation;
- `trustdmp` AD enumeration;
- an `ad.7z` archive.

The last four require a user-writable ancestor (`lineage.ancestor_user_writable`). No rule,
in any round of either run, names the Caldera agent; all three of Odin's best rules did.

### What it shows

1. **The checks now promote correct LLM rules.** Odin's 67 rules gave 0 active (§11). Run 1
   gave 2 and run 2 gave 6, all with precision 1.00 and no benign window flagged.
2. **Agreement between LLM rules is not independent on one host, and C5 is revised.** The
   two false actives under the designed C5 confirmed only each other: a CompatTelRunner
   `-maintenance` rule written from APT29 and a Defender `-IdleTask` rule written from
   OilRig, agreeing on background in a third window.
   - Two inductions share a model (the risk §3 named), and routine background recurs
     across one host's recordings.
   - Across Odin step 2 and both runs, LLM–LLM agreement promoted only background rules.
     Every correct rule was confirmed by a non-LLM source.
   - **Revised C5:** LLM–LLM agreement is recorded, and a rule it alone supports stays in
     shadow with that reason. Promotion needs a source of a different kind: hand-written
     now; imported Sigma, threat intelligence or an analyst later.
   - This revision was made on design data after label-graded inspection. Its justification
     is §3's stated assumption, and step 4 reports both C5 variants.
3. **Episodes and steering fix what sank Odin.** No rule keys on the agent, and no literal
   was mis-copied (Odin: 7 of 67). The model declines most background episodes itself.
4. **The LLM rules add precision, not yet coverage.** Their attack steps are a subset of
   what the hand-written rules find (51/62 either way), because C5 can only confirm what a
   hand-written rule also sees.
   - Correct rules for behaviours no hand rule covers wait in shadow, for want of a
     confirming source: plink reverse-SSH tunnel (precision 1.00); run 1's Startup-folder
     shortcut persistence (1.00).
   - This is the autonomy limit of a C5 that needs a different kind of source, and the case
     for the approval mode (§5) or an imported rule base as a second source.

### Caveats

- **C3 covers attacker-chosen executable names and command spellings, not other
  attacker-chosen literals.** Three active rules key on names from the emulation plans: the
  output file `ad.7z`, `trustdmp`, and the upload function
  `invoke-multipartformdataupload`. They may not transfer to another operator; step 4 will
  show it.
- In-sample: the design numbers are the model's own training view of the data.
- C5's hand-written source was designed with CITAR in view (as in §11).
- One model, one seed per run.

**Cost:** run 2 used 43 calls (~140k tokens in, ~13k out, 566 s of model time); run 1 used
60 calls (~214k / ~28k).

**Tests:**
- ARGUS: 93 pass (15 new in `tests/test_induce.py`).
- A mutation check broke 13 step-3 properties, and all 13 are caught (one needed a new
  test first). The properties: shadow cannot move the verdict; keying by rule id; the parent
  lineage field; writable carve-outs; the episode root stopping at inactive ancestors; IP
  and name redaction; repair superseding; passing rules not resent; the reserved baseline;
  lifecycle order; immutability of judged rules; hash-seed independence.

**Frozen input to step 4:** `eval_runs/2026-10-01-s3-step3/library.json` (sha256
`d64069bf907987fa…`): 6 active, 18 shadow, 18 rejected.

---

## 13. Step 4 results — the frozen library on the held-out campaigns (2026-10-01)

`tools/rules_heldout.py`; output in `eval_runs/2026-10-01-s3-step4/`. No model calls.
- **Inputs.** Library sha256 `d64069bf907987fa…`, as frozen in step 3. ARGUS freeze
  `ARGUS_FREEZE_2026-10-01-s3-step3.json` matches.
- **Held out:** Wizard Spider and menuPass (2 attack windows, 48 steps, 16 benign windows).
  They were never loaded in step 3; labels are read only to grade.
- **Reproduction:** the hand-written arms reproduce step 1 exactly. The one shared-code
  change, keying `eval_heldout.score_window` alerts by rule id, moved no number.

### Rule level (a rule fires when its score is above 0)

| rules | n | attack windows | benign windows | event precision | attack steps |
|---|---|---|---|---|---|
| every judged, valid rule | 34 | 2/2 | 16/16 | 0.08 | 22/48 |
| rejected at C4 | 8 | 2/2 | 16/16 | 0.05 | 6/48 |
| passed C1–C4 | 24 | 2/2 | 10/16 | 0.73 | 22/48 |
| shadow (C1–C4, not C5) | 18 | 2/2 | 10/16 | 0.72 | 22/48 |
| active, C5 as designed (any source) | 8 | 1/2 | **3/16** | 0.14 | 1/48 |
| **active, C5 revised (non-LLM source)** | **6** | **1/2** | **0/16** | **1.00** | **1/48** |
| hand-written P1–P3 | 6 | 2/2 | 0/16 | 0.76 | 37/48 |
| hand-written + active (revised) | 12 | 2/2 | 0/16 | 0.76 | 37/48 |

### System level (ARGUS decisions at the operating point)

| arm | attack windows | benign windows | steps (95% CI) | event precision |
|---|---|---|---|---|
| argus (hand-written S2) | 2/2 | 0/16 | 38/48 (0.66–0.88) | 0.80 |
| **argus + active LLM rules (revised C5), shadow measured** | **2/2** | **0/16** | **38/48** | **0.80** |
| argus + rules the designed C5 would promote | 2/2 | **3/16** | 38/48 | 0.77 |
| pre-CITAR ARGUS (7 technique hypotheses) | 0/2 | 0/16 | 0/48 | — |
| pre-CITAR + active LLM rules instead of P1–P3 | 1/2 | 0/16 | 1/48 (0.00–0.11) | 1.00 |

ARGUS with the LLM rules is unchanged under every robustness transform (renamed agent,
renamed agent and C2 flags, masquerading as svchost, equivalent commands, no network
telemetry): 2/2 attack, 0/16 benign, 38/48 steps.

### What it shows

1. **The checks select safe rules, not general ones.**
   - Every promoted rule that fires on held-out data is correct (precision 1.00), and none
     raises a false alarm.
   - But only 1 of the 6 active rules fires at all: the upload rule keyed on
     `invoke-multipartformdataupload`, a helper the Caldera emulation plans share. It finds
     one Wizard Spider step, which the hand-written rules already find.
   - The other five match plan-specific literals (`ad.7z`, `trustdmp`, the exact download
     cmdlets of FIN6/OilRig/APT29) and never fire on Wizard Spider or menuPass.
   - Net effect on ARGUS: none, in either direction.
2. **LLM rules cannot yet replace the hand-written tactic rules.** Pre-CITAR ARGUS plus
   the LLM rules finds 1 of 48 held-out steps; with hand-written P1–P3 it finds 38.
3. **The C5 revision holds out of sample.** It was made on design data after
   label-graded inspection (§12). On held-out data:
   - the designed C5 adds 3 of 16 benign windows to ARGUS's alerts, all from the Defender
     idle-task rule, which only another LLM rule had confirmed;
   - the revised C5 adds none.
4. **C4 cost nothing.** The 8 rules it rejected fire on 16 of 16 held-out benign windows
   at precision 0.05.
5. **Shadow did its job on the strongest held-out rule.** "SystemCertificates registry keys
   added by a descendant of a user-writable program" finds 22/48 held-out steps at
   precision 0.91, but flags 3 of 16 benign windows.
   - In effect it detects PowerShell or .NET start-up under the agent.
   - It stayed in shadow, measured, because no hand-written rule watches registry events.
   - Alerting on it would have cost 3 false alarms. It is the case the approval mode (§5)
     and the feedback loop (step 5) exist for.

### Why the rules do not generalise, and what to change

Each cause is a design issue found by inspecting the pipeline, not by tuning to these
labels:
- **The prompt overstates C2.** It says every literal must occur in the episode. In fact
  C2 requires only one member of each `contains_any` group, which is how P1's broad token
  lists pass. Told otherwise, the model wrote one- or two-token rules naming exactly what
  it saw.
  - **Change:** state C2 precisely, and ask for the behaviour class: other commands and
    tools that do the same thing.
- **C3 tests attacker-chosen executable names and command spellings, but not other
  attacker-chosen literals.**
  - **Change:** a label-free transform that renames the files an episode's user-writable
    tree creates, and the script functions it defines. Rules keyed on `ad.7z` or
    `trustdmp` would then fail C3.
  - **Trade-off:** it would also reject the one rule that transferred, which transfers only
    because every campaign used the same tool.
- **C5 can confirm only what a hand-written rule also sees,** so correct rules for uncovered
  behaviours wait in shadow (plink tunnel, Startup persistence, the SystemCertificates
  rule).
  - **Change:** a second non-LLM source (imported Sigma rules), or analyst approval of
    shadow rules on their measured record (step 5).

**Evaluation constraint.** The held-out campaigns have now been used for S3. Any change
above must be measured on data neither the rules nor the changes have seen: DARPA OpTC
(needs download permission) or new captures. Re-scoring Wizard Spider and menuPass after
changing the pipeline would be tuning on the test set.

### Caveats

- Small n: 2 held-out attack windows and 48 steps. Intervals are reported.
- The labels count every event in the agent's process tree as malicious, so event precision
  favours rules that fire on agent side-effects (the SystemCertificates rule).
- One model, one seed. The library is one sample of what this pipeline writes.

---

## 14. The three fixes and step 5 — feedback and rule memory (2026-10-01)

`tools/rules_step5.py` and `tools/rules_induce.py --memory-from …`; output in
`eval_runs/2026-10-01-s3-step5/`. Freeze `ARGUS_FREEZE_2026-10-01-s3-step5.json`. Before
run 3 it was decided that run 3, merged and given one feedback round, is the step 5 result.

### The three fixes (S3 §13)

1. **The prompt states C2 precisely.** Inside a list of alternatives only one has to occur
   in the episode. The prompt also asks for the behaviour class, not the one instance shown.
2. **C3 renames created artifacts.** A third label-free transform renames the files that an
   episode's user-writable process tree created, and the script functions its commands
   define (`checks.created_artifacts`).
   - Applied to the step 3 library, it retires the `ad.7z` rule. It keeps `trustdmp`,
     because `-sc trustdmp` is a built-in AdFind option, so the token describes what the
     command does.
   - The hand-written discovery rule recognised FIN6 only by the downloaded tool's name
     `adfind`. Hand-written rules are not gated by C3; this is recorded as a finding.
3. **Analyst approval** (S3 §5): a shadow rule becomes active when every alert it raised in
   the review period has been reviewed and confirmed. Importing Sigma rules as a second
   non-LLM source needs a download and is not done.

### Step 5 (`argus/rules/feedback.py`)

- **Verdicts:** each rule's precision is estimated from analyst verdicts (Beta(1, 1)
  prior, Wilson lower bound).
- **Promotion and retirement:** shadow → active on 2 malicious verdicts out of 2 (or on
  complete review); shadow or active → retired when the posterior mean is ≤ 0.40. Every
  move records its verdict counts.
- **What to ask:** the expected lifecycle moves per verdict (a Beta-predictive lookahead to
  the fewest verdicts that could decide), weighted by the decisions the rule would change.
  - The first version used plain uncertainty sampling. It spread 10 verdicts over 10 rules
    and decided nothing.
- **Rule memory:** confirmed rules, analyst-retired rules, and the commonest failure reasons
  go into every prompt. Only observed outcomes are included, never ground truth.
- **In evaluation, the analyst is simulated:** its verdict on a (rule, capture) alert is
  malicious when at least half the selected events are labelled malicious. Only design
  labels are read.

### Results

**Feedback, design period.** False alarms avoided, by number of analyst verdicts:

| verdicts | value-based | random (mean of 20) |
|---|---|---|
| 5 | 7 | 1.5 |
| 10 | 14 | 5.0 |
| 20 | 23 | 12.9 |
| 40 | 28 | 25.5 |

- Correct promotions are rare under both strategies (at most 1 rule).
- The value strategy spends a small budget retiring rules that would change decisions,
  which here means rules that would add false alarms. Correct rules that fire only on
  attack windows ARGUS already flags change no decision, so they rank low. At 10 verdicts
  per round, no shadow rule was approved in either round.
- One rule retired by verdicts, "SystemCertificates registry", is correct event by event,
  but its only effect on decisions is false alarms.

**Run 3** (fixed prompt, the new C3, memory):
- 42 calls; the model declined 19 of 36 episodes.
- 1 new active rule: PowerShell `Compress-Archive` for exfiltration, confirmed by a
  hand-written rule.
- 22 new shadow rules. Several are correct on design data (precision 1.00, no benign
  windows): curl upload, `.7z` staging, cscript `.vbs`, a Startup-folder shortcut, WMIC
  remote execution, an SSH reverse tunnel.
- Feedback round 2 retired 5 noisy rules (18 false alarms avoided) and approved none.

**Final library:** 6 active, 30 shadow, 11 retired, 39 rejected (sha256
`283dbe29c88657b2…`).

**Held-out second look — exploratory, not a test.** The fixes were motivated by the step 4
result on these campaigns.

| rules | n | attack windows | benign windows | event precision | attack steps |
|---|---|---|---|---|---|
| active | 6 | 1/2 | 0/16 | 1.00 | 1/48 |
| shadow | 30 | 2/2 | 13/16 | 0.02 | 1/48 |
| retired by analyst verdicts | 10 | 2/2 | 9/16 | 0.81 | 22/48 |
| hand-written P1–P3 | 6 | 2/2 | 0/16 | 0.76 | 37/48 |

- ARGUS with the active rules is unchanged: 2/2 attack, 0/16 benign, 38/48 steps.
- Of the design-correct shadow rules, only cscript `.vbs` fires on held-out attack events.
- The SystemCertificates rule that verdicts retired would have added 9 of 16 benign
  windows.

### What it shows

1. **The loop works end to end, label-free where it matters.**
   - Novel episodes are found without labels; the model writes rules; checks judge them.
   - A lifecycle keeps every rule with its reasons; analyst verdicts promote and retire;
     memory carries outcomes into the next prompt.
   - Trusted rules are correct wherever they fire: precision 1.00, and no held-out false
     alarm in either look.
2. **It does not yet write rules that generalise.** Even with the fixes, the trusted rules
   find 1 of 48 held-out steps against 37–38 for hand-written rules. The model, given one
   campaign's episode, still writes for that campaign's tools and names.
3. **Feedback is most useful for removing noise.** Value-based questions find rules that
   would raise false alarms about 2–4 times faster than random review. Promotion of correct
   new rules needs a larger review budget or a second non-LLM source.
4. **CITAR is the limit.** Five campaigns from one emulation tool on one host is too
   little variety to show generalisation, and the held-out campaigns are now spent. The
   next result must come from fresh data (DARPA OpTC, with download permission, or new
   captures).

**Tests:** ARGUS 102 pass (9 new in `tests/test_feedback.py`). A mutation check broke 8
new properties; 7 are caught, and the eighth is an equivalent mutant (a redundant guard).
