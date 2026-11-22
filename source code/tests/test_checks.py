"""Label-free rule checks (argus/rules/checks.py) on the REAL agent episode of run1 (web01):
the CALDERA agent `splunkd`, run from the user's home, launching `sh -c env|whoami|...`.

Run: .venv/bin/python -m pytest tests/ -q   (from `source code/`)
"""
from __future__ import annotations

from argus.reason.context import CaseContext
from argus.rules import checks as C
from argus.rules import load_rules, to_hypotheses

from lab_data import agent_episode, needs_lab

pytestmark = needs_lab


def _rule(select, score=None, rid="r"):
    ind = {"name": "i", "weight": 1.0, "required": True, "select": select}
    if score:
        ind["aggregate"] = [{"as": "n", "op": "count"}]
        ind["score"] = score
    return {"id": rid, "technique": "T0", "name": rid, "indicators": [ind]}


def _hyp(rule):
    return to_hypotheses(load_rules([rule]))[0]


def _ctx(claims):
    return CaseContext(claims=claims)


def _ep():
    return agent_episode().claims


# ------------------------------------------------------------------ C2 own evidence

def test_c2_passes_a_rule_grounded_in_and_firing_on_its_evidence():
    r = _rule({"claim_type": "process_create", "facts.image": "whoami"})
    chk = C.c2_own_evidence(r, _hyp(r), _ep(), _ctx(_ep()))
    assert chk.passed and chk.data["origin_score"] == 1.0


def test_c2_diagnoses_literals_the_model_broke_while_copying():
    r = _rule({"claim_type": "process_create", "facts.command": {"regex": "sh\\\\s+-c"}})
    r2 = _rule({"claim_type": "process_create", "facts.image": "WhoAmI"})
    for rule, cause in ((r, "over_escaped"), (r2, "case")):
        chk = C.c2_own_evidence(rule, _hyp(rule), _ep(), _ctx(_ep()))
        assert not chk.passed and chk.data["causes"].get(cause) == 1, chk.data


def test_c2_catches_a_rule_that_selects_its_evidence_but_never_scores():
    r = _rule({"claim_type": "process_create", "facts.image": "whoami"},
              score={"op": "saturate", "value": "n", "floor": 3, "ceiling": 10})
    chk = C.c2_own_evidence(r, _hyp(r), _ep(), _ctx(_ep()))
    assert not chk.passed and chk.data["causes"] == {"dead_score": 1}
    assert "selects 1 claim(s)" in chk.detail


# ------------------------------------------------------------------ C3 robustness

def test_rename_touches_only_user_writable_executables_and_is_consistent():
    ep = _ep()
    assert C.renameable_images(ep) == {"splunkd"}
    t = C.transform(ep, "rename_user_writable")
    agent = next(c for c in t if c.claim_type == "process_create" and c.facts["image_path"].startswith("/home/"))
    new = agent.facts["image"]
    assert new != "splunkd" and new in agent.facts["command"]             # renamed in its own command too
    shells = [c for c in t if c.facts.get("image") == "dash"]
    assert shells and all(c.facts["parent"] == new for c in shells)       # the same new name everywhere
    assert all(c.facts.get("image") != "dash" or c.facts["image_path"] == "/usr/bin/dash" for c in t)
    assert any(c.facts.get("image") == "splunkd" for c in ep)             # the originals are untouched


def test_c3_rejects_a_rule_keyed_on_a_name_the_attacker_chose():
    keyed = _rule({"claim_type": "process_create", "facts.parent": "splunkd"})
    behaviour = _rule({"claim_type": "process_create", "facts.image": "dash",
                       "lineage.parent_user_writable": {"truthy": True}})
    for rule, ok in ((keyed, False), (behaviour, True)):
        chk = C.c3_robust(rule, _hyp(rule), _ep(), _ctx, fired_on_origin=True)
        assert chk.passed is ok, chk.to_dict()
    assert C.c3_robust(keyed, _hyp(keyed), _ep(), _ctx, True).data["lost_under"] == ["rename_user_writable"]


def test_c3_respelling_catches_rules_keyed_on_one_spelling():
    """`whoami` and `/usr/bin/whoami` run the same program."""
    spelled = _rule({"claim_type": "process_create", "facts.command": {"regex": "^whoami$"}})
    by_name = _rule({"claim_type": "process_create", "facts.image": "whoami"})
    chk = C.c3_robust(spelled, _hyp(spelled), _ep(), _ctx, fired_on_origin=True)
    assert not chk.passed and chk.data["lost_under"] == ["respell_commands"]
    assert C.c3_robust(by_name, _hyp(by_name), _ep(), _ctx, True).passed
    assert C.respell("whoami", "whoami", "/usr/bin/whoami") == "/usr/bin/whoami"
    assert C.respell("sh -c whoami", "dash", "/usr/bin/dash") == "sh -c whoami"   # argv[0] is not the image


# ------------------------------------------------------------------ C4, C5 (rates and sources)

def test_c4_is_a_rate_on_history():
    assert C.c4_quiet(["w1"], ["w1", "w2", "w3", "w4"], 0.25).passed
    assert not C.c4_quiet(["w1", "w2"], ["w1", "w2", "w3", "w4"], 0.25).passed
    assert C.history_rate({"w1", "w2"}, ["w0", "w1", "w2", "w3", "w4"], exclude="w0") == 0.5


def test_c5_needs_the_same_events_from_a_different_recording():
    mine = {"run1_web01_1230": {"e1", "e2"}}
    same_rec = [("sigma:x", {"run1"}, {"run1_web01_1230": {"e1"}})]
    other_rec = [("sigma:y", {"sigma"}, {"run1_web01_1230": {"e2"}})]
    other_events = [("hand:KILLCHAIN", {"human"}, {"run1_web01_1230": {"e9"}})]
    written = [("llm:z", {"run2"}, {"run1_web01_1230": {"e1"}})]
    assert not C.c5_confirmed(mine, {"run1"}, same_rec).passed
    assert not C.c5_confirmed(mine, {"run1"}, other_events).passed
    chk = C.c5_confirmed(mine, {"run1"}, other_rec + other_events)
    assert chk.passed and chk.data["confirmed_by"] == ["sigma:y@run1_web01_1230"]
    assert chk.data["source"] == "Sigma rule"
    # another written rule agreeing is a note, never a confirmation
    only_llm = C.c5_confirmed(mine, {"run1"}, [], written)
    assert not only_llm.passed and only_llm.data["llm_agreement"] == ["llm:z@run1_web01_1230"]


# ------------------------------------------------------------------ one contract (A3)

def test_the_checks_are_defined_once_and_status_needs_them():
    assert C.KEYS == ("C1_valid", "C2_own_evidence", "C3_robust", "C4_quiet", "C5_confirmed")
    assert C.SHADOW_NEEDS == C.KEYS[:4] and C.ACTIVE_NEEDS == C.KEYS
    assert C.passed_all({k: {"passed": True} for k in C.KEYS[:4]}, C.SHADOW_NEEDS)
    assert not C.passed_all({k: {"passed": True} for k in C.KEYS[:3]}, C.SHADOW_NEEDS)   # C4 not reached


def test_only_rules_that_may_decide_confirm():
    from argus.reason import hypotheses as H
    from argus.rules.learn import HAND_SOURCES
    deciding = {h.technique for h in H.HYPOTHESES if h.decides}
    assert set(HAND_SOURCES) == deciding and "KILLCHAIN" in deciding
    assert not {"TA0007", "TA0009", "TA0010", "TA0011", "NOVELTY"} & set(HAND_SOURCES)


@needs_lab
def test_a_confirmer_counts_only_where_it_is_itself_quiet():
    """On run1 the discovery primitive fires on most of every host's windows (it flagged
    7 of 12 benign windows before A2): by C4's bar it confirms nothing anywhere."""
    from argus.reason import hypotheses as H
    from lab_data import LAB, case
    wins = sorted(p.name for p in LAB.glob("run1_*"))
    host_of = {w: w.split("_")[1] for w in wins}
    by_host = {h: [w for w in wins if host_of[w] == h] for h in set(host_of.values())}
    disc = next(h for h in H.HYPOTHESES if h.technique == "TA0007")
    hits = {}
    for w in wins:
        lc = case(w)
        s, sel, _ = C.rule_score(disc, lc.claims, CaseContext(claims=lc.claims, health=lc.health))
        if s > 0:
            hits[w] = {c.claim_id for c in sel}
    assert len(hits) > len(wins) / 2
    assert C.quiet_hits(hits, host_of, by_host, 0.25) == {}


@needs_lab
def test_a_library_written_before_a3_reads_with_status_and_checks_agreeing():
    """The run-1 library (2026-10-08, before A3) recorded analyst approvals beside a failed
    C5. Read today, every active rule passes C1–C5; statuses are exactly as saved."""
    import json
    from lab_data import ROOT
    from argus.rules.library import RuleLibrary
    path = ROOT / "eval_runs" / "2026-10-08-lab-induce" / "library.json"
    raw = {e["uid"]: e for e in json.loads(path.read_text())["entries"]}
    lib = RuleLibrary.load(path)
    assert {u: e.status for u, e in lib.entries.items()} == {u: e["status"] for u, e in raw.items()}
    for e in lib.entries.values():
        assert "C5_any_source" not in e.checks and "C4_rare_history" not in e.checks
        if e.status == "active":
            assert C.passed_all(e.checks, C.ACTIVE_NEEDS), e.uid
        if e.status == "shadow":
            assert C.passed_all(e.checks, C.SHADOW_NEEDS), e.uid
        if "C5_confirmed" in e.checks:                        # reached only after C4 passed
            assert e.checks["C4_quiet"]["passed"]
        if "C3_robust" in e.checks:                           # reached only by a rule that fires
            assert (e.checks["C2_own_evidence"].get("origin_score") or 0) > 0
    approved = [e for e in lib.entries.values() if e.status == "active"
                and e.history[-1]["reason"].startswith("analyst")]
    assert approved and all(e.checks["C5_confirmed"]["source"] == "analyst" for e in approved)
