"""ARGUS rules as data (argus/rules/dsl.py, loader.py): the validator on rule JSON, and the
interpreter on REAL lab windows (run1).

Run: .venv/bin/python -m pytest tests/ -q   (from `source code/`)
"""
from __future__ import annotations

import pytest

from argus.reason.context import CaseContext
from argus.rules import load_rules, to_hypotheses
from argus.rules.dsl import eval_indicator, validate
from argus.rules.loader import RuleError

from lab_data import AGENT_WINDOW, STEPS_WINDOW, claims, needs_lab


def _rule(**ind):
    base = {"name": "i", "weight": 1.0, "required": True,
            "select": {"claim_type": "process_create"}}
    base.update(ind)
    return {"id": "r", "technique": "T0", "name": "r", "indicators": [base]}


def _run(ind, cl):
    return eval_indicator(ind, cl, CaseContext(claims=cl))


# ------------------------------------------------------------------ validation (rule JSON only)

@pytest.mark.parametrize("mutate, message", [
    (lambda r: r["indicators"][0]["select"].update({"facts.x": {"nope": 1}}), "is not a predicate"),
    (lambda r: r["indicators"][0]["select"].update({"image": "id"}), "unknown field path 'image'"),
    (lambda r: r["indicators"][0].update(required=False), "required"),
    (lambda r: r["indicators"][0]["select"].update({"facts.c": {"regex": "("}}), "invalid regex"),
    (lambda r: r["indicators"][0].update(aggregate=[{"as": "n", "op": "distinct_categories"}]),
     "distinct_categories needs categories"),
    (lambda r: r["indicators"][0].update(score={"op": "affine", "value": "m"}), "undefined value 'm'"),
    (lambda r: r["indicators"][0].update(score={"op": "magic"}), "unknown op 'magic'"),
    (lambda r: r.update(severity=3), "severity"),
])
def test_validator_names_the_problem(mutate, message):
    r = _rule()
    mutate(r)
    assert any(message in e for e in validate(r)), validate(r)


def test_validator_errors_suggest_the_valid_alternatives():
    msg = " ".join(validate(_rule(select={"image": "id"})))
    assert "facts.<name>" in msg and "claim_type" in msg


def test_chain_references_must_resolve_and_ids_are_unique():
    chain = {"id": "k", "technique": "K", "name": "k", "indicators": [
        {"name": "c", "weight": 3.0, "required": True,
         "chain": {"stages": [{"name": "a", "rule": "r"}, {"name": "b", "rule": "missing"}]}}]}
    with pytest.raises(RuleError, match="unknown rule 'missing'"):
        load_rules([_rule(), chain])
    with pytest.raises(RuleError, match="duplicate rule id"):
        load_rules([_rule(), _rule()])
    with pytest.raises(RuleError):
        to_hypotheses(load_rules([_rule(select={"image": "x"})]))       # never reaches the engine


# ------------------------------------------------------------------ semantics, on real claims

@needs_lab
def test_llm_style_syntax_is_accepted():
    """Aliases and predicate shorthand the model writes unprompted."""
    r = _rule(select={"and": [{"claim_type": "process_create"}, {"facts.image": {"eq": "whoami"}}]})
    assert validate(r) == []
    hits, s = _run(r["indicators"][0], claims(AGENT_WINDOW))
    assert s == 1.0 and [h.facts["command"] for h in hits] == ["whoami"]


@needs_lab
def test_provenance_is_multi_valued_and_affine_scores_counts():
    cl = claims(AGENT_WINDOW)
    ind = _rule(select={"claim_type": "process_create", "provenance.sensor_id": {"prefix": "auditd"},
                        "facts.parent": "splunkd"},
                aggregate=[{"as": "n", "op": "count"}],
                score={"op": "affine", "value": "n", "intercept": 0.65, "slope": 0.15,
                       "offset": 1, "floor": 1})["indicators"][0]
    hits, s = _run(ind, cl)
    assert len(hits) == 3 and s == min(1.0, 0.65 + 0.15 * 2)              # three shells from the agent


@needs_lab
def test_grouping_lowercases_and_scores_the_best_group():
    """The benign script's curl to localhost, grouped by program and destination."""
    ind = _rule(select={"claim_type": "host_network_connection"},
                group_by=[{"field": "facts.image", "lower": True}, "facts.dst_ip"],
                aggregate=[{"as": "n", "op": "count"}],
                score={"op": "threshold", "value": "n", "at": 20})["indicators"][0]
    hits, s = _run(ind, claims(STEPS_WINDOW))
    assert s == 1.0 and {(h.facts["image"], h.facts["dst_ip"]) for h in hits} == {("curl", "127.0.0.1")}


@needs_lab
def test_categories_count_distinct_behaviours():
    ind = _rule(categories={"a": {"facts.image": "whoami"}, "b": {"facts.image": "env"}},
                aggregate=[{"as": "n", "op": "distinct_categories"}],
                score={"op": "threshold", "value": "n", "at": 2})["indicators"][0]
    cl = claims(AGENT_WINDOW)
    hits, s = _run(ind, cl)
    assert s == 1.0 and {h.facts["image"] for h in hits} == {"whoami", "env"}
    no_env = [c for c in cl if c.facts.get("image") != "env"]
    assert _run(ind, no_env)[1] == 0.0


@needs_lab
def test_behaviour_tactics_select_what_a_program_is_for():
    ind = _rule(select={"claim_type": "process_create",
                        "behaviour.tactics": {"in": ["discovery"]},
                        "lineage.ancestor_user_writable": {"truthy": True}})["indicators"][0]
    hits, s = _run(ind, claims(STEPS_WINDOW))
    assert s == 1.0 and {"ip", "cat"} <= {h.facts["image"] for h in hits}  # the agent's discovery


def _stage(rid, image):
    return {"id": rid, "technique": rid, "name": rid, "indicators": [
        {"name": rid, "weight": 1.0, "required": True,
         "select": {"claim_type": "process_create", "facts.image": image}}]}


def _chain(early, obj):
    return {"id": "K", "technique": "K", "name": "k", "indicators": [
        {"name": "chain", "weight": 3.0, "required": True,
         "chain": {"stages": [{"name": "early", "rule": early}, {"name": "obj", "rule": obj}],
                   "min_stages": 2, "scope": "window", "score": {"offset": 1, "over": 3.0},
                   "order_bonus": {"early": ["early"], "objective": ["obj"], "bonus": 0.1}}}]}


@needs_lab
@pytest.mark.parametrize("early, obj, want", [
    ("E", "W", 1 / 3 + 0.1),          # env (12:55:58) before whoami (12:56:47): kill-chain order
    ("W", "E", 1 / 3),                # the other way round: no bonus
])
def test_chain_scores_stages_and_their_order(early, obj, want):
    hs = {h.technique: h for h in to_hypotheses(load_rules([_stage("E", "env"), _stage("W", "whoami"),
                                                            _chain(early, obj)]))}
    cl = claims(AGENT_WINDOW)
    hits, s = hs["K"].indicators[0].match(cl, CaseContext(claims=cl))
    assert abs(s - want) < 1e-12 and {h.facts["image"] for h in hits} == {"env", "whoami"}
    one = [c for c in cl if c.facts.get("image") != "env"]
    assert hs["K"].indicators[0].match(one, CaseContext(claims=one))[1] == 0.0
