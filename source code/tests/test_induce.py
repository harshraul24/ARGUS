"""S3 on Linux: episodes, rendering, the write-check-repair loop and the rule library, on the
REAL agent episode of run1 (web01). The model is a scripted stand-in: the loop under test
is ARGUS's, not the model's.

Run: .venv/bin/python -m pytest tests/ -q   (from `source code/`)
"""
from __future__ import annotations

import json

import pytest

from argus.reason.context import CaseContext
from argus.reason.engine import Config, reason
from argus.rules import checks as C
from argus.rules import induce as I
from argus.rules import load_rules, to_hypotheses
from argus.rules.dsl import get
from argus.rules.episodes import Redactor, find_episodes, render
from argus.rules.library import LifecycleError, RuleLibrary

from lab_data import AGENT_WINDOW, STEPS_WINDOW, agent_episode, case, claims, history, needs_lab
from rule_records import passed

# a rule keyed on the name the attacker chose, and the behaviour it should become
KEYED = {"id": "agent-shell", "technique": "T1059", "name": "shell from agent", "evidence": [],
         "indicators": [{"name": "shell", "weight": 1.0, "required": True,
                         "select": {"claim_type": "process_create", "facts.parent": "splunkd"}}]}
FIXED = {"id": "writable-parent-shell", "technique": "T1059", "name": "shell from user-writable parent",
         "evidence": [],
         "indicators": [{"name": "shell", "weight": 1.0, "required": True,
                         "select": {"claim_type": "process_create", "facts.image": "dash",
                                    "lineage.parent_user_writable": {"truthy": True}}}]}


class Scripted:
    def __init__(self, answers):
        self.answers, self.prompts = list(answers), []

    def __call__(self, prompt):
        self.prompts.append(prompt)
        return json.dumps(self.answers.pop(0))


def _induce(model, renameable, max_repairs=2):
    ep = agent_episode()
    return I.induce_episode(model, "EPISODE", ep.claims, {}, ep.eid, "m", renameable, max_repairs=max_repairs)


# ------------------------------------------------------------------ lineage fields

@needs_lab
def test_lineage_fields_read_folders_not_names_and_survive_renaming():
    cl = claims(AGENT_WINDOW)
    ctx = CaseContext(claims=cl)
    shell = next(c for c in cl if c.facts.get("parent") == "splunkd")
    assert get(shell, "lineage.parent_user_writable", ctx) is True
    assert get(shell, "lineage.user_writable", ctx) is False
    t = C.transform(cl, "rename_user_writable")
    shell_t = next(c for c in t if c.claim_id == shell.claim_id)
    assert shell_t.facts["parent"] != "splunkd"
    assert get(shell_t, "lineage.parent_user_writable", CaseContext(claims=t)) is True
    assert get(shell, "lineage.parent_user_writable", CaseContext(claims=cl, lineage_enabled=False)) is None


@needs_lab
def test_an_ancestor_from_an_earlier_window_keeps_its_folder():
    """The agent started at 12:52; its discovery steps run at 13:45, in the next window."""
    cl = claims(STEPS_WINDOW)
    ctx = CaseContext(claims=cl)
    step = next(c for c in cl if c.facts.get("command") == "cat /etc/passwd")
    assert get(step, "lineage.ancestor_user_writable", ctx) is True
    assert get(step, "lineage.parent_user_writable", ctx) is False          # its parent is /usr/bin/dash


# ------------------------------------------------------------------ episodes and rendering

@needs_lab
def test_episode_is_the_novel_tree_under_its_non_hub_root():
    ep = agent_episode()
    imgs = {c.facts.get("image") for c in ep.claims if c.claim_type == "process_create"}
    assert ep.root_image == "splunkd" and imgs == {"splunkd", "dash", "env", "whoami"}
    assert len(ep.novel_launches) >= 3
    eps = find_episodes(case(AGENT_WINDOW).claims, AGENT_WINDOW, history(), min_novel=99)
    assert eps == []                                                         # too few novel launches


@needs_lab
def test_rendering_fences_attacker_text_and_redacts_identity():
    ep = agent_episode()
    cl = case(AGENT_WINDOW).claims
    text, _ = render(ep, history(), Redactor(cl))
    assert "USER-WRITABLE" in text and "«./splunkd -server http://<ip>:8888 -group red -v»" in text
    assert "192.168.2" not in text and AGENT_WINDOW not in text           # no capture name reaches the model
    later = case(STEPS_WINDOW).claims
    cmd = next(c.facts["command"] for c in later if c.facts.get("command") == "ls -la /home/www")
    assert Redactor(later)(cmd) == "ls -la /home/<name>"


def _shared_render() -> str:
    """Every episode of a busy real window (a package install): ties in activity counts must
    not be ordered by Python's set order."""
    w = "run1_web01_1300"
    cl = case(w).claims
    h = history()
    return "\n".join(render(ep, h, Redactor(cl))[0] for ep in find_episodes(cl, w, h))


@needs_lab
def test_prompts_are_identical_across_python_hash_seeds():
    """Prompts are cache keys: any set-order leak makes a re-run miss the cache."""
    import os
    import subprocess
    import sys
    code = "import sys; sys.path.insert(0, 'tests'); import test_induce as T; print(T._shared_render())"
    outs = {subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                           env={**os.environ, "PYTHONHASHSEED": str(s)},
                           cwd=os.path.dirname(os.path.dirname(__file__))).stdout
            for s in range(1, 7)}
    assert len(outs) == 1 and "dpkg" in next(iter(outs))


# ------------------------------------------------------------------ parsing and ids

def test_parse_tolerates_fences_and_reports_garbage():
    rules, why, err = I.parse('```json\n{"rules": [{"id": "x"}], "reasoning": "r"}\n```')
    assert rules == [{"id": "x"}] and why == "r" and err is None
    assert I.parse("no json here")[2]
    assert I.parse('[{"id": "y"}]')[0] == [{"id": "y"}]


def test_unique_ids_keep_the_behaviour_identity():
    a, b = I.finalize(FIXED, "cap#1", "m", 0), I.finalize(FIXED, "cap#2", "m", 0)
    assert a["id"] != b["id"] and a["provenance"]["semantic_id"] == b["provenance"]["semantic_id"]


# ------------------------------------------------------------------ the loop

@needs_lab
def test_repair_loop_feeds_c3_findings_back_and_keeps_the_fix():
    model = Scripted([{"rules": [KEYED], "reasoning": "r0"}, {"rules": [FIXED], "reasoning": "r1"}])
    ind = _induce(model, C.renameable_images(agent_episode().claims))
    assert ind.calls == 2
    assert "splunkd" in model.prompts[0]                         # named as never-a-literal
    assert "renamed" in model.prompts[1] and "lineage" in model.prompts[1]
    first, second = ind.attempts
    assert not first.checks["C3_robust"].passed and first.superseded_by == second.rule["id"]
    assert I.passed(second.checks) and ind.final() == [second]


@needs_lab
def test_passing_rules_are_not_sent_back_and_rounds_are_bounded():
    ind = _induce(Scripted([{"rules": [KEYED]}] * 3), {"splunkd"})
    assert ind.calls == 3 and not any(I.passed(a.checks) for a in ind.attempts)
    assert _induce(Scripted([{"rules": [FIXED]}]), set()).calls == 1


@needs_lab
def test_only_failing_rules_go_back_and_passing_ones_stay():
    model = Scripted([{"rules": [FIXED, KEYED]}, {"rules": []}])
    ind = _induce(model, {"splunkd"}, max_repairs=1)
    sent = model.prompts[1].split("YOUR EARLIER RULES FAILED")[1]
    assert "agent-shell" in sent and "writable-parent-shell" not in sent
    assert [a.rule["name"] for a in ind.final()] == [FIXED["name"]]


def test_every_example_clause_in_the_prompt_is_valid_rule_syntax():
    """An example the model copies must be valid as written."""
    from argus.rules.dsl import validate
    g = json.loads(I.grammar_text({"process_create": ["command"]}))
    for ex in g["select_clause_examples"]:
        r = {"id": "x", "technique": "T", "name": "n",
             "indicators": [{"name": "i", "required": True, "select": ex}]}
        assert validate(r, {}) == [], ex


def test_the_prompt_is_about_linux_and_asks_for_the_behaviour_class():
    p = I.build_prompt("E", {"process_create": ["command"]}, set())
    assert "Linux host" in p and "Windows" not in p and ".exe" not in p
    assert "only ONE alternative" in p and "BEHAVIOUR CLASS" in p and "behaviour.tactics" in p
    assert "WHAT EARLIER RULES" not in p and "WHAT EARLIER RULES" in I.build_prompt("E", {}, set(), memory="- x")


def test_written_rules_may_not_read_the_baseline():
    r = I.finalize({**FIXED, "indicators": [{**FIXED["indicators"][0],
                    "select": {"claim_type": "process_create", "baseline.image_seen": {"lte": 0}}}]},
                   "o", "m", 0)
    chk = I.c1(r)
    assert not chk.passed and "reserved" in chk.detail


# ------------------------------------------------------------------ library

def test_lifecycle_is_enforced_and_judged_rules_are_immutable(tmp_path):
    lib = RuleLibrary()
    r = I.finalize(FIXED, "o", "m", 0)
    lib.add(r, {"capture": "c"})
    with pytest.raises(LifecycleError):
        lib.transition(r["id"], "active", "skip shadow")
    with pytest.raises(LifecycleError):                      # no check record: not shadow
        lib.transition(r["id"], "shadow", "passed C1–C4")
    passed(lib, r["id"])
    lib.transition(r["id"], "shadow", "passed C1–C4")
    with pytest.raises(LifecycleError):
        lib.edit(r["id"], {**r, "severity": 0.1})
    with pytest.raises(LifecycleError):                      # C5 not passed: not active
        lib.transition(r["id"], "active", "passed C5")
    passed(lib, r["id"], "C5_confirmed")
    lib.transition(r["id"], "active", "passed C5")
    lib.save(tmp_path / "lib.json")
    e = RuleLibrary.load(tmp_path / "lib.json").entries[r["id"]]
    assert e.status == "active" and [h["to"] for h in e.history] == ["candidate", "shadow", "active"]


# ------------------------------------------------------------------ engine

def _two(sev_a, sev_b):
    base = FIXED["indicators"]
    return to_hypotheses(load_rules([
        {"id": "a", "technique": "T1059", "name": "a", "severity": sev_a, "indicators": base},
        {"id": "b", "technique": "T1059", "name": "b", "severity": sev_b, "indicators": base}]))


@needs_lab
def test_results_are_keyed_by_rule_id_not_technique():
    d = reason("c", claims(AGENT_WINDOW), cfg=Config(hypotheses=_two(0.2, 0.9)))
    assert d.severity == pytest.approx(0.9 * d.hypotheses[0].score)
    assert d.hypotheses[0].rule_id == "b"


@needs_lab
def test_shadow_rules_are_reported_and_never_move_the_decision():
    cl = claims(AGENT_WINDOW)
    d0 = reason("c", cl, cfg=Config(hypotheses=[]))
    d1 = reason("c", cl, cfg=Config(hypotheses=[], shadow=_two(0.9, 0.9)))
    assert [r.rule_id for r in d1.shadow] and not d0.shadow
    strip = lambda d: {k: v for k, v in d.model_dump().items() if k not in ("shadow", "config")}
    assert strip(d0) == strip(d1)


@needs_lab
def test_rules_firing_on_the_same_events_merge_into_the_most_general_one():
    """Two spellings of the history-clearing rule select the same command in run1; a whoami
    rule selects another. The two merge (the one with fewer literals is kept); whoami stays."""
    def rule(rid, tokens):
        return I.finalize({"id": rid, "technique": "T1070.003", "name": rid, "indicators": [
            {"name": "i", "weight": 1.0, "required": True,
             "select": {"claim_type": "process_create", "facts.command": {"contains_any": tokens}}}]},
            "o", "m", 0)
    lib = RuleLibrary()
    rules = [rule("history-a", ["bash_history"]), rule("history-b", ["bash_history", "HISTFILE"]),
             rule("whoami", ["whoami"])]
    for r in rules:
        lib.add(r)
        passed(lib, r["id"], "C5_confirmed")
        lib.transition(r["id"], "shadow", "passed C1–C4")
        lib.transition(r["id"], "active", "passed C5")
    cl = claims(AGENT_WINDOW)
    hits = {}
    for r, h in zip(rules, to_hypotheses(rules)):
        s, sel, _ = C.rule_score(h, cl, CaseContext(claims=cl))
        hits[r["id"]] = {AGENT_WINDOW: {c.claim_id for c in sel}} if s > 0 else {}
    assert hits[rules[0]["id"]] == hits[rules[1]["id"]] != hits[rules[2]["id"]]
    assert lib.merge_duplicates(hits) == [(rules[1]["id"], rules[0]["id"])]
    assert {e.uid for e in lib.by_status("active")} == {rules[0]["id"], rules[2]["id"]}
    assert lib.entries[rules[1]["id"]].history[-1]["reason"].startswith(f"duplicate of {rules[0]['id']}")
