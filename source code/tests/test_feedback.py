"""Analyst feedback (argus/rules/feedback.py): precision estimates, lifecycle moves, value-of-
information queries and rule memory; and C3's created-artifact rule on real lab data.

Run: .venv/bin/python -m pytest tests/ -q   (from `source code/`)
"""
from __future__ import annotations

import random

from argus.rules import checks as C
from argus.rules import feedback as F
from argus.rules import induce as I
from argus.rules.library import RuleLibrary

from lab_data import LAB, needs_lab
from rule_records import passed
from test_induce import FIXED


# ------------------------------------------------------------------ C3 artifacts, on real data

@needs_lab
def test_files_created_by_system_programs_are_not_artifacts():
    """ws-fin01 13:00: systemctl wrote unit links and ssh created the user's known_hosts.
    Neither runs from, or descends from, a user-writable folder, so their file names are
    not an author's choice a rule must avoid."""
    from argus.case import load_case
    cl = load_case(LAB / "run1_ws-fin01_1300").claims
    created = {c.facts["file_path"] for c in cl if c.claim_type == "file_create"}
    assert "/home/alice/.ssh/known_hosts" in created
    assert C.created_artifacts(cl) == set()


# ------------------------------------------------------------------ step 5: feedback

def test_precision_estimate_and_lifecycle_moves():
    lib = RuleLibrary()
    good, bad, few = (I.finalize({**FIXED, "id": n}, n, "m", 0) for n in ("good", "bad", "few"))
    for r in (good, bad, few):
        lib.add(r)
        passed(lib, r["id"])
        lib.transition(r["id"], "shadow", "passed C1–C4")
    st = F.FeedbackStore()
    for cap in ("w1", "w2"):
        st.add(F.Verdict(good["id"], cap, "malicious"))
        st.add(F.Verdict(bad["id"], cap, "benign"))
    st.add(F.Verdict(few["id"], "w1", "malicious"))
    assert st.precision(good["id"])["mean"] == 0.75 and st.precision(bad["id"])["mean"] == 0.25
    moves = dict((u, to) for u, to, _ in F.apply(lib, st))
    assert moves == {good["id"]: "active", bad["id"]: "retired"}     # one verdict is not enough
    assert lib.entries[good["id"]].history[-1]["reason"].startswith("analyst-approved: analyst verdicts 2 malicious")


def test_value_query_prefers_uncertain_rules_that_would_change_a_decision():
    st = F.FeedbackStore()
    st.add(F.Verdict("known", "w9", "malicious"))
    st.add(F.Verdict("known", "w8", "malicious"))
    alerts = {"known": {"w1": {"e"}}, "fresh": {"w1": {"e"}, "w2": {"e"}}}
    assert F.next_query(alerts, st, benign_now={"w2"}) == ("fresh", "w2")
    assert F.next_query(alerts, st, benign_now=set()) in {("fresh", "w1"), ("fresh", "w2")}
    picks = {F.next_query(alerts, st, set(), "random", random.Random(s)) for s in range(20)}
    assert ("known", "w1") in picks                              # random ignores value
    for r, caps in alerts.items():
        for c in caps:
            st.add(F.Verdict(r, c, "benign"))
    assert F.next_query(alerts, st, set()) is None


def test_memory_reports_outcomes_not_labels():
    lib = RuleLibrary()
    a, b, c = (I.finalize({**FIXED, "id": n, "name": n}, n, "m", 0) for n in ("kept", "broad", "routine"))
    for r in (a, b, c):
        lib.add(r)
    passed(lib, a["id"], "C5_confirmed")
    passed(lib, c["id"])
    lib.transition(a["id"], "shadow", "passed C1–C4")
    lib.transition(a["id"], "active", "passed C5")
    lib.transition(b["id"], "rejected", "C4_rare_history: fires on 95% of the host's other captures")
    lib.transition(c["id"], "shadow", "passed C1–C4")
    lib.transition(c["id"], "retired", "analyst: analyst verdicts 0 malicious / 2 benign")
    m = F.memory(lib)
    assert "kept" in m and "routine" in m and "too many of this host's captures" in m
    assert "malicious_event_ids" not in m and "label" not in m.lower()


def test_value_queries_concentrate_until_a_decision_completes():
    """Uncertainty sampling alone spread 10 verdicts over 10 rules and decided nothing."""
    st = F.FeedbackStore()
    alerts = {r: {"w1": {"e"}, "w2": {"e"}} for r in ("a", "b", "c")}
    first = F.next_query(alerts, st, benign_now=set())
    st.add(F.Verdict(first[0], first[1], "malicious"))
    assert F.next_query(alerts, st, benign_now=set())[0] == first[0]     # finish that rule
    assert F.move_rate(1, 0, F.Policy()) > F.move_rate(0, 0, F.Policy()) > 0
    assert F.move_rate(2, 0, F.Policy()) == 0.0                         # already decided
    assert F.move_rate(1, 1, F.Policy(), can_promote=False) > 0         # active: may still retire
    # approval mode: a rule with one alert in the period is decided by reviewing it
    assert F.move_rate(0, 0, F.Policy(), total=1) == 0.5
    assert F.move_rate(1, 0, F.Policy(), total=1) == 0.0


def test_approval_on_complete_review_promotes_a_rule_whose_every_alert_was_confirmed():
    lib = RuleLibrary()
    one, two = (I.finalize({**FIXED, "id": n}, n, "m", 0) for n in ("one-alert", "two-alerts"))
    for r in (one, two):
        lib.add(r)
        passed(lib, r["id"])
        lib.transition(r["id"], "shadow", "passed C1–C4")
    st = F.FeedbackStore([F.Verdict(one["id"], "w1", "malicious"), F.Verdict(two["id"], "w1", "malicious")])
    moves = dict((u, to) for u, to, _ in F.apply(lib, st, totals={one["id"]: 1, two["id"]: 2}))
    assert moves == {one["id"]: "active"}                       # the other has an unreviewed alert
    assert "all 1 alert(s) reviewed" in lib.entries[one["id"]].history[-1]["reason"]
