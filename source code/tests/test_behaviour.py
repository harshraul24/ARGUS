"""Behaviour vocabulary (argus/normalize/behaviour.py, tools/behaviour_vocab.py): the Linux
Sigma tactic tags ARGUS ships, checked against the lab snapshot and a real run1 window.

Run: .venv/bin/python -m pytest tests/ -q   (from `source code/`)
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from argus.normalize import behaviour as B
from argus.reason.context import CaseContext
from argus.rules import checks as C
from argus.rules import load_rules, to_hypotheses

from lab_data import STEPS_WINDOW, case, needs_lab

SNAP_VOCAB = Path(__file__).resolve().parents[2] / "intel" / "snapshots" / "lab" / "behaviour_vocab.json"
pytestmark = pytest.mark.skipif(not B.DEFAULT_PATH.exists(), reason="needs the shipped vocabulary")

DISCOVERY_RULE = {"id": "discovery-program", "technique": "TA0007", "name": "a discovery program runs",
                  "indicators": [{"name": "i", "weight": 1.0, "required": True,
                                  "select": {"claim_type": "process_create", "behaviour.tactics": "discovery"}}]}


def test_the_shipped_vocabulary_is_the_lab_snapshots_linux_one():
    shipped = json.loads(B.DEFAULT_PATH.read_text())
    assert shipped["platform"] == "linux" and shipped["snapshot"] == "lab"
    assert not any(p.endswith(".exe") for p in shipped["binaries"])
    if SNAP_VOCAB.exists():
        assert B.DEFAULT_PATH.read_bytes() == SNAP_VOCAB.read_bytes()


def test_linux_discovery_programs_share_one_tactic():
    b = json.loads(B.DEFAULT_PATH.read_text())["binaries"]
    for p in ("id", "uname", "hostname", "netstat", "ss", "ip"):
        assert "discovery" in b[p]["tactics"], (p, b[p])


@needs_lab
def test_one_rule_finds_the_agents_discovery_by_what_the_programs_are_for():
    h = to_hypotheses(load_rules([DISCOVERY_RULE]))[0]
    lc = case(STEPS_WINDOW)
    _, hits, _ = C.rule_score(h, lc.claims, CaseContext(claims=lc.claims))
    assert {"ip", "cat"} <= {B.program(c.facts.get("image_path")) for c in hits}


@needs_lab
def test_the_field_is_absent_without_a_vocabulary():
    lc = case(STEPS_WINDOW)
    c = next(c for c in lc.claims if c.claim_type == "process_create")
    with B.use(None):
        assert B.tactics(c) is None
        h = to_hypotheses(load_rules([DISCOVERY_RULE]))[0]
        assert C.rule_score(h, lc.claims, CaseContext(claims=lc.claims))[0] == 0
    assert B.tactics(c) is not None                                          # the default is back
