"""Sigma import (argus/rules/sigma.py), checked on REAL data only: the dated SigmaHQ
snapshot (intel/snapshots/lab) and real run1 lab windows. Skipped when they are absent.

Run: .venv/bin/python -m pytest tests/ -q   (from `source code/`)
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml

from argus.reason.context import CaseContext
from argus.rules import checks as C
from argus.rules import to_hypotheses
from argus.rules.dsl import validate
from argus.rules.sigma import FIELDS, Refused, from_sigma, load_snapshot

from lab_data import LAB, case

SNAP = Path(__file__).resolve().parents[2] / "intel" / "snapshots" / "lab"
pytestmark = pytest.mark.skipif(not (SNAP / "sigma").exists() or not (LAB / "run1_web01_1330").exists(),
                                reason="needs the lab intel snapshot and the run1 lab capture")
LOCAL_ACCOUNT = "rules/linux/process_creation/proc_creation_lnx_local_account.yml"


@pytest.fixture(scope="module")
def converted():
    return load_snapshot(SNAP)


def _sigma(rel: str) -> dict:
    return yaml.safe_load((SNAP / "sigma" / rel).read_text())


def test_only_linux_rules_convert_each_valid_and_every_refusal_has_a_reason(converted):
    rules, refused = converted
    assert len(rules) > 100 and all(validate(r, {}) == [] for r in rules)
    assert {r["provenance"]["logsource"]["product"] for r in rules} == {"linux"}
    assert all(reason for _, reason in refused)
    assert any(p.startswith("rules/windows/") and "product" in why for p, why in refused)


def test_no_rule_postdates_the_snapshot(converted):
    as_of = json.loads((SNAP / "MANIFEST.json").read_text())["as_of"]
    for r in converted[0]:
        for k in ("date", "modified"):
            d = r["provenance"][k].replace("/", "-")
            assert not d or d[:10] <= as_of, (r["id"], d)


def test_a_sigma_rule_fires_on_exactly_what_its_yaml_selects_in_a_real_window():
    """The agent's account discovery (`cat /etc/passwd`, run1 13:45), judged by the rule's
    own selection read from the YAML, not by ARGUS's conversion of it."""
    doc = _sigma(LOCAL_ACCOUNT)
    rule = from_sigma(doc, LOCAL_ACCOUNT, "lab")
    det = doc["detection"]
    readers = {v.lstrip("/") for v in det["selection_3"]["Image|endswith"]}
    files = det["selection_3"]["CommandLine|contains"]
    nonempty = 0
    for w in ("run1_web01_1200", "run1_web01_1300", "run1_web01_1330"):
        lc = case(w)
        _, hits, _ = C.rule_score(to_hypotheses([rule])[0], lc.claims, CaseContext(claims=lc.claims))
        oracle = {c.claim_id for c in lc.claims if c.claim_type == "process_create" and (
            (c.facts.get("image") in readers and any(f in (c.facts.get("command") or "") for f in files))
            or c.facts.get("image") in ("lastlog", "id")
            or (c.facts.get("image") == "lsof" and "-u" in (c.facts.get("command") or ""))
            or "'x:0:'" in (c.facts.get("command") or ""))}
        assert {c.claim_id for c in hits} == oracle, w
        nonempty += bool(oracle)
    assert nonempty, "no window with a match: the comparison would be vacuous"


def test_a_required_field_argus_lacks_refuses_the_rule_rather_than_broadening_it():
    """A selection that ANDs a field ARGUS has with one it lacks (e.g. CommandLine and
    ParentCommandLine) must be refused: dropping the missing half would make the rule fire
    more often than the original."""
    known = set(FIELDS["process_create"])
    hits = 0
    for f in sorted((SNAP / "sigma" / "rules" / "linux" / "process_creation").glob("*.yml")):
        d = yaml.safe_load(f.read_text())
        for k, sel in d.get("detection", {}).items():
            if k == "condition" or k.startswith("filter") or not isinstance(sel, dict):
                continue
            fields = {x.split("|")[0] for x in sel}
            if fields & known and fields - known:
                with pytest.raises(Refused):
                    from_sigma(d, str(f), "lab")
                hits += 1
                break
    assert hits > 0
