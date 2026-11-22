"""Triage workbench (argus/api/workbench.py + static UI), on a REAL lab window (run1, ws-fin01,
13:30: the agent's discovery steps beside the benign script's activity).

Run: .venv/bin/python -m pytest tests/ -q   (from `source code/`)
"""
from __future__ import annotations

import json
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

_ROOT = Path(__file__).resolve().parents[2]
CASE = "cases_lab:run1_ws-fin01_1330"
pytestmark = pytest.mark.skipif(not (_ROOT / "cases_lab" / "run1_web01_1330").exists(), reason="needs the run1 lab capture")


@pytest.fixture(scope="module")
def client(tmp_path_factory):
    import os
    os.environ["ARGUS_FEEDBACK_DIR"] = str(tmp_path_factory.mktemp("feedback"))
    from argus.api import workbench as W
    W.FEEDBACK_DIR = Path(os.environ["ARGUS_FEEDBACK_DIR"])
    # ARGUS alone: the installed rule library is model output and may change between runs
    os.environ["ARGUS_LIBRARY"] = "none"
    W.CFG, W.CFG_INFO = W._config()
    W.store = W.CaseStore(cfg=W.CFG)
    from argus.api.app import app
    c = TestClient(app)
    c.post(f"/workbench/triage/{CASE}")
    for _ in range(200):
        r = c.get(f"/workbench/case/{CASE}")
        if r.status_code == 200 and r.json().get("verdict"):
            break
        time.sleep(0.3)
    return c


def test_the_ui_and_its_assets_are_served(client):
    assert client.get("/ui/").status_code == 200
    assert "ARGUS" in client.get("/ui/").text
    assert client.get("/ui/app.js").status_code == 200 and client.get("/ui/app.css").status_code == 200


def test_case_view_has_verdict_context_sensors_and_the_episode_tree(client):
    v = client.get(f"/workbench/case/{CASE}").json()
    assert v["verdict"]["disposition"] == "suspicious"
    assert v["verdict"]["blind_spots"] == []                            # auditd met its contract here
    assert set(v["sensors"]) == {"auditd"}
    assert any("context" in n for n in v["verdict"]["notes"])           # weak primitives, shown as context
    roots = v["tree"]["roots"]
    assert len(roots) == 1                                              # one episode root, no strays

    def walk(n):
        yield n
        for ch in n["children"]:
            yield from walk(ch)
    nodes = list(walk(roots[0]))
    assert any(n["evidence"] for n in nodes) and len(nodes) < 1000


def test_ground_truth_is_separate_from_the_analyst_view(client):
    v = client.get(f"/workbench/case/{CASE}").text
    assert "malicious_event_ids" not in v and "malicious_claims" not in v
    gt = client.get(f"/workbench/case/{CASE}/groundtruth").json()
    assert gt["available"] and gt["category"] == "attack" and gt["malicious_claims"]


def test_feedback_is_recorded_in_the_rule_library_verdict_shape(client):
    from argus.api import workbench as W
    from argus.rules.feedback import Verdict
    v = client.get(f"/workbench/case/{CASE}").json()
    rule = v["hypotheses"][0]["rule_id"]
    r = client.post("/workbench/feedback", json={"case_id": CASE, "outcome": "true_positive",
                                                  "rule_verdicts": {rule: "malicious"}, "analyst": "test"})
    assert r.json()["recorded"]
    rows = [json.loads(x) for x in (W.FEEDBACK_DIR / "rule_verdicts.jsonl").read_text().splitlines()]
    Verdict(**rows[-1])                                                  # loads as the loop's type
    assert rows[-1]["rule_id"] == rule and rows[-1]["capture"] == CASE


def test_cases_outside_the_corpora_are_refused(client):
    assert client.post("/workbench/triage/cases_citar:..%2F..%2Fetc").status_code == 404
    assert client.post("/workbench/triage/not_a_corpus:x").status_code == 404
    assert client.get("/workbench/cases?root=/etc").status_code == 404
