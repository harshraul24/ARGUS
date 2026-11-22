"""Rule learning and rule review from the workbench (argus/api/workbench.py, argus/rules/learn.py),
on the REAL run1 lab windows. The model is the offline stub and every file goes to a temporary
folder: the installed library is never touched.

Run: .venv/bin/python -m pytest tests/ -q   (from `source code/`)
"""
from __future__ import annotations

import json
import time

import pytest
from fastapi.testclient import TestClient

from argus.api import workbench as W
from argus.api.app import app
from argus.rules import induce as I
from argus.rules.library import RuleLibrary

from lab_data import needs_lab
from rule_records import passed

SECRET = "test-key-0f3c9a7e-never-stored"


@pytest.fixture
def ui(tmp_path, monkeypatch):
    lib = tmp_path / "lab_library.json"
    monkeypatch.setenv("ARGUS_LIBRARY", str(lib))
    monkeypatch.setattr(W, "LEARN_PROVIDER", "stub")
    monkeypatch.setattr(W, "LEARN_ARCHIVE", tmp_path / "runs")
    monkeypatch.setattr(W, "LEARN_CACHE", tmp_path / "cache")
    monkeypatch.setattr(W, "JOB", W.LearnJob())
    W._reload()
    yield TestClient(app), lib, tmp_path
    monkeypatch.setenv("ARGUS_LIBRARY", "none")
    W._reload()


@needs_lab
def test_a_learning_run_from_the_page_installs_a_library_and_keeps_no_key(ui):
    client, lib, tmp = ui
    src = client.get("/workbench/learn").json()["source"]
    assert src["operations"] == ["run1"] and src["windows"] == 20
    r = client.post("/workbench/learn", json={"model": "m", "api_key": SECRET}).json()
    assert r["state"] == "running" and SECRET not in json.dumps(r)
    for _ in range(300):
        s = client.get("/workbench/learn").json()
        if s["state"] != "running":
            break
        time.sleep(0.1)
    assert s["state"] == "done", s["message"]
    assert lib.exists() and s["result"]["new_rules"] == 0             # the stub writes no rules
    assert SECRET not in json.dumps(s)
    for f in tmp.rglob("*"):                                          # library, run archive, cache
        if f.is_file():
            assert SECRET not in f.read_text(errors="ignore"), f


def test_a_second_run_cannot_start_while_one_is_running(ui, monkeypatch):
    client, _, _ = ui
    monkeypatch.setattr(W.JOB, "state", "running")
    assert client.post("/workbench/learn", json={"api_key": ""}).status_code == 409


def _shadow_library(path):
    rule = I.finalize({"id": "writable-parent-shell", "technique": "T1059", "name": "shell from a user-writable program",
                       "indicators": [{"name": "i", "weight": 1.0, "required": True,
                                       "select": {"claim_type": "process_create", "facts.image": "dash",
                                                  "lineage.parent_user_writable": {"truthy": True}}}]}, "o", "m", 0)
    lib = RuleLibrary()
    lib.add(rule)
    passed(lib, rule["id"])
    lib.transition(rule["id"], "shadow", "passed C1–C4")
    lib.save(path)
    return rule["id"]


def test_the_analyst_approves_and_retires_rules_and_the_history_says_so(ui):
    client, lib_path, _ = ui
    uid = _shadow_library(lib_path)
    W._reload()
    assert W.CFG_INFO["shadow"] == 1 and W.CFG_INFO["active"] == 0
    r = client.post(f"/workbench/library/{uid}", json={"action": "approve"})
    assert r.status_code == 200 and r.json()["status"] == "active"
    assert W.CFG_INFO["active"] == 1                                  # it decides cases from now on
    assert client.post(f"/workbench/library/{uid}", json={"action": "approve"}).status_code == 409
    assert client.post(f"/workbench/library/{uid}", json={"action": "retire"}).json()["status"] == "retired"
    hist = RuleLibrary.load(lib_path).entries[uid].history
    assert [h["to"] for h in hist] == ["candidate", "shadow", "active", "retired"]
    assert hist[2]["reason"] == "analyst approved it in the workbench"
    assert client.post("/workbench/library/no-such-rule", json={"action": "retire"}).status_code == 404
