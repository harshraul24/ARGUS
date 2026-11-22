"""Importing a capture from the workbench (argus/api/workbench.py, argus/collectors/lab_capture.py),
on the REAL run1 lab capture. The capture is copied to a temporary folder, and the lab folder,
cases folder and lab_split.json are temporary too: nothing real is touched.

Run: .venv/bin/python -m pytest tests/ -q   (from `source code/`)
"""
from __future__ import annotations

import json
import shutil
import time
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from argus.api import workbench as W
from argus.api.app import app

_ROOT = Path(__file__).resolve().parents[2]
RUN = _ROOT / "Test Setup" / "lab" / "captured" / "run1"
pytestmark = pytest.mark.skipif(not (RUN / "web01" / "audit.log").exists(), reason="needs the run1 lab capture")


@pytest.fixture
def lab(tmp_path, monkeypatch):
    caps, cases = tmp_path / "captured", tmp_path / "cases_lab"
    src = caps / "run-2"                              # the real run1 capture under a new folder name
    for f in RUN.glob("*/*.log"):
        if f.parent.name != "network":
            (src / f.parent.name).mkdir(parents=True, exist_ok=True)
            shutil.copy(f, src / f.parent.name / f.name)
    shutil.copy(RUN / "test2_report.json", src)
    shutil.copy(RUN / "ground_truth.json", src)
    split = tmp_path / "lab_split.json"
    split.write_text(json.dumps({"excluded": {"smoke": "pipeline check"}, "operations": ["run1"], "design_count": 3}))
    monkeypatch.setattr(W, "CAPTURES", caps)
    monkeypatch.setattr(W, "LAB", cases)
    monkeypatch.setattr(W, "SPLIT", split)
    monkeypatch.setattr(W, "IMPORT", W.ImportJob())
    return TestClient(app), caps, cases, split


def _wait(client):
    for _ in range(300):
        j = client.get("/workbench/import").json()
        if j["state"] != "running":
            return j
        time.sleep(0.1)
    raise AssertionError("import did not finish")


def test_a_capture_is_found_with_its_hosts_and_report(lab):
    client, *_ = lab
    d = client.get("/workbench/captures").json()
    [c] = d["captures"]
    assert c["folder"] == "run-2" and c["name"] == "run-2" and c["imported_as"] is None
    assert c["hosts"] == ["app01", "web01", "ws-dev01", "ws-fin01"]
    assert c["reports"] == ["test2_report.json"] and c["ground_truth"]
    assert d["split"]["operations"] == ["run1"] and {"run1", "smoke"} <= set(d["taken"])


def test_importing_writes_the_same_windows_as_the_converter_and_registers_the_operation(lab, tmp_path):
    from argus.collectors.lab_capture import convert
    client, caps, cases, split = lab
    r = client.post("/workbench/import", json={"folder": "run-2", "name": "run2", "report": "test2_report.json"})
    assert r.status_code == 200, r.text
    j = _wait(client)
    assert j["state"] == "done", j["message"]
    assert j["result"]["windows"] == 20 and j["result"]["role"] == "design"
    assert (j["result"]["steps"], j["result"]["steps_matched"]) == (36, 36)
    assert json.loads(split.read_text())["operations"] == ["run1", "run2"]      # in capture order
    assert not any(p.name.startswith(".") for p in cases.iterdir())             # no staging left
    # exactly what the converter writes from the same real capture
    src = caps / "run-2"
    ref = tmp_path / "ref"
    convert(src, ref, "run2", report=src / "test2_report.json", ground_truth=src / "ground_truth.json", source="run-2")
    assert sorted(p.name for p in cases.iterdir()) == sorted(p.name for p in ref.iterdir())
    for d in sorted(cases.iterdir()):
        for f in ("events.jsonl", "lineage.json", "labels.json", "meta.json"):
            assert (d / f).read_text() == (ref / d.name / f).read_text(), (d.name, f)
        m = json.loads((d / "meta.json").read_text())
        assert m["campaign"] == "run2" and m["capture_folder"] == "run-2"
    listed = client.get("/workbench/captures").json()
    assert listed["captures"][0]["imported_as"] == "run2" and "run2" in listed["taken"]


def test_without_a_report_the_cases_are_for_triage_only(lab):
    client, _, cases, split = lab
    client.post("/workbench/import", json={"folder": "run-2", "name": "quiet", "report": None})
    j = _wait(client)
    assert j["state"] == "done" and j["result"]["role"] == "triage" and not j["result"]["labelled"]
    assert json.loads(split.read_text())["operations"] == ["run1"]              # not evaluated
    assert not list(cases.glob("*/labels.json")) and len(list(cases.glob("quiet_*"))) == 20


def test_names_and_reports_are_checked(lab):
    client, *_ = lab
    post = lambda **kw: client.post("/workbench/import", json={"folder": "run-2", "name": "run2", **kw})
    assert post(name="run1").status_code == 409                                  # an operation already
    assert post(name="smoke").status_code == 409                                 # excluded, still taken
    assert post(name="Run_2").status_code == 400
    assert post(report="ground_truth.json").status_code == 400                   # not an operation report
    assert client.post("/workbench/import", json={"folder": "../cases_lab", "name": "x"}).status_code == 404
    assert client.post("/workbench/import", json={"folder": "nope", "name": "x"}).status_code == 404


def test_the_page_copies_in_a_capture_but_only_its_own_files(lab):
    client, caps, _, _ = lab
    log = (RUN / "web01" / "audit.log").read_bytes()
    assert client.put("/workbench/captures/run-3/web01/audit.log", content=log).status_code == 200
    assert (caps / "run-3" / "web01" / "audit.log").read_bytes() == log
    assert client.put("/workbench/captures/run-3/web01/audit.log", content=b"x").status_code == 409   # never over a file
    assert client.put("/workbench/captures/run-3/web01/run.sh", content=b"x").status_code == 400
    assert client.put("/workbench/captures/run-3/a/b/audit.log", content=b"x").status_code == 400
    assert client.put("/workbench/captures/.hidden/web01/audit.log", content=b"x").status_code == 400
    assert not list(caps.rglob("*.part")) and not (caps / ".hidden").exists()
    found = {c["folder"]: c for c in client.get("/workbench/captures").json()["captures"]}
    assert found["run-3"]["hosts"] == ["web01"] and found["run-3"]["reports"] == []
