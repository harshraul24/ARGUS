"""ARGUS core on REAL Linux captures: the lab's run1/smoke windows (cases_lab) and the
APT-Agent Metasploitable captures (cases_linux). Skipped when the data is absent.

Run: .venv/bin/python -m pytest tests/ -q   (from `source code/`)
"""
from __future__ import annotations

import time
from collections import Counter

import pytest
from fastapi.testclient import TestClient

from argus.api.app import app
from argus.case import load_case
from argus.llm.verbalizer import render
from argus.models import Control
from argus.normalize.redact import RedactionError, assert_clean, redact
from argus.reason.engine import Config, reason

from lab_data import AGENT_WINDOW, LAB, LINUX, STEPS_WINDOW, case, needs_lab, needs_linux

BRUTE = LINUX / "apt_live_001"            # APT-Agent SSH brute force, live Metasploitable2
EXPLOIT = LINUX / "apt_live_014"          # APT-Agent vsftpd backdoor, live Metasploitable2


# --------------------------------------------------------------------- redaction

def test_linux_command_line_secrets_are_redacted_and_paths_are_not():
    for cmd in ("sshpass -p s3cretpass ssh www@10.0.0.3 hostname", "mysql -uroot -pS3cret appdb",
                "curl -u admin:hunter2 http://10.0.0.3/", "tool --password=abc"):
        out, n = redact(cmd)
        assert n == 1 and "<REDACTED:" in out, cmd
    for cmd in ("mkdir -p /var/tmp/x", "ssh -p 2222 host", "ps -p 1234"):
        assert redact(cmd) == (cmd, 0), cmd


def test_redaction_is_idempotent_and_the_gate_is_hard():
    once, _ = redact("sshpass -p s3cretpass ssh h")
    assert redact(once) == (once, 0)
    assert redact("sshpass -p x h")[0] == redact("sshpass -p x h")[0]       # same secret, same digest
    with pytest.raises(RedactionError):
        assert_clean("sshpass -p s3cretpass ssh h")


# --------------------------------------------------------------------- collection

@needs_lab
def test_a_lab_window_carries_processes_connections_watched_files_and_lineage():
    lc = case(STEPS_WINDOW)
    types = Counter(c.claim_type for c in lc.claims)
    assert types["process_create"] and types["host_network_connection"] and types["file_read"]
    assert all(c.facts.get("_procs") for c in lc.claims)                   # every claim has its actor
    cmd = next(c for c in lc.claims if c.claim_type == "process_create")
    assert cmd.provenance[0].control == Control.L2 and cmd.provenance[0].sensor_id.startswith("auditd:")


@needs_lab
def test_the_sensor_contract_comes_from_the_audit_rules_the_host_loaded():
    """run1's hosts loaded the connect rule; the smoke capture's did not. A smoke window
    without connections is therefore not blind to them, and a run1 window would be."""
    assert case(STEPS_WINDOW).health["auditd"].blind_to == []
    smoke = load_case(LAB / "smoke_web01_1230")
    assert smoke.meta["sensor_contract"] == ["process_create"]
    assert "host_network_connection" not in smoke.health["auditd"].blind_to


@needs_linux
def test_a_raw_linux_case_reads_auth_log_and_zeek():
    lc = load_case(BRUTE)
    assert {"logon_failure", "session_opened"} <= {c.claim_type for c in lc.claims}
    assert "zeek" in lc.health                                              # the network sensor is modelled
    assert "network_connection" in {c.claim_type for c in load_case(EXPLOIT).claims}


# --------------------------------------------------------------------- reasoning

@needs_lab
def test_every_claim_is_reachable():
    lc = case(STEPS_WINDOW)
    d = reason(lc.case_id, lc.claims, lc.health)
    assert d.claims_considered == d.claims_total == len(lc.claims)


@needs_linux
def test_brute_force_and_an_exploited_service_are_found_on_real_captures():
    for path, tech in ((BRUTE, "T1110"), (EXPLOIT, "T1210")):
        lc = load_case(path)
        d = reason(lc.case_id, lc.claims, lc.health, Config())
        assert d.disposition.value in ("malicious", "suspicious"), path.name
        assert tech in [h.technique for h in d.hypotheses if h.score > 0], path.name


@needs_lab
def test_a_weak_primitive_is_context_and_never_decides_alone():
    """12:30: the exfiltration primitive fires on the `curl` that fetched the agent from its
    server (labelled attack: the deployment), but one weak primitive does not decide."""
    lc = case(AGENT_WINDOW)
    d = reason(lc.case_id, lc.claims, lc.health, Config())
    assert "TA0010" in d.context and d.disposition.value == "benign"
    assert any("context" in n for n in d.notes)
    assert d.top is None or d.top.technique != "TA0010"
    ex = render(d)
    assert str(d.claims_total) in " ".join(ex.sentences)                    # content from the decision


# --------------------------------------------------------------------- API

@needs_linux
def test_api_async_submit_poll_and_late_evidence_revises():
    with TestClient(app) as client:
        assert client.get("/healthz").json()["ok"] is True
        r = client.post("/triage", json={"case_path": str(BRUTE), "case_id": "t-brute"})
        assert r.status_code == 202 and r.headers["Location"] == "/triage/t-brute"
        for _ in range(120):
            s = client.get("/triage/t-brute").json()
            if s["status"] in ("complete", "failed"):
                break
            time.sleep(0.25)
        assert s["status"] == "complete", s.get("error")
        assert s["decision"]["claims_considered"] == s["decision"]["claims_total"]
        # late evidence: the exploited-service capture's network records arrive afterwards
        late = [c.model_dump(mode="json") for c in load_case(EXPLOIT).claims
                if c.claim_type in ("network_connection", "remote_access_session")]
        after = client.post("/triage/t-brute/evidence",
                            json={"claims": late, "cause": "delayed Zeek upload"}).json()
        assert "T1210" in [h["technique"] for h in after["decision"]["hypotheses"] if h["score"] > 0]
        assert after["revisions"][-1]["cause"] == "delayed Zeek upload"


# --------------------------------------------------------------------- LLM layer

def test_cache_makes_runs_replayable(tmp_path):
    from argus.llm.cache import ResponseCache
    from argus.llm.client import LLMClient
    c1 = LLMClient(provider="stub", cache=ResponseCache(tmp_path))
    first = c1.complete("hello")
    second = LLMClient(provider="stub", cache=ResponseCache(tmp_path)).complete("hello")
    assert first.cached is False and second.cached is True and first.text == second.text
