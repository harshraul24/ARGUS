"""Lab capture converter (tools/apt_capture/auditd_to_windows.py) on the REAL run1 capture.

Run: .venv/bin/python -m pytest tests/ -q   (from `source code/`)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
RUN = _ROOT / "Test Setup" / "lab" / "captured" / "run1"
pytestmark = pytest.mark.skipif(not (RUN / "web01" / "audit.log").exists(), reason="needs the run1 lab capture")
sys.path.insert(0, str(_ROOT / "tools" / "apt_capture"))


@pytest.fixture(scope="module")
def run1():
    import auditd_to_windows as A
    execs, acts = [], []
    for h in sorted(p.parent.name for p in RUN.glob("*/audit.log")):
        execs += A.parse_host(RUN / h / "audit.log", h)
        acts += A.parse_activity(RUN / h / "audit.log", h)
    execs.sort(key=lambda x: x["ts"])
    acts.sort(key=lambda x: x["ts"])
    A.build_lineage(execs, acts)
    report = json.loads((RUN / "test2_report.json").read_text())
    gt = json.loads((RUN / "ground_truth.json").read_text())
    return A, execs, acts, A.labels_from_report(report, execs, gt)


def test_enriched_fields_survive_the_group_separator(run1):
    _, execs, acts, _ = run1
    # auditd writes \x1d before UID="www", SYSCALL=connect, SADDR={...}; splitlines() broke there
    assert {x["user"] for x in execs if x["host"] == "web01"} >= {"www", "root"}
    assert any(a["kind"] == "network_connection" for a in acts)


def test_every_step_matches_a_process_and_clocks_agree(run1):
    _, _, _, lab = run1
    assert len(lab["steps"]) == 36 and all(s["matched"] for s in lab["steps"])
    assert {s["status"] for s in lab["steps"]} == {"success", "failed", "no_result"}
    assert sum(1 for s in lab["steps"] if s.get("bootstrap")) == 4
    assert all(abs(o) < 5 for o in lab["clock_offset_s"].values())          # the plan's clock gate


def test_the_agents_connection_is_attributed_to_it_and_benign_traffic_is_not(run1):
    _, _, acts, lab = run1
    agent = [a for a in acts if a["kind"] == "network_connection" and a["exe"].endswith("/splunkd")]
    assert {a["host"] for a in agent} == {"web01", "app01", "ws-dev01", "ws-fin01"}
    assert all(a["facts"]["dst_port"] == 8888 and a["key"] in lab["malicious"] for a in agent)
    benign = [a for a in acts if a["exe"].endswith("/curl") and a["facts"]["dst_ip"] == "127.0.0.1"]
    assert benign and not any(a["key"] in lab["malicious"] for a in benign)


def test_protocol_activity_is_found_from_the_protocols_own_commands(run1):
    A, execs, _, _ = run1
    # sensor_check: the first-boot provisioning's `auditctl -l` (make-victim.sh runcmd)
    assert {k for x in execs for k, f in A.PROTOCOL.items() if f(x)} == {
        "log_collection", "first_boot", "package_install", "sensor_check"}


BURNIN = _ROOT / "Test Setup" / "lab" / "captured" / "burnin"


@pytest.mark.skipif(not (BURNIN / "app01" / "audit.log").exists(), reason="needs the burn-in capture")
def test_events_stay_apart_across_a_reboot_and_the_later_protocol_is_recognised():
    """The burn-in's app01 rebooted: about 700 audit serials were reused. Records are grouped
    by time and serial together, so no event takes on another's records; and the later pull
    (`cat` of rotated logs), persona control and power-off are protocol, not benign activity."""
    import re
    from argus.collectors import lab_capture as LC
    log = BURNIN / "app01" / "audit.log"
    raw = {m.groups() for line in log.read_text(errors="ignore").split("\n")
           if (m := re.match(r"^type=\w+ msg=audit\((\d+\.\d+):(\d+)\)", line))}
    assert len({s for _, s in raw}) < len(raw)                      # serials are reused
    assert len(LC._records(log)) == len(raw)                        # one event per time and serial
    found = {k for x in LC.parse_host(log, "app01") for k, f in LC.PROTOCOL.items() if f(x)}
    assert {"log_collection", "persona_control", "power", "sensor_check"} <= found


@pytest.mark.skipif(not (_ROOT / "cases_lab" / "run1_web01_1330").exists(), reason="needs converted run1")
def test_workbench_names_ancestors_launched_in_an_earlier_window():
    from argus.api.workbench import _names
    assert "splunkd" in _names("cases_lab:run1_web01_1330").values()


def test_the_sensor_contract_follows_the_audit_rules_each_host_loaded(run1):
    A = run1[0]
    end = 2e9
    assert {"exec", "net"} <= A.loaded_keys(A.parse_rules(RUN / "web01" / "audit.log"), end)
    smoke = RUN.parent / "web01" / "audit.log"                     # the earlier smoke capture
    if smoke.exists():
        assert A.loaded_keys(A.parse_rules(smoke), end) == {"exec"}


@pytest.mark.skipif(not (_ROOT / "cases_lab" / "run1_web01_1330").exists(), reason="needs converted run1")
def test_the_lineage_map_keeps_each_processs_folder():
    import json
    procs = json.loads((_ROOT / "cases_lab" / "run1_web01_1330" / "lineage.json").read_text())["processes"]
    agent = [p for p in procs.values() if p["image"] == "splunkd"]
    assert agent and agent[0]["path"] == "/home/www/splunkd"


def test_the_agents_deployment_is_labelled_attack(run1):
    """The commands that fetched and launched the agent name its file or its server."""
    _, execs, _, lab = run1
    dep = [s for s in lab["steps"] if s.get("deployment")]
    assert {s["host"] for s in dep} == {"web01", "app01", "ws-dev01", "ws-fin01"}
    web = next(s for s in dep if s["host"] == "web01")
    cmds = {" ".join(x["argv"]) for x in execs if x["key"] in web["keys"]}
    assert any(c.startswith("curl ") and "/file/download" in c for c in cmds)
    assert "chmod +x splunkd" in cmds and any(c.startswith("./splunkd -server") for c in cmds)
    assert web["keys"] <= lab["malicious"]
