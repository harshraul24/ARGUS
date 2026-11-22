"""Ad-hoc (live) triage (argus.live, tools/replay_capture.py, the workbench's live endpoints),
on the REAL run 1 capture. The stream is the captured audit logs written as the receiver would
write them; nothing is synthetic.

Run: .venv/bin/python -m pytest tests/ -q   (from `source code/`)
"""
from __future__ import annotations

import shutil
import sys
import time
from collections import defaultdict
from pathlib import Path

import pytest

from argus.collectors import lab_capture as LC
from argus.live.feed import HostFeed
from argus.live.loop import LiveTriage, engine_decider
from argus.reason import hypotheses as H
from argus.reason.engine import Config
from argus.rules.library import RuleLibrary

_ROOT = Path(__file__).resolve().parents[2]
RUN1 = _ROOT / "Test Setup" / "lab" / "captured" / "run1"
LIBRARY = _ROOT / "eval_runs" / "lab_library.json"
pytestmark = pytest.mark.skipif(not (RUN1 / "web01" / "audit.log").exists(), reason="needs the run1 capture")
FLAGGED = ("malicious", "suspicious")


def _stream(tmp: Path, hosts=("app01", "web01", "ws-dev01", "ws-fin01"), keep=lambda line: True) -> Path:
    out = tmp / "stream"
    for h in hosts:
        (out / h).mkdir(parents=True)
        lines = (RUN1 / h / "audit.log").read_bytes().split(b"\n")
        (out / h / "audit.log").write_bytes(b"\n".join(ln for ln in lines if keep(ln)))
    return out


def _agent_cases(lt: LiveTriage) -> set[str]:
    return {c.case_id for c in lt.cases.values()
            if any(Path(ev["facts"].get("image_path") or "").name == "splunkd" for _, ev, _ in c.events)}


def test_the_live_feed_gives_the_batch_converters_events_however_the_log_grows(tmp_path):
    log = RUN1 / "web01" / "audit.log"
    execs, acts = LC.parse_host(log, "web01"), LC.parse_activity(log, "web01")
    LC.build_lineage(execs, acts)
    batch = sorted((x["ts"], x["key"], x.get("kind") or "") for x in execs + acts)
    growing = tmp_path / "audit.log"
    data = log.read_bytes()
    feed, got = HostFeed("web01", growing, settle=3600), []    # completion alone releases events
    with open(growing, "wb") as f:
        for i in range(0, len(data), 7777):                    # appended in arbitrary pieces
            f.write(data[i:i + 7777])
            f.flush()
            got += feed.poll()
    got += feed.poll(flush=True)
    assert sorted((x["ts"], x["key"], x.get("kind") or "") for x in got) == batch


def test_run1_live_flags_each_hosts_agent_case_and_nothing_else(tmp_path):
    stream = _stream(tmp_path)
    lib = RuleLibrary.load(LIBRARY)
    for learned, expect in ((False, 0), (True, 4)):
        cfg = Config(hypotheses=list(H.HYPOTHESES) + (lib.hypotheses("active") if learned else []))
        hist = defaultdict(list)
        lt = LiveTriage(stream, tmp_path / f"cases{learned}", engine_decider(cfg, hist), run="run1")
        lt.poll(flush=True)
        flagged = {cid for cid, h in hist.items() if h[-1]["disposition"] in FLAGGED}
        agents = _agent_cases(lt)
        assert len(agents) == 4 and {lt.cases[c].host for c in agents} == {"app01", "web01", "ws-dev01", "ws-fin01"}
        assert len(flagged) == expect and (not learned or flagged == agents)
        for h in hist.values():                                  # two clocks on every decision
            assert all(r["event_time"] and r["decided_at"] for r in h)


def test_a_host_whose_connections_stop_is_a_blind_spot_and_a_healthy_one_is_not(tmp_path):
    """web01 with its connect records removed (as if the audit rule for them had stopped
    reporting): once the stream is older than HEALTH_WINDOW, its cases carry a blind spot."""
    lib = RuleLibrary.load(LIBRARY)
    cfg = Config(hypotheses=list(H.HYPOTHESES) + lib.hypotheses("active"))
    for drop, blind in ((False, False), (True, True)):
        stream = _stream(tmp_path / str(drop), hosts=("web01",),
                         keep=(lambda ln: not (ln.startswith(b"type=SYSCALL") and b'key="net"' in ln))
                         if drop else (lambda ln: True))     # the rule stays loaded; its records stop
        hist = defaultdict(list)
        lt = LiveTriage(stream, tmp_path / str(drop) / "cases", engine_decider(cfg, hist), run="run1")
        lt.poll(flush=True)
        late = [c for c in lt.cases.values() if c.last - lt.first_record["web01"] > 1900]
        assert late
        assert all(bool(hist[c.case_id][-1]["blind_spots"]) == blind for c in late), drop


def test_replay_streams_a_capture_exactly(tmp_path):
    sys.path.insert(0, str(_ROOT / "tools"))
    import replay_capture as R
    n = R.replay(RUN1, tmp_path / "replayed", speed=0, hosts=["web01"], say=lambda *_: None)
    src = (RUN1 / "web01" / "audit.log").read_bytes()
    assert n > 0 and (tmp_path / "replayed" / "web01" / "audit.log").read_bytes() == src + (b"" if src.endswith(b"\n") else b"\n")


def test_the_workbench_runs_live_triage_and_lists_its_flagged_cases(tmp_path, monkeypatch):
    from fastapi.testclient import TestClient
    from argus.api import workbench as W
    from argus.api.app import app
    caps = tmp_path / "captured"
    shutil.copytree(_stream(tmp_path, hosts=("web01",)), caps / "run1-live")
    monkeypatch.setattr(W, "CAPTURES", caps)
    monkeypatch.setattr(W, "ROOT", tmp_path)
    monkeypatch.setattr(W, "LIVE", None)
    monkeypatch.setenv("ARGUS_LIBRARY", str(LIBRARY))
    W._reload()
    client = TestClient(app)
    try:
        assert "run1-live" in client.get("/workbench/live").json()["runs"]
        assert client.post("/workbench/live", json={"run": "run1-live"}).json()["running"]
        assert client.post("/workbench/live", json={"run": "run1-live"}).status_code == 409
        for _ in range(200):
            st = client.get("/workbench/live").json()
            if st["flagged"]:
                break
            time.sleep(0.2)
        cases = client.get("/workbench/cases?root=live").json()
        assert "live" in client.get("/workbench/config").json()["roots"]
        first = cases["cases"][0]
        assert first["disposition"] in FLAGGED and first["host"] == "web01"
        v = client.get(f"/workbench/case/{first['case_id']}").json()
        assert v["verdict"]["disposition"] in FLAGGED and v["revisions"][-1]["event_time"]
        assert client.post(f"/workbench/triage/{first['case_id']}").json()["status"] == "complete"
    finally:
        client.post("/workbench/live/stop")
        monkeypatch.setenv("ARGUS_LIBRARY", "none")
        W._reload()
