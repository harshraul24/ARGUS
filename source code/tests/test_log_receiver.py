"""The lab's log receiver (Test Setup/lab/log_receiver.py), fed REAL lines from the burn-in
capture over a real local TCP connection, framed the way the victims' rsyslog frames them
(forward-logs.sh: RFC 5424, octet-counted). No model, no victim: the receiving side only.

Run: .venv/bin/python -m pytest tests/ -q   (from `source code/`)
"""
from __future__ import annotations

import socket
import sys
import threading
import time
from pathlib import Path

import pytest

_ROOT = Path(__file__).resolve().parents[2]
LAB = _ROOT / "Test Setup" / "lab"
BURNIN = LAB / "captured" / "burnin" / "app01"
sys.path.insert(0, str(LAB))

import log_receiver as R                                         # noqa: E402

pytestmark = pytest.mark.skipif(not (BURNIN / "audit.log").exists(), reason="needs the burn-in capture")


def _lines(name: str, n: int) -> list[str]:
    text = (BURNIN / name).read_bytes().decode("utf-8", errors="surrogateescape")
    return [ln for ln in text.split("\n") if ln][:n]


def _frame(host: str, tag: str, msg: str) -> bytes:
    """One line as forward-logs.sh's rsyslog sends it (RSYSLOG_SyslogProtocol23Format)."""
    body = f"<133>1 2026-10-14T13:24:00.000000+00:00 {host} {tag} - - - {msg}\n".encode("utf-8", "surrogateescape")
    return str(len(body)).encode() + b" " + body


def _send(port: int, payload: bytes, chunk: int = 997) -> None:
    with socket.create_connection(("127.0.0.1", port)) as s:
        for i in range(0, len(payload), chunk):               # frames split across packets
            s.sendall(payload[i:i + chunk])


def _wait(store: R.Store, host: str, name: str, lines: int) -> None:
    for _ in range(200):
        if store.status()["hosts"].get(host, {}).get(name, {}).get("lines", 0) >= lines:
            return
        time.sleep(0.02)


def test_lines_arrive_exactly_as_written_once_each(tmp_path):
    audit, auth, act = _lines("audit.log", 3000), _lines("auth.log", 40), _lines("benign-activity.log", 200)
    assert any("\x1d" in ln for ln in audit)                  # auditd's enriched-field separator
    store = R.Store(tmp_path, since=0)
    srv = R.make_server(store, "127.0.0.1", 0)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    port = srv.server_address[1]
    try:
        payload = b"".join(_frame("app01", "argus-audit", ln) for ln in audit)
        payload += b"".join(_frame("app01", "argus-auth", ln) for ln in auth)
        payload += b"".join(_frame("app01", "argus-activity", ln) for ln in act)
        payload += _frame("app01", "argus-test", "forwarding test from app01")
        payload += _frame("app01", "cron", "an ordinary syslog line, not part of the capture")
        _send(port, payload)
        _send(port, b"".join(_frame("app01", "argus-audit", ln) for ln in audit[:500]))   # resent
        _wait(store, "app01", "audit.log", len(set(audit)))
        _wait(store, "app01", "benign-activity.log", len(set(act)))
    finally:
        srv.shutdown()
        store.close()

    def written(name):
        return (tmp_path / "app01" / name).read_bytes().decode("utf-8", "surrogateescape").split("\n")[:-1]

    def once(xs):
        return list(dict.fromkeys(xs))

    assert written("audit.log") == once(audit)                # byte for byte, in order, no repeats
    assert written("auth.log") == once(auth)
    assert written("benign-activity.log") == once(act)
    st = store.status()
    assert st["tests"] == ["app01 (127.0.0.1)"]
    assert st["dropped"]["other tag"] == 1 and st["dropped"]["duplicate (resent)"] >= 500


def test_lines_recorded_before_the_run_are_left_out(tmp_path):
    audit = _lines("audit.log", 2000)
    times = [R.record_time("audit.log", ln) for ln in audit]
    cut = sorted(t for t in times if t)[len(audit) // 2]
    store = R.Store(tmp_path, since=cut)
    for ln in audit:
        store.write("app01", "argus-audit", ln, peer="test")
    store.close()
    kept = (tmp_path / "app01" / "audit.log").read_text(errors="ignore").split("\n")[:-1]
    assert kept and all(R.record_time("audit.log", ln) >= cut for ln in kept)
    assert store.status()["dropped"]["recorded before this run"] == sum(1 for t in times if t and t < cut)


def test_an_escaped_separator_is_restored_and_a_bad_host_name_is_refused(tmp_path):
    line = next(ln for ln in _lines("audit.log", 3000) if "\x1d" in ln)
    host, tag, msg = R.parse_frame(_frame("app01", "argus-audit", line.replace("\x1d", "#035")).split(b" ", 1)[1])
    assert (host, tag, msg) == ("app01", "argus-audit", line)
    store = R.Store(tmp_path, since=0)
    store.write("../etc", "argus-audit", line, peer="test")
    assert store.status()["dropped"] == {"bad host name": 1} and not list(tmp_path.iterdir())


@pytest.mark.skipif(not (LAB / "captured" / "run2" / "run2_report.json").exists(), reason="needs run2")
def test_the_check_finds_run2s_missing_hosts(capsys):
    """Run 2's SSH pull fetched only app01's audit log: the check must say so."""
    assert R.check("run2") == 1
    out = capsys.readouterr().out
    for h in ("web01", "ws-dev01", "ws-fin01"):
        assert f"FAIL {h:<10} no audit.log" in out
    assert "ok   app01" in out                                   # complete through the operation
    assert "KALI" not in out                                     # the server is not a victim
