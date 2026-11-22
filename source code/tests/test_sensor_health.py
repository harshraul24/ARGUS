"""Sensor health (gap 4 of the 2026-11-16 review): a sensor that is not in a capture, and an
interval in which a sensor could not record, are blind spots and never evidence of absence.
On REAL captures: the burn-in's raw audit logs and windows, and the earlier attack captures.

Run: .venv/bin/python -m pytest tests/ -q   (from `source code/`)
"""
from __future__ import annotations

import shutil
from pathlib import Path

import pytest

from argus.case import load_case
from argus.collectors import lab_capture as LC
from argus.live.feed import HostFeed
from argus.models import DefeaterKind
from argus.reason.engine import Config, reason

_ROOT = Path(__file__).resolve().parents[2]
LINUX = _ROOT / "cases_linux"
LAB = _ROOT / "cases_lab"
BURNIN = _ROOT / "Test Setup" / "lab" / "captured" / "burnin"
needs_linux = pytest.mark.skipif(not (LINUX / "apt_live_010").is_dir(), reason="needs cases_linux")
needs_burnin = pytest.mark.skipif(not (BURNIN / "web01" / "audit.log").exists(), reason="needs the burn-in capture")
needs_windows = pytest.mark.skipif(not (LAB / "burnin_web01_0000" / "meta.json").exists(),
                                   reason="needs the converted burn-in (cases_lab)")


def _t1210(decision):
    return next(h for h in decision.hypotheses if h.technique == "T1210")


def _without_auth(tmp_path: Path, empty: bool = False) -> Path:
    """apt_live_010 (an exploited service, seen by Zeek) with its auth.log removed or emptied."""
    d = tmp_path / "apt_live_010"
    shutil.copytree(LINUX / "apt_live_010", d, ignore=shutil.ignore_patterns("results"))
    for f in (d / "host").glob("*auth*"):
        f.write_text("") if empty else f.unlink()
    return d


@needs_linux
def test_with_its_auth_log_the_capture_has_no_blind_spot():
    lc = load_case(LINUX / "apt_live_010")
    d = reason(lc.case_id, lc.claims, lc.health, Config())
    assert lc.health["authlog"].healthy and not d.blind_spots
    assert not _t1210(d).defeaters


@needs_linux
@pytest.mark.parametrize("empty", [False, True])
def test_a_missing_or_emptied_auth_log_is_a_blind_spot_not_a_rebuttal(tmp_path, empty):
    """The exploited-service hypothesis expects the session's authentication in auth.log.
    Without the log, that absence says nothing: an undercut of weight 0 and a blind spot.
    Before the fix the missing sensor was read as working, and its silence rebutted."""
    lc = load_case(_without_auth(tmp_path, empty))
    assert not lc.health["authlog"].healthy
    full = load_case(LINUX / "apt_live_010")
    before = _t1210(reason(full.case_id, full.claims, full.health, Config())).score
    d = reason(lc.case_id, lc.claims, lc.health, Config())
    h = _t1210(d)
    kinds = [x.kind for x in h.defeaters]
    assert DefeaterKind.UNDERCUT in kinds and DefeaterKind.REBUT not in kinds
    assert h.score == before                                   # nothing was held against it
    assert any("auth.log" in b for b in d.blind_spots)
    assert d.priority < d.severity                             # a blind spot lowers priority


@needs_linux
def test_a_sensor_with_no_health_record_is_absent_to_the_engine(tmp_path):
    """Whatever the loader, the engine never reads an unknown sensor's silence as evidence."""
    lc = load_case(_without_auth(tmp_path))
    health = {k: v for k, v in lc.health.items() if k != "authlog"}
    h = _t1210(reason(lc.case_id, lc.claims, health, Config()))
    assert [x.kind for x in h.defeaters] == [DefeaterKind.UNDERCUT]
    assert any("no authlog sensor in this capture" in g for g in h.coverage_gaps)


@needs_linux
def test_a_capture_without_zeek_declares_it(tmp_path):
    d = tmp_path / "apt_live_010"
    shutil.copytree(LINUX / "apt_live_010", d, ignore=shutil.ignore_patterns("results", "network"))
    assert not load_case(d).health["zeek"].healthy


@needs_burnin
def test_the_reboot_and_the_hourly_restarts_are_gaps_read_from_the_log_itself():
    """web01's burn-in: the audit daemon restarts at :47 every hour (the persona's sensor
    maintenance) and the host rebooted at 00:11. A restart stops the daemon and reloads its
    rules: one gap, not three."""
    gaps = LC.gaps_of(LC._records(BURNIN / "web01" / "audit.log"))
    whole = gaps.overlapping(0, float("inf"))
    reboot = [g for g in whole if g["seconds"] and g["seconds"] > 60]
    assert len(reboot) == 1 and 420 < reboot[0]["seconds"] < 440
    assert reboot[0]["start"].startswith("2026-10-15T00:11:11") and "audit daemon stopped" in reboot[0]["cause"]
    hourly = [g for g in whole if g["start"][14:19] == "47:01"]
    assert len(hourly) >= 11 and all(g["seconds"] < 1 for g in hourly)
    assert all(set(g["types"]) == {"network_connection", "process_create"} for g in hourly)
    assert all(g["seconds"] >= LC.MIN_GAP_S for g in whole)        # nothing of zero length
    # a window gets exactly the gaps that overlap it
    w = 1800
    start = (LC._epoch(reboot[0]["start"]) // w) * w
    assert [g["start"] for g in gaps.overlapping(start, start + w)] == [reboot[0]["start"]]
    assert gaps.overlapping(start - 10 * w, start - 9 * w + 1) != gaps.overlapping(start, start + w)


@needs_burnin
def test_the_live_feed_finds_the_same_gaps_as_the_log_grows(tmp_path):
    log = BURNIN / "web01" / "audit.log"
    batch = LC.gaps_of(LC._records(log)).overlapping(0, float("inf"))
    growing = tmp_path / "audit.log"
    data = log.read_bytes()
    feed = HostFeed("web01", growing, settle=3600)
    with open(growing, "wb") as f:
        for i in range(0, len(data), 65536):
            f.write(data[i:i + 65536])
            f.flush()
            feed.poll()
    feed.poll(flush=True)
    assert feed.gaps.overlapping(0, float("inf")) == batch


@needs_windows
def test_a_window_with_a_gap_reports_it_and_keeps_its_verdict():
    """S11 (LAB_TEST_SUITE.md): scheduled sensor maintenance is reported for exactly its
    interval, and nothing malicious comes of it."""
    lc = load_case(LAB / "burnin_web01_1630")
    assert len(lc.health["auditd"].gaps) == 2
    d = reason(lc.case_id, lc.claims, lc.health, Config())
    assert d.disposition.value == "benign"
    spots = [b for b in d.blind_spots if "not recording" in b]
    assert len(spots) == 2 and all("under 1 s" in b and "audit daemon stopped" in b for b in spots)
    assert any("confirm whether authorised" in a for a in d.next_actions)
    reboot = load_case(LAB / "burnin_web01_0000")
    d = reason(reboot.case_id, reboot.claims, reboot.health, Config())
    assert d.disposition.value == "benign"
    assert any("00:11:11 to 00:18:19 UTC (428 s)" in b for b in d.blind_spots)


@needs_windows
def test_a_window_without_a_gap_reports_none():
    lc = load_case(LAB / "burnin_web01_1500")
    d = reason(lc.case_id, lc.claims, lc.health, Config())
    assert not lc.health["auditd"].gaps and not any("not recording" in b for b in d.blind_spots)
