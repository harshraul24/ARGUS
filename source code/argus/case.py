"""Case loading: a directory of Linux telemetry -> claims + sensor health.

Two layouts:
  window   `events.jsonl` (+ `lineage.json`, `meta.json`), written by
           collectors/lab_capture.py from a victim's auditd log
  case     `host/` (auth.log, syslog, audit.log) and `network/` (Zeek logs)

Sensors are modelled objects, not implicit file paths: the registry declares what each
sensor covers and what it is blind to.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from argus.collectors.linux import collect_auth, collect_syslog
from argus.collectors.zeek import collect_health, collect_network
from argus.models import Claim, SensorHealth


@dataclass
class LoadedCase:
    case_id: str
    claims: list[Claim]
    health: dict[str, SensorHealth] = field(default_factory=dict)
    # Techniques the capture protocol induces. Reported, never scored. None on Linux yet.
    protocol_artifacts: set[str] = field(default_factory=set)
    meta: dict = field(default_factory=dict)


def _zeek_scope(meta: dict) -> tuple[list[str], list[str]]:
    """Derive coverage from the range topology."""
    topo = meta.get("topology") or {}
    sensor = topo.get("zeek_sensor") or {}
    covers, blind = [], []
    s1, s2 = topo.get("s1_subnet"), topo.get("s2_subnet")
    pos = str(sensor.get("position", "")).lower()
    if s1:
        covers.append(s1)
    if s2:
        # A sensor on the S1-side boundary does not observe the S2 segment.
        (blind if "s1" in pos or not pos else covers).append(s2)
    return covers, blind


def _capture_year(meta: dict) -> int:
    """auth.log lines carry no year; recover it from the capture window."""
    from datetime import datetime, timezone
    win = (meta.get("capture") or {}).get("window") or {}
    start = win.get("start") or ""
    if len(start) >= 4 and start[:4].isdigit():
        return int(start[:4])
    return datetime.now(timezone.utc).year


def load_case(case_dir: Path, case_id: str | None = None) -> LoadedCase:
    case_dir = Path(case_dir)
    case_id = case_id or case_dir.name
    meta = {}
    if (case_dir / "meta.json").exists():
        meta = json.loads((case_dir / "meta.json").read_text())

    # Window layout: converted auditd events with lineage.
    events_file = case_dir / "events.jsonl"
    if events_file.exists():
        from argus.collectors.events import collect_events, events_health
        claims = collect_events(events_file)
        return LoadedCase(case_id=case_id, claims=claims,
                          health={"auditd": events_health(claims, meta.get("sensor_contract"),
                                                          gaps=meta.get("sensor_gaps"))},
                          meta=meta)

    # Case layout: raw host logs + Zeek.
    host_dir, net_dir = case_dir / "host", case_dir / "network"
    claims: list[Claim] = []
    health: dict[str, SensorHealth] = {}
    year = _capture_year(meta)
    # Every sensor of this layout gets a health record, present or not: a hypothesis that
    # expects evidence from a sensor that is not in the capture must be told so (an
    # undercut), never left to read its silence as "nothing happened" (a rebut).
    auth_files = sorted(set(host_dir.glob("auth.log")) | set(host_dir.glob("*auth*.log")))
    auth_claims: list[Claim] = []
    for f in auth_files:
        auth_claims += collect_auth(f, year=year)
    claims += auth_claims
    health["authlog"] = _authlog_health(auth_files, auth_claims)
    if (host_dir / "syslog").exists():
        claims += collect_syslog(host_dir / "syslog", year=year)
    audit_files = sorted(set(host_dir.glob("audit.log")) | set(host_dir.glob("*audit*.log")))
    if audit_files:
        from argus.collectors.auditd import auditd_health, collect_auditd
        for f in audit_files:
            claims += collect_auditd(f)
        health["auditd"] = auditd_health([c for c in claims if c.provenance
                                          and str(c.provenance[0].sensor_id).startswith("auditd")])
    if net_dir.exists():
        claims += collect_network(net_dir)
        covers, blind = _zeek_scope(meta)
        health["zeek"] = collect_health(net_dir, covers=covers, blind_to=blind)
    else:
        health["zeek"] = SensorHealth(sensor_id="zeek", healthy=False,
                                      notes=["no Zeek logs in this capture"])
    return LoadedCase(case_id=case_id, claims=claims, health=health, meta=meta)


def _authlog_health(files: list[Path], claims: list[Claim]) -> SensorHealth:
    """auth.log's health from the file itself: missing, or present with no line at all (a
    running host always writes some: cron sessions, sudo), is a sensor that could not speak."""
    if not files:
        return SensorHealth(sensor_id="authlog", healthy=False, notes=["no auth.log in this capture"])
    if not any(line.strip() for f in files for line in open(f, errors="ignore")):
        return SensorHealth(sensor_id="authlog", healthy=False,
                            notes=["auth.log is empty: cleared, or never written"])
    return SensorHealth(sensor_id="authlog", covers=sorted({c.claim_type for c in claims}))


def ground_truth(case_dir: Path) -> dict:
    p = Path(case_dir) / "meta.json"
    if not p.exists():
        return {}
    meta = json.loads(p.read_text())
    tech = (meta.get("mitre") or {}).get("technique", "")
    return {
        "is_attack": meta.get("category") == "attack",
        "title": meta.get("title"),
        "technique": str(tech).split(" ")[0] if tech else None,
    }
