"""Zeek collector, including the sensor-health channels v1 never opened.

The dataset ships 23 Zeek log types; v1 read two (conn, dns). The only surviving
evidence of the A04 lateral movement is a single record in smb_files.log, and the
fact that the sensor was degraded is recorded in capture_loss.log / notice.log —
neither of which had any consumer.
"""
from __future__ import annotations

import csv
from pathlib import Path

from argus.models import Claim, Control, Provenance, SensorHealth

REMOTE_PORTS = {"445", "139", "3389", "22", "5985", "5986"}
REMOTE_SERVICES = {"smb", "ssh", "rdp", "dce_rpc", "ntlm"}


def read_tsv(path: Path) -> list[dict[str, str]]:
    if not path.exists():
        return []
    fields: list[str] | None = None
    rows: list[dict[str, str]] = []
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        if line.startswith("#fields"):
            fields = line.split("\t")[1:]
            continue
        if not line or line.startswith("#") or fields is None:
            continue
        try:
            values = next(csv.reader([line], delimiter="\t"))
        except StopIteration:
            continue
        rows.append(dict(zip(fields, values)))
    return rows


def collect_network(net_dir: Path, sensor_id: str = "zeek") -> list[Claim]:
    claims: list[Claim] = []
    n = 0

    def add(ctype: str, entity: str, facts: dict, ts, src_file: str, conf: float = 0.93):
        nonlocal n
        n += 1
        claims.append(Claim(
            claim_id=f"net_{n:05d}",
            modality="network",
            claim_type=ctype,
            entity=entity,
            event=f"{ctype} {facts.get('src_ip','-')} -> {facts.get('dst_ip','-')}",
            time=ts,
            confidence=conf,
            facts=facts,
            # Passive network observation is not attacker-authored.
            provenance=[Provenance(sensor_id=sensor_id, source=src_file, control=Control.L0)],
        ))

    for r in read_tsv(net_dir / "conn.log"):
        port, svc = r.get("id.resp_p", ""), (r.get("service") or "").lower()
        facts = {"src_ip": r.get("id.orig_h"), "dst_ip": r.get("id.resp_h"),
                 "dst_port": port, "service": svc, "proto": r.get("proto"),
                 "state": r.get("conn_state"), "duration": r.get("duration")}
        if port in REMOTE_PORTS or svc in REMOTE_SERVICES:
            add("remote_access_session", r.get("id.orig_h", "-"), facts, r.get("ts"),
                str(net_dir / "conn.log"))
        else:
            add("network_connection", r.get("id.orig_h", "-"), facts, r.get("ts"),
                str(net_dir / "conn.log"), conf=0.85)

    for r in read_tsv(net_dir / "smb_files.log"):
        add("smb_file_operation", r.get("id.orig_h", "-"),
            {"src_ip": r.get("id.orig_h"), "dst_ip": r.get("id.resp_h"),
             "action": r.get("action"), "name": r.get("name"), "dst_port": "445"},
            r.get("ts"), str(net_dir / "smb_files.log"))

    for r in read_tsv(net_dir / "smb_mapping.log"):
        add("smb_share_mapping", r.get("id.orig_h", "-"),
            {"src_ip": r.get("id.orig_h"), "dst_ip": r.get("id.resp_h"),
             "share": r.get("path"), "share_type": r.get("share_type"), "dst_port": "445"},
            r.get("ts"), str(net_dir / "smb_mapping.log"))

    for r in read_tsv(net_dir / "ntlm.log"):
        ok = (r.get("success") or "").upper() == "T"
        add("ntlm_authentication", r.get("id.orig_h", "-"),
            {"src_ip": r.get("id.orig_h"), "dst_ip": r.get("id.resp_h"),
             "username": r.get("username"), "hostname": r.get("hostname"),
             "success": ok, "dst_port": "445"},
            r.get("ts"), str(net_dir / "ntlm.log"))

    for r in read_tsv(net_dir / "dns.log"):
        add("dns_query", r.get("id.orig_h", "-"),
            {"src_ip": r.get("id.orig_h"), "dst_ip": r.get("id.resp_h"),
             "query": r.get("query"), "rcode": r.get("rcode_name")},
            r.get("ts"), str(net_dir / "dns.log"), conf=0.85)

    return claims


def collect_health(net_dir: Path, sensor_id: str = "zeek",
                   covers: list[str] | None = None,
                   blind_to: list[str] | None = None) -> SensorHealth:
    """W6 — read what the sensor says about itself.

    In A04 this yields loss_pct = 35.294 and a CaptureLoss::Too_Much_Loss notice.
    v1 had no code path that opened either file.
    """
    health = SensorHealth(sensor_id=sensor_id, covers=covers or [], blind_to=blind_to or [])

    worst = 0.0
    for r in read_tsv(net_dir / "capture_loss.log"):
        try:
            worst = max(worst, float(r.get("percent_lost") or 0))
        except ValueError:
            continue
    health.loss_pct = worst

    for r in read_tsv(net_dir / "notice.log"):
        note = r.get("note", "")
        if "CaptureLoss" in note:
            health.notes.append(note)

    # An expected log that was never produced is scope degradation, not absence.
    for expected in ("conn.log",):
        if not (net_dir / expected).exists():
            health.healthy = False
            health.notes.append(f"{expected} not produced")

    return health
