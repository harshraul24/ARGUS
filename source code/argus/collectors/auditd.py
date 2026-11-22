"""Adapter: a raw Linux auditd `audit.log` (execve auditing) -> process_create claims.

For a case directory that ships the raw log (`host/audit.log`, the APT-Agent captures).
Lab windows are converted ahead of time instead (collectors/lab_capture.py, read by
collectors/events.py), which adds lineage, network and watched-path events.

auth.log + Zeek see logins and flows, not the discovery / collection / staging commands
that are the bulk of an intrusion; auditd with an execve rule records a process creation
for every command. A DEFENDER-side log parser only: no detection logic.

auditd groups the records of one event by the `msg=audit(<epoch>:<serial>)` key:
    type=SYSCALL ... ppid=.. pid=.. uid=.. comm=".." exe=".." success=yes
    type=EXECVE  ... argc=N a0=".." a1=".."        (args, sometimes hex-encoded)
    type=CWD     ... cwd=".."
We join them, rebuild the command line from a0..aN, and emit one L2 process_create claim.
"""
from __future__ import annotations

import re
from pathlib import Path

from argus.models import Claim, Control, Provenance, SensorHealth
from argus.normalize.redact import redact

AUDITD_CLAIM_TYPES = ("process_create",)

_MSGID = re.compile(r"msg=audit\((?P<epoch>\d+\.\d+):(?P<serial>\d+)\)")
_KV = re.compile(r'(\w+)=("[^"]*"|\S+)')


def _unq(v: str) -> str:
    return v[1:-1] if len(v) >= 2 and v[0] == '"' and v[-1] == '"' else v


def _decode_arg(v: str) -> str:
    """An EXECVE arg is quoted, or hex-encoded when it holds spaces/specials."""
    if v.startswith('"'):
        return _unq(v)
    if re.fullmatch(r"[0-9A-Fa-f]+", v) and len(v) % 2 == 0:
        try:
            return bytes.fromhex(v).decode("utf-8", "replace")
        except ValueError:
            return v
    return v


def _rebuild_cmd(fields: dict) -> str:
    argc = fields.get("argc")
    if argc is None:
        return ""
    try:
        n = int(_unq(argc))
    except ValueError:
        return ""
    return " ".join(_decode_arg(fields[f"a{i}"]) for i in range(n) if f"a{i}" in fields)


def collect_auditd(path: Path, sensor_id: str = "auditd") -> list[Claim]:
    path = Path(path)
    if not path.exists():
        return []

    # group records by (epoch:serial)
    events: dict[str, dict] = {}
    order: list[str] = []
    with open(path, errors="ignore") as fh:
        for line in fh:
            mid = _MSGID.search(line)
            if not mid:
                continue
            key = f"{mid.group('epoch')}:{mid.group('serial')}"
            typ_m = re.search(r"type=(\w+)", line)
            typ = typ_m.group(1) if typ_m else ""
            kv = {k: v for k, v in _KV.findall(line)}
            if key not in events:
                events[key] = {"epoch": float(mid.group("epoch"))}
                order.append(key)
            if typ == "SYSCALL":
                events[key]["syscall"] = kv
            elif typ == "EXECVE":
                events[key]["execve"] = kv
            elif typ == "CWD":
                events[key]["cwd"] = _unq(kv.get("cwd", ""))

    from datetime import datetime, timezone
    claims: list[Claim] = []
    n = 0
    for key in order:
        ev = events[key]
        sc = ev.get("syscall") or {}
        ex = ev.get("execve") or {}
        if not ex and "exe" not in sc:
            continue                                   # only execve-bearing events are processes
        n += 1
        raw_cmd = _rebuild_cmd(ex) if ex else _unq(sc.get("exe", ""))
        cmd, _ = redact(raw_cmd)
        image = _unq(sc.get("exe", "")) or (cmd.split(" ", 1)[0] if cmd else "")
        ts = datetime.fromtimestamp(ev["epoch"], tz=timezone.utc).isoformat().replace("+00:00", "Z")
        facts = {
            "command": cmd, "image": image,
            "pid": _unq(sc.get("pid", "")), "parent_pid": _unq(sc.get("ppid", "")),
            "uid": _unq(sc.get("uid", "")), "user": _unq(sc.get("auid", "")) or _unq(sc.get("uid", "")),
            "cwd": ev.get("cwd", ""), "success": _unq(sc.get("success", "")),
            "host": "endpoint",
            "_event_id": f"{sensor_id}:{key}",          # for per-event evaluation
        }
        claims.append(Claim(
            claim_id=f"auditd_{n:06d}", modality="endpoint", claim_type="process_create",
            entity="endpoint", event=f"execve {image}", time=ts, confidence=0.9,
            facts=facts,
            provenance=[Provenance(sensor_id=f"{sensor_id}:endpoint", source=str(path),
                                   span=cmd[:160], control=Control.L2)],
        ))
    return claims


def auditd_health(claims: list[Claim]) -> SensorHealth:
    if not claims:
        return SensorHealth(sensor_id="auditd", healthy=False,
                            notes=["auditd recorded no execve events in this capture"])
    return SensorHealth(sensor_id="auditd", covers=["process_create"])
