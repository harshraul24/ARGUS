"""Adapter: a Linux capture window's `events.jsonl` (+ `lineage.json`) -> ARGUS claims.

INPUT-FITTING ONLY. A window is written by collectors/lab_capture.py (the workbench's Import
capture, or tools/apt_capture/auditd_to_windows.py) from a victim's auditd log; this maps
its events onto ARGUS's claim shapes and introduces no detection logic.

Mapping:
  process_create      -> process_create (L2): command, image, image_path, parent, user, cwd
  network_connection  -> host_network_connection (L0): dst_ip, dst_port, direction, image
  file_read/_write/_create/_delete/_rename -> the same claim type (L1/L2): file_path,
                         audit_key — hits on the paths the sensor watches
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

from argus.models import Claim, Control, Provenance, SensorHealth
from argus.normalize.redact import redact

EVENTS_FORMAT = "argus-events-v1"

_FILE = {
    "file_read":   Control.L1,
    "file_write":  Control.L2,
    "file_create": Control.L2,
    "file_delete": Control.L2,
    "file_rename": Control.L2,
}

# What auditd records continuously when its execve and connect rules are loaded. Watched-path
# hits (file_*) fire only when a watched file is touched, so their absence is not a gap.
DEFAULT_CONTRACT = ("process_create", "host_network_connection")
_CONTRACT_NAMES = {"network_connection": "host_network_connection"}


def events_health(claims: list[Claim], contract=None, sensor_id: str = "auditd",
                  gaps=None) -> SensorHealth:
    """W6, within-capture and label-free: a claim type the sensor is configured to record
    (`contract`, from the window's meta.json) that it emitted zero times is a blind spot,
    not evidence of absence. The engine turns a missing expectation into an undercut.
    `gaps` (meta.sensor_gaps) are the intervals in which the sensor could not record: its
    daemon was stopped or a rule was unloaded. Each is a blind spot as well."""
    gaps = [g for g in (gaps or []) if isinstance(g, dict) and g.get("start")]
    # no contract given: the default; an explicit empty one (a live case whose host's stream
    # is healthy, argus.live): nothing is expected to be missing
    expected = tuple(_CONTRACT_NAMES.get(t, t) for t in (DEFAULT_CONTRACT if contract is None else contract))
    if not claims:
        return SensorHealth(sensor_id=sensor_id, healthy=False, gaps=gaps,
                            notes=[f"the {sensor_id} sensor recorded nothing in this capture"])
    present = Counter(c.claim_type for c in claims)
    missing = [t for t in expected if not present.get(t)]
    return SensorHealth(sensor_id=sensor_id, covers=sorted(present), blind_to=missing, gaps=gaps,
                        notes=[f"recorded no {t} events in this capture" for t in missing]
                        + [gap_text(g) for g in gaps])


def gap_text(g: dict) -> str:
    """One sensor gap in words: "not recording 2026-10-15 00:11:11 to 00:18:19 UTC (428 s):
    audit daemon stopped"."""
    types = [_CONTRACT_NAMES.get(t, t) for t in g.get("types") or []]
    what = "" if len(types) != 1 else f" {types[0]}"
    start, end = str(g["start"])[:19].replace("T", " "), g.get("end")
    if end is None:
        span, dur = f"since {start} UTC", "not resumed in this capture"
    else:
        end = str(end)[:19].replace("T", " ")
        secs = g.get("seconds")
        dur = "under 1 s" if secs is not None and secs < 1 else f"{secs:.0f} s" if secs is not None else "?"
        span = f"{start} to {end[11:] if end[:10] == start[:10] else end} UTC"
    return f"not recording{what} {span} ({dur}): {g.get('cause', 'cause not recorded')}"


def _lineage(path: Path) -> tuple[dict, dict]:
    """(actors, processes) from the `lineage.json` beside the events, if present.

    actors: event_id -> process keys that performed it; processes: key -> {image, path, parent,
    children (distinct child programs over the process's recorded life)}.
    A key is `host/pid@exec-time` (PIDs are reused)."""
    side = path.parent / "lineage.json"
    if not side.exists():
        return {}, {}
    d = json.loads(side.read_text())
    return d.get("actors", {}), d.get("processes", {})


def _chain(key: str, procs: dict, limit: int = 64) -> list[str]:
    out = []
    while key and key not in out and len(out) < limit:
        out.append(key)
        key = (procs.get(key) or {}).get("parent")
    return out


# facts mapped onto ARGUS's own names below, so not carried twice
_MAPPED = {"command_line", "parent_image"}


def collect_events(path: Path, sensor_id: str = "auditd") -> list[Claim]:
    path = Path(path)
    if not path.exists():
        return []
    actors, procs = _lineage(path)
    claims: list[Claim] = []
    n = 0
    with open(path, errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            et = e.get("event_type")
            f = e.get("facts") or {}
            host = e.get("host", "-")
            carried = {k: v for k, v in f.items() if k not in _MAPPED}
            n += 1

            if et == "process_create":
                cmd, _ = redact(f.get("command_line") or "")
                facts = {**carried, "command": cmd, "parent": f.get("parent_image"), "host": host}
                ctype, modality, control = "process_create", "endpoint", Control.L2
            elif et == "network_connection":
                facts = {**carried, "host": host}
                ctype, modality, control = "host_network_connection", "network", Control.L0
            elif et in _FILE:
                facts = {**carried, "host": host}
                ctype, modality, control = et, "endpoint", _FILE[et]
            else:
                continue

            facts["_event_id"] = e.get("event_id")   # for per-event evaluation (underscore = hidden in display)
            if actors.get(e.get("event_id")):
                # W-E: each performing process with its ancestry, nearest first. The graph
                # is rebuilt from claims (reason.lineage), so every caller of reason() gets it.
                chains = [_chain(k, procs) for k in actors[e["event_id"]]]
                facts["_procs"] = chains
                # names and folders of the chain's processes, from the window's lineage map:
                # an ancestor launched in an earlier window performed nothing here
                facts["_proc_meta"] = {k: [procs[k].get("image"), procs[k].get("path"),
                                           procs[k].get("children") or []]
                                       for ch in chains for k in ch if k in procs}
            claims.append(Claim(
                claim_id=f"ev_{n:06d}", modality=modality, claim_type=ctype,
                entity=host, event=f"{et} on {host}", time=e.get("time"), confidence=0.9,
                facts=facts,
                provenance=[Provenance(
                    sensor_id=f"{sensor_id}:{host}", source=str(path),
                    span=str(facts.get("command") or facts.get("file_path") or facts.get("image") or "")[:160],
                    control=control)],
            ))
    return claims
