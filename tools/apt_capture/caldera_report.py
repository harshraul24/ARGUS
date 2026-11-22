"""CALDERA operation report -> ARGUS ground_truth.json.

This ingests CALDERA's own operation report so a lab run emulated with CALDERA produces
ground truth in the exact shape label_campaign.py emits for APT-Agent — one ordered action trace with absolute
timestamps and ATT&CK ids. The DEFENDER telemetry still comes from auditd/Zeek/auth on the
target (argus.collectors.*); this file only turns "what CALDERA executed, when" into labels.

CALDERA gives this report at  GET /api/v2/operations/{id}/report  (or the GUI download).
Schema handled defensively across CALDERA 4.x/5.x:
    { "name","start","finish","host_group":[...],
      "steps": { "<paw>": {"steps":[ <link>, ... ]} | [ <link>, ... ] } }
each <link>:
    { "ability_id","name","command"(base64) | "plaintext_command",
      "attack": {"tactic","technique_id","technique_name"},
      "run_timestamp"|"finish"|"delegated_timestamp", "status"(0=success),
      "host","paw","platform" }

Usage:
    python tools/apt_capture/caldera_report.py operation_report.json --out ground_truth.json
"""
from __future__ import annotations

import argparse
import base64
import json
from pathlib import Path

# exfil/impact-leaning primary ordering (most-decisive objective first)
_PRIMARY_ORDER = ["T1486", "T1490", "T1041", "T1567", "T1210", "T1021", "T1110", "T1046"]


def _decode_cmd(link: dict) -> str:
    for k in ("command", "plaintext_command"):
        v = link.get(k)
        if not v:
            continue
        s = str(v)
        try:                                   # CALDERA base64-encodes commands (sometimes both fields)
            s = base64.b64decode(v, validate=True).decode("utf-8")
        except (ValueError, UnicodeDecodeError):
            pass                               # value was already plaintext
        s = s.strip()
        if s:
            return s
    ab = link.get("ability") or {}
    return str(ab.get("name") or link.get("name") or "").strip()


def _time(link: dict) -> str | None:
    for k in ("run_timestamp", "finish", "collect", "decide", "delegated_timestamp", "collect_timestamp"):
        if link.get(k):
            return str(link[k]).replace(" ", "T")
    return None


def _links(report: dict) -> list[dict]:
    """Flatten steps[paw] -> list of link dicts, tolerating both nestings."""
    out = []
    steps = report.get("steps") or {}
    if isinstance(steps, dict):
        for _paw, v in steps.items():
            seq = v.get("steps") if isinstance(v, dict) else v
            if isinstance(seq, list):
                out.extend(x for x in seq if isinstance(x, dict))
    elif isinstance(steps, list):
        out.extend(x for x in steps if isinstance(x, dict))
    # schema B (operation report export): host_group:[{..., links:[<link>, ...]}]
    for agent in report.get("host_group") or []:
        if isinstance(agent, dict):
            out.extend(lk for lk in (agent.get("links") or []) if isinstance(lk, dict))
    return out


def convert(report: dict) -> dict:
    actions = []
    techniques: set[str] = set()
    for link in _links(report):
        atk = link.get("attack") or link.get("ability") or {}
        tech = (atk.get("technique_id") or "").strip()
        tactic = (atk.get("tactic") or "").strip()
        if tech:
            techniques.add(tech.split(".")[0])
        status = link.get("status", 0)
        actions.append({
            "time": _time(link),
            "tactic": tactic or "?",
            "technique": tech or (atk.get("technique_name") or "")[:40],
            "detail": _decode_cmd(link),
            "result": "success" if status in (0, "0", "success") else "fail",
        })
    actions = [a for a in actions if a["time"]]
    actions.sort(key=lambda a: a["time"])

    primary = next((t for t in _PRIMARY_ORDER if t in techniques), None)
    if not primary and techniques:
        primary = sorted(techniques)[0]
    objective = any(a["result"] == "success" and a["technique"].startswith(("T1041", "T1486", "T1567"))
                    for a in actions)
    return {
        "category": "attack",
        "campaign_start": report.get("start") or (actions[0]["time"] if actions else None),
        "techniques": sorted(techniques),
        "primary_technique": primary,
        "objective_reached": objective,
        "source": f"caldera operation '{report.get('name','?')}'",
        "actions": actions,
    }


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("report", help="CALDERA operation report JSON")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()
    report = json.loads(Path(args.report).read_text())
    gt = convert(report)
    text = json.dumps(gt, indent=2)
    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out}  ({len(gt['actions'])} actions, "
              f"{len(gt['techniques'])} techniques, primary {gt['primary_technique']}, "
              f"objective_reached={gt['objective_reached']})")
    else:
        print(text)


if __name__ == "__main__":
    main()
