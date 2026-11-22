#!/usr/bin/env python3
"""ARGUS Cortex analyzer — the plugin surface for TheHive.

Contract: a JSON job on stdin, a JSON report on stdout. That is the whole
interface, which is why this is the first integration target: no vendor
licensing, no partner agreement, and real SOCs and national CERTs already run
Cortex.

Input (stdin):
    {"data": "/path/to/case", "dataType": "other",
     "config": {"url": "http://localhost:8000", "mode": "local"}}

Output (stdout):
    {"success": true, "summary": {...}, "artifacts": [...], "full": {...}}

Install:
    cp -r argus/plugins/ARGUS /opt/Cortex-Analyzers/analyzers/
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

TAXONOMY_LEVEL = {
    "malicious": "malicious",
    "suspicious": "suspicious",
    "undecidable": "info",      # abstention is not "safe"
    "benign": "safe",
}


def _taxonomy(namespace: str, predicate: str, value: str, level: str) -> dict:
    return {"level": level, "namespace": namespace, "predicate": predicate, "value": value}


def build_report(decision: dict) -> dict:
    disp = decision.get("disposition", "undecidable")
    level = TAXONOMY_LEVEL.get(disp, "info")
    hyps = [h for h in decision.get("hypotheses", []) if h.get("score", 0) > 0]
    top = hyps[0] if hyps else None
    blind = decision.get("blind_spots", [])

    taxonomies = [_taxonomy("ARGUS", "disposition", disp, level)]
    if top:
        taxonomies.append(_taxonomy("ARGUS", "technique",
                                    f"{top['technique']} ({top['score']:.2f})", level))
    if blind:
        # Surfaced as its own taxonomy so an analyst sees at a glance that the
        # verdict was formed under partial observability.
        taxonomies.append(_taxonomy("ARGUS", "blind-spots", str(len(blind)), "info"))

    # Observables worth pivoting on in TheHive.
    artifacts = []
    for h in hyps:
        for gap in h.get("coverage_gaps", []):
            artifacts.append({"dataType": "other", "data": gap, "tags": ["argus:coverage-gap"]})

    lines = [f"Disposition: {disp} (severity {decision.get('severity', 0):.2f})"]
    for h in hyps:
        lines.append(f"  {h['technique']} {h['name']} — score {h['score']:.2f}")
        for r in h.get("rationale", []):
            lines.append(f"      support: {r}")
        for d in h.get("defeaters", []):
            lines.append(f"      {d['kind']}: {d['reason']}")
    if blind:
        lines.append("Blind spots (evidence unavailable, NOT absent):")
        lines += [f"  - {b}" for b in blind]
    for a in decision.get("next_actions", []):
        lines.append(f"Next: {a}")
    for n in decision.get("notes", []):
        lines.append(f"Note: {n}")

    return {
        "success": True,
        "summary": {"taxonomies": taxonomies},
        "artifacts": artifacts,
        "full": {
            "disposition": disp,
            "severity": decision.get("severity"),
            "priority": decision.get("priority"),
            "hypotheses": hyps,
            "blind_spots": blind,
            "next_actions": decision.get("next_actions", []),
            "notes": decision.get("notes", []),
            "claims_total": decision.get("claims_total"),
            "claims_considered": decision.get("claims_considered"),
            "report": "\n".join(lines),
        },
    }


def run_local(case_path: str) -> dict:
    from argus.assurance import confound as cg
    from argus.assurance import observability as obsmod
    from argus.case import load_case
    from argus.reason.engine import Config, reason

    lc = load_case(Path(case_path))
    decision = reason(lc.case_id, lc.claims, lc.health,
                      Config(confound=cg.load(), observability=obsmod.load()),
                      lc.protocol_artifacts)
    return decision.model_dump(mode="json")


def run_remote(url: str, case_path: str, timeout: float = 300.0) -> dict:
    import time
    import httpx

    with httpx.Client(base_url=url, timeout=30.0) as client:
        r = client.post("/triage", json={"case_path": case_path})
        r.raise_for_status()
        case_id = r.json()["case_id"]

        deadline = time.time() + timeout
        while time.time() < deadline:
            s = client.get(f"/triage/{case_id}").json()
            if s["status"] == "complete":
                return s["decision"]
            if s["status"] == "failed":
                raise RuntimeError(s.get("error") or "triage failed")
            time.sleep(1.0)
    raise TimeoutError("ARGUS did not finish within the timeout")


def main() -> int:
    try:
        job = json.load(sys.stdin)
    except json.JSONDecodeError as exc:
        json.dump({"success": False, "errorMessage": f"bad job JSON: {exc}"}, sys.stdout)
        return 1

    data = job.get("data")
    cfg = job.get("config", {}) or {}
    if not data:
        json.dump({"success": False, "errorMessage": "no 'data' in job"}, sys.stdout)
        return 1

    try:
        if cfg.get("mode", "local") == "remote":
            decision = run_remote(cfg.get("url", "http://localhost:8000"), data)
        else:
            decision = run_local(data)
        json.dump(build_report(decision), sys.stdout, indent=2)
        return 0
    except Exception as exc:
        json.dump({"success": False,
                   "errorMessage": f"{type(exc).__name__}: {exc}"}, sys.stdout)
        return 1


if __name__ == "__main__":
    sys.exit(main())
