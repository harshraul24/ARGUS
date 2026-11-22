"""Score frozen ARGUS on real lab captures (cases_lab/, from tools/apt_capture/auditd_to_windows.py).

Nothing here tunes ARGUS: the arms are ARGUS's hand-written reasoning alone, and with the
Linux rule library written on the design operations (tools/rules_induce.py: active rules
decide, shadow rules are measured). Labels are read only to grade.
Metrics are reported over all windows and over the windows that pass the capture-validity
gate (meta.json `capture_gate`, LAB_EVAL_PLAN.md §2), with steps split by CALDERA status
and bootstrap steps counted separately.

Usage (from the ARGUS root):  .venv/bin/python tools/eval_lab.py --operations run1 --out eval_runs/<run>
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "source code"))
sys.path.insert(0, str(ROOT / "tools"))

import lab_common as E                                             # noqa: E402
from argus.case import load_case                                   # noqa: E402
from argus.reason import hypotheses as H                           # noqa: E402
from argus.reason.engine import Config                             # noqa: E402
from argus.rules.library import RuleLibrary                        # noqa: E402

LIBRARY = ROOT / "eval_runs" / "lab_library.json"


def arms(library: Path) -> dict[str, Config]:
    out = {"argus": Config(hypotheses=list(H.HYPOTHESES))}
    if library.exists():
        lib = RuleLibrary.load(library)
        out["argus_s3"] = Config(hypotheses=list(H.HYPOTHESES) + lib.hypotheses("active"),
                                 shadow=lib.hypotheses("shadow"))
    return out


def metrics(rows: list[dict], steps: list[dict]) -> dict:
    flagged = Counter((r["category"], r["disposition"] in E.FLAGGED) for r in rows)
    att = sum(1 for r in rows if r["category"] == "attack")
    ben = sum(1 for r in rows if r["category"] == "benign")
    k = sum(s["detected"] for s in steps)
    sel = sum(r["selected"] for r in rows)
    return {"attack_windows_flagged": f"{flagged[('attack', True)]}/{att}",
            "benign_windows_flagged": f"{flagged[('benign', True)]}/{ben}",
            "steps_detected": f"{k}/{len(steps)}", "step_recall_ci95": E.wilson(k, len(steps)) if steps else None,
            "event_precision": round(sum(r["malicious_selected"] for r in rows) / sel, 4) if sel else None,
            "steps_by_rule": dict(Counter(t for s in steps for t in s["by"]).most_common())}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--operations", nargs="+", required=True, help="lab operations to score (lab_split.json)")
    ap.add_argument("--library", type=Path, default=LIBRARY)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    wins = E.windows(args.operations)
    fz = E.freeze_status()
    sp = E.split()
    role = {o: ("design" if o in sp["design"] else "test" if o in sp["test"] else "excluded")
            for o in args.operations}
    print(f"ARGUS freeze {fz['manifest']} matches={fz['matches']} · {len(wins)} windows · {role}")
    out = {"freeze": fz, "operations": role, "arms": {}}
    for arm, cfg in arms(args.library).items():
        steps, rows = [], []
        # NOVELTY has no Linux baseline until fix F1 (per-host burn-in), so it stays off
        for w in wins:
            lab = json.loads((w / "labels.json").read_text())
            meta = json.loads((w / "meta.json").read_text())
            r = E.score_window(w, cfg)
            sel = set().union(*[a["events"] for a in r["alerts"].values()]) if r["alerts"] else set()
            mal = set(lab["malicious_event_ids"])
            gate = meta.get("capture_gate", "pass")
            for a in lab["abilities"]:
                hit = sorted(t for t, x in r["alerts"].items() if x["events"] & set(a["event_ids"]))
                steps.append({"window": w.name, "step": a["name"], "status": a.get("status"),
                              "bootstrap": bool(a.get("bootstrap")), "deployment": bool(a.get("deployment")),
                              "gate": gate,
                              "detected": bool(hit), "by": hit})
            lc = load_case(w)
            rows.append({"window": w.name, "category": lab["category"], "gate": gate,
                         "disposition": r["disposition"], "alerts": sorted(r["alerts"]),
                         "context": r["context"],
                         "selected": len(sel), "malicious_selected": len(sel & mal),
                         "malicious": len(mal), "blind_spots": r["blind_spots"][:4], "claims": len(lc.claims)})
        m = {"all": metrics(rows, steps),
             "gate_pass": metrics([r for r in rows if r["gate"] == "pass"], [s for s in steps if s["gate"] == "pass"]),
             "steps_by_status": {k: f"{sum(s['detected'] for s in steps if s['status'] == k)}/"
                                    f"{sum(1 for s in steps if s['status'] == k)}"
                                 for k in sorted({s["status"] for s in steps})},
             "bootstrap_steps": f"{sum(s['detected'] for s in steps if s['bootstrap'])}/{sum(s['bootstrap'] for s in steps)}",
             "deployment_steps": f"{sum(s['detected'] for s in steps if s['deployment'])}/{sum(s['deployment'] for s in steps)}"}
        out["arms"][arm] = {"metrics": m, "windows": rows, "steps": steps}
        print(f"\n[{arm}]")
        for k, v in m.items():
            print(f"  {k}: {json.dumps(v)}")
        for r in rows:
            print(f"  {r['window']:<24} {r['category']:<7} -> {r['disposition']:<12} alerts {r['alerts']} "
                  f"sel {r['selected']} (mal {r['malicious_selected']}/{r['malicious']})"
                  + (f" context {r['context']}" if r["context"] else "")
                  + ("" if r["gate"] == "pass" else f"  [gate {r['gate']}]"))
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "summary.json").write_text(json.dumps(out, indent=1, default=sorted))
        print(f"wrote {args.out}/summary.json")


if __name__ == "__main__":
    main()
