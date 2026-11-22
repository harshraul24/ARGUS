"""Event-level scoring of every labelled lab capture: each event is one unit.

Positive = an event CALDERA's labels mark malicious. Predicted positive = an event an
alerting rule selected (same selection as eval_lab / eval_cumulative's event precision).
Burn-in windows have no labels and no agent activity, so every event there is benign.

Reports TP/FP/FN/TN, precision, recall, F1, false-positive rate (with Wilson 95% CIs)
per capture (run1 = design/in-sample, smoke = unseen test, burnin = benign only) and pooled.

Usage (from the project root):
  .venv/bin/python tools/eval_events.py --out eval_runs/<date>-events
"""
from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "source code"))
sys.path.insert(0, str(ROOT / "tools"))

import lab_common as E                                           # noqa: E402
from eval_lab import LIBRARY, arms                               # noqa: E402


def _ids(w: Path) -> list[str]:
    with open(w / "events.jsonl") as fh:
        return [json.loads(l)["event_id"] for l in fh if l.strip()]


def _m(c: dict) -> dict:
    tp, fp, fn, tn = c["tp"], c["fp"], c["fn"], c["tn"]
    p = tp / (tp + fp) if tp + fp else None
    r = tp / (tp + fn) if tp + fn else None
    f1 = 2 * p * r / (p + r) if p and r else (0.0 if p is not None and r is not None else None)
    fpr = fp / (fp + tn) if fp + tn else None
    return {**c, "events": tp + fp + fn + tn,
            "precision": None if p is None else round(p, 4),
            "precision_ci95": E.wilson(tp, tp + fp),
            "recall": None if r is None else round(r, 4),
            "recall_ci95": E.wilson(tp, tp + fn),
            "f1": None if f1 is None else round(f1, 4),
            "fpr": None if fpr is None else round(fpr, 6),
            "fpr_ci95": E.wilson(fp, fp + tn),
            "false_alarms_per_10k_benign_events": None if fpr is None else round(1e4 * fpr, 2)}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", type=Path, default=LIBRARY)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()
    wins = E.windows()
    out = {"freeze": E.freeze_status(), "arms": {}}
    for arm, cfg in arms(args.library).items():
        per = defaultdict(lambda: {"tp": 0, "fp": 0, "fn": 0, "tn": 0})
        for w in wins:
            ids = set(_ids(w))
            mal = set(E.labels(w)["malicious_event_ids"]) & ids if (w / "labels.json").exists() else set()
            r = E.score_window(w, cfg)
            sel = (set().union(*[a["events"] for a in r["alerts"].values()]) if r["alerts"] else set()) & ids
            for key in (E.operation(w), "pooled"):
                c = per[key]
                c["tp"] += len(sel & mal)
                c["fp"] += len(sel - mal)
                c["fn"] += len(mal - sel)
                c["tn"] += len(ids - sel - mal)
        out["arms"][arm] = {k: _m(v) for k, v in per.items()}
        print(f"\n[{arm}]")
        for k, v in out["arms"][arm].items():
            print(f"  {k}: {json.dumps(v)}")
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "summary.json").write_text(json.dumps(out, indent=1, default=list))
        print(f"\nwrote {args.out}/summary.json")


if __name__ == "__main__":
    main()
