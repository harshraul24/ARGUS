"""Merge duplicate active rules in a Linux rule library (label-free).

Two active rules are duplicates when they fire on exactly the same events in every window
of the design operations (lab_split.json). The more general one is kept
(RuleLibrary.merge_duplicates); the others are retired with the reason. No labels are read
and nothing the library detects on the design data is lost.

tools/rules_induce.py does this itself after promotion; this tool applies it to a library
written before that existed.

Usage (from the ARGUS root):
  .venv/bin/python tools/rules_dedupe.py                       # eval_runs/lab_library.json
  .venv/bin/python tools/rules_dedupe.py --library <path> [--also <path> ...]
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "source code"))
sys.path.insert(0, str(ROOT / "tools"))

import lab_common as E                                             # noqa: E402
from argus.case import load_case                                   # noqa: E402
from argus.reason.context import CaseContext                       # noqa: E402
from argus.rules import checks as C                                # noqa: E402
from argus.rules.library import RuleLibrary                        # noqa: E402


def design_hits(lib: RuleLibrary) -> dict[str, dict[str, set]]:
    """Active rule id -> design window -> event ids it fires on."""
    active = lib.by_status("active")
    hyps = dict(zip([e.uid for e in active], lib.hypotheses("active")))
    hits: dict[str, dict[str, set]] = {u: {} for u in hyps}
    for w in E.windows(E.split()["design"]):
        lc = load_case(w)
        ctx = CaseContext(claims=lc.claims, health=lc.health)
        for u, h in hyps.items():
            s, sel, _ = C.rule_score(h, lc.claims, ctx)
            if s > 0:
                hits[u][w.name] = {c.facts.get("_event_id") for c in sel if c.facts.get("_event_id")}
    return hits


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--library", type=Path, default=ROOT / "eval_runs" / "lab_library.json")
    ap.add_argument("--also", type=Path, nargs="*", default=[], help="other copies to write the result to")
    args = ap.parse_args()
    lib = RuleLibrary.load(args.library)
    before = len(lib.by_status("active"))
    merged = lib.merge_duplicates(design_hits(lib))
    for path in [args.library, *args.also]:
        lib.save(path)
    kept: dict[str, list[str]] = {}
    for gone, keep in merged:
        kept.setdefault(keep, []).append(gone)
    print(f"active rules {before} -> {len(lib.by_status('active'))} ({len(merged)} duplicates retired)")
    for keep, gone in sorted(kept.items()):
        print(f"  kept {keep}\n    retired {', '.join(gone)}")


if __name__ == "__main__":
    main()
