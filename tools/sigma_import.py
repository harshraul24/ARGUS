"""Convert a dated intelligence snapshot's Sigma rules into ARGUS rules (argus.rules.sigma).

Writes intel/snapshots/<name>/argus_sigma_rules.json (the converted rules, each validated
by C1) and import_report.json (counts, every refusal with its reason, narrowed rules).

Usage (from the ARGUS root):  .venv/bin/python tools/sigma_import.py --snapshot lab
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "source code"))

from argus.rules.dsl import validate                               # noqa: E402
from argus.rules.sigma import load_snapshot                        # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", required=True)
    args = ap.parse_args()
    snap = ROOT / "intel" / "snapshots" / args.snapshot
    man = json.loads((snap / "MANIFEST.json").read_text())
    rules, refused = load_snapshot(snap)
    ok, invalid = [], []
    seen = set()
    for r in rules:
        errs = validate(r, {})
        if errs:
            invalid.append((r["provenance"]["sigma_path"], "; ".join(errs[:2])))
        elif r["id"] in seen:
            invalid.append((r["provenance"]["sigma_path"], f"duplicate id {r['id']}"))
        else:
            seen.add(r["id"])
            ok.append(r)
    reason = Counter(_bucket(why) for _, why in refused + invalid)
    by_cat = Counter((r["provenance"]["logsource"]["product"], r["provenance"]["logsource"]["category"]) for r in ok)
    out = {"snapshot": args.snapshot, "snapshot_aggregate": man["aggregate_sha256"],
           "sigma_commit": man["sources"]["sigma"]["commit"], "as_of": man["as_of"],
           "converted": len(ok), "narrowed": sum(r["provenance"]["narrowed"] for r in ok),
           "refused": len(refused) + len(invalid), "converted_by_logsource": {f"{p}/{c}": n for (p, c), n in by_cat.most_common()},
           "refusal_reasons": dict(reason.most_common()),
           "refusals": [{"path": p, "reason": w} for p, w in refused + invalid]}
    blob = json.dumps({"rules": ok}, indent=1)
    (snap / "argus_sigma_rules.json").write_text(blob)
    out["rules_sha256"] = hashlib.sha256(blob.encode()).hexdigest()
    (snap / "import_report.json").write_text(json.dumps(out, indent=1))
    print(f"{args.snapshot} (sigma {out['sigma_commit'][:10]}, as of {out['as_of']}): converted {out['converted']} "
          f"(narrowed {out['narrowed']}), refused {out['refused']}")
    print("  converted by logsource:", out["converted_by_logsource"])
    print("  top refusal reasons:", dict(list(out["refusal_reasons"].items())[:10]))


def _bucket(why: str) -> str:
    """Group refusal reasons for the report (the full reason stays per rule)."""
    for pat, name in (("has no ARGUS claim type", "logsource not in ARGUS telemetry"),
                      ("product", "not a Linux rule"),
                      ("is not in ARGUS", "field not in ARGUS telemetry"),
                      ("folder of a process", "needs parent/target folder"),
                      ("modifier", "unsupported modifier"),
                      ("keyword", "keyword search"),
                      ("aggregation", "aggregation"),
                      ("exclusion", "unsupported field inside an exclusion")):
        if pat in why:
            return name
    return why[:60]


if __name__ == "__main__":
    main()
