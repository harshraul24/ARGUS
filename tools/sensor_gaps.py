"""Add `sensor_gaps` to the meta.json of windows that were converted before the converter
recorded them (2026-11-16): the intervals in which a host's audit daemon was stopped or an
audit rule was unloaded, read from the capture's raw audit logs by the converter's own code
(argus.collectors.lab_capture.SensorGaps). Events, lineage and labels are not touched, so a
window's evidence is exactly what was scored before. New imports record the gaps themselves.

Usage (from the ARGUS root):
  .venv/bin/python tools/sensor_gaps.py --operation burnin --capture "Test Setup/lab/captured/burnin"
  .venv/bin/python tools/sensor_gaps.py --operation burnin --capture ... --dry-run
"""
from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "source code"))

from argus.collectors import lab_capture as LC                   # noqa: E402

LAB = ROOT / "cases_lab"


def _epoch(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("--operation", required=True, help="the capture's name in cases_lab (meta campaign)")
    ap.add_argument("--capture", type=Path, required=True, help="the capture folder with <host>/audit.log")
    ap.add_argument("--dry-run", action="store_true", help="report, write nothing")
    args = ap.parse_args()

    gaps = {log.parent.name: LC.gaps_of(LC._records(log)) for log in sorted(args.capture.glob("*/audit.log"))}
    if not gaps:
        sys.exit(f"no <host>/audit.log in {args.capture}")
    windows = with_gaps = 0
    for d in sorted(LAB.iterdir()):
        mp = d / "meta.json"
        if not mp.exists():
            continue
        meta = json.loads(mp.read_text())
        if meta.get("campaign") != args.operation:
            continue
        if meta.get("host") not in gaps:
            sys.exit(f"{d.name}: host {meta.get('host')} has no audit.log in {args.capture}")
        w = meta["capture"]["window"]
        found = gaps[meta["host"]].overlapping(_epoch(w["start"]), _epoch(w["end"]))
        windows += 1
        with_gaps += bool(found)
        for g in found:
            print(f"  {d.name}: {g['start'][:19]} to {str(g['end'])[:19]} "
                  f"({g['seconds']} s) {'+'.join(g['types'])}: {g['cause']}")
        if not args.dry_run:
            # in the converter's key order: after sensor_contract
            out = {}
            for k, v in meta.items():
                if k != "sensor_gaps":
                    out[k] = v
                if k == "sensor_contract":
                    out["sensor_gaps"] = found
            out.setdefault("sensor_gaps", found)
            mp.write_text(json.dumps(out, indent=1))
    print(f"{args.operation}: {windows} window(s), {with_gaps} with a sensor gap"
          + (" (dry run: nothing written)" if args.dry_run else ""))


if __name__ == "__main__":
    main()
