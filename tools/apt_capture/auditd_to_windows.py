"""Real multi-host auditd capture + CALDERA operation report -> ARGUS lab windows, from a
terminal. The conversion itself is argus/collectors/lab_capture.py (also behind the
workbench's Import capture sheet); see its docstring for what is written and how.

Usage (from the ARGUS root):
  .venv/bin/python tools/apt_capture/auditd_to_windows.py "Test Setup/lab/captured/run1" \
      --report "Test Setup/lab/captured/run1/test2_report.json" \
      --ground-truth "Test Setup/lab/captured/run1/ground_truth.json" --out cases_lab --name run1
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "source code"))

from argus.collectors.lab_capture import *          # noqa: E402,F401,F403  (tests use the parsers)
from argus.collectors.lab_capture import convert    # noqa: E402


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("captured", type=Path, help="directory with <host>/audit.log")
    ap.add_argument("--report", type=Path, required=True)
    ap.add_argument("--ground-truth", type=Path, default=None,
                    help="the run's ground_truth.json, for bootstrap abilities (not in the report)")
    ap.add_argument("--out", type=Path, default=Path("cases_lab"))
    ap.add_argument("--name", default="lab")
    ap.add_argument("--window-minutes", type=int, default=30)
    args = ap.parse_args()
    s = convert(args.captured, args.out, args.name, report=args.report, ground_truth=args.ground_truth,
                window_minutes=args.window_minutes)
    for row in s["windows"]:
        print("  %-24s events %5d (net %4d file %3d) malicious %4d steps %2d gate %s" % row)
    print(f"steps matched to processes: {s['steps_matched']}/{s['steps']}"
          + (f"  unmatched: {s['unmatched']}" if s["unmatched"] else ""))
    print("clock offset vs CALDERA (s):", s["clock_offset_s"])


if __name__ == "__main__":
    main()
