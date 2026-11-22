"""Replay a captured run as if its victims were streaming it now (LAB_ADHOC_TEST.md L5).

Each host's audit.log in the source capture is written, line by line in record-time order
across all hosts, into `Test Setup/lab/captured/<as>/<host>/audit.log` — where the log
receiver would write a live run — at `--speed` times the original pace. Ad-hoc triage
(the workbench's Live sheet, argus.live) then sees exactly what it would have seen while the
run happened. Real captures only; nothing is changed in the source.

Usage (from the ADGUS root):
  .venv/bin/python tools/replay_capture.py "Test Setup/lab/captured/run1" --as replay-run1 --speed 60
  (--speed 60: one hour of capture in one minute; --speed 0: as fast as possible)
"""
from __future__ import annotations

import argparse
import heapq
import re
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
CAPTURED = ROOT / "Test Setup" / "lab" / "captured"
AUDIT_T = re.compile(rb"msg=audit\((\d+\.\d+):")


def _lines(path: Path):
    """(record time, line) for each line; a line without a time keeps the previous one's."""
    t = 0.0
    with open(path, "rb") as f:
        for line in f:
            m = AUDIT_T.search(line)
            if m:
                t = float(m.group(1))
            yield t, line if line.endswith(b"\n") else line + b"\n"


def replay(source: Path, target: Path, speed: float, hosts: list[str] | None = None, say=print) -> int:
    logs = {p.parent.name: p for p in sorted(source.glob("*/audit.log")) if not hosts or p.parent.name in hosts}
    if not logs:
        raise SystemExit(f"no <host>/audit.log in {source}")
    if target.exists():
        raise SystemExit(f"{target} exists: replay into a new run name")
    out = {}
    for h in logs:
        (target / h).mkdir(parents=True, exist_ok=True)
        out[h] = open(target / h / "audit.log", "ab")
    streams = [((t, h, i), line) for h, p in logs.items() for i, (t, line) in enumerate(_lines(p))]
    merged = heapq.merge(*[[x for x in streams if x[0][1] == h] for h in logs], key=lambda x: x[0])
    start_rec = start_wall = None
    n = 0
    try:
        for (t, h, _), line in merged:
            if speed > 0 and t:
                if start_rec is None:
                    start_rec, start_wall = t, time.time()
                wait = start_wall + (t - start_rec) / speed - time.time()
                if wait > 0:
                    for f in out.values():
                        f.flush()
                    time.sleep(wait)
            out[h].write(line)
            n += 1
    finally:
        for f in out.values():
            f.close()
    say(f"replayed {n} lines of {len(logs)} host(s) into {target}")
    return n


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("source", type=Path, help="a captured run folder with <host>/audit.log")
    ap.add_argument("--as", dest="name", required=True, help="the run name to stream into (captured/<name>)")
    ap.add_argument("--speed", type=float, default=60.0, help="times the original pace (0 = as fast as possible)")
    ap.add_argument("--hosts", nargs="*", default=None)
    a = ap.parse_args()
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", a.name):
        sys.exit("a run name is letters, digits, dot, dash or underscore")
    replay(a.source, CAPTURED / a.name, a.speed, a.hosts)


if __name__ == "__main__":
    main()
