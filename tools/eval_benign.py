"""Score ARGUS on a benign-only capture (a burn-in): every window is benign by construction,
so every flagged window is a false alarm.

The arms are tools/eval_lab.py's: ARGUS's hand-written rules alone, and with the installed
learned library. For each flagged window it reports the rule, the events behind it, and the
persona's benign look-alike actions in that window (from each host's benign-activity.log in
the capture folder), so a false alarm can be traced to what caused it. It also reports the
audit daemon's stop/start gaps from the raw audit logs: sensor maintenance that ARGUS should
eventually report as a blind spot (LAB_TEST_SUITE.md S11).

The capture must contain no attack: the tool refuses a window with CALDERA agent activity
(its agent's process or a connection to CALDERA's port). Labels are not read.

Usage (from the ARGUS root):
  .venv/bin/python tools/eval_benign.py --operation burnin \
      --capture "Test Setup/lab/captured/burnin" --out eval_runs/<date>-burnin
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "source code"))
sys.path.insert(0, str(ROOT / "tools"))

import lab_common as E                                           # noqa: E402
from eval_lab import LIBRARY, arms                               # noqa: E402

AGENT_IMAGES = {"splunkd", "sandcat", "sandcat.go"}
CALDERA_PORT = 8888
RE_ACT = re.compile(r"^(\S+Z) benign ROLE=\S+ (\S+?)=(\S+)")
RE_DAEMON = re.compile(r"^type=DAEMON_(START|END|ABORT) msg=audit\((\d+)\.\d+:\d+\)")


def _epoch(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def _events(w: Path) -> dict[str, dict]:
    return {e["event_id"]: e for e in map(json.loads, (w / "events.jsonl").read_text().splitlines())}


def _attack_free(w: Path, events: dict) -> bool:
    for e in events.values():
        f = e["facts"]
        if (f.get("image") or "").lower() in AGENT_IMAGES or "sandcat" in (f.get("command_line") or ""):
            return False
        if e["event_type"] == "network_connection" and f.get("dst_port") == CALDERA_PORT:
            return False
    return True


def _show(e: dict) -> str:
    f = e["facts"]
    what = f.get("command_line") or f.get("file_path") or f"{f.get('dst_ip')}:{f.get('dst_port')}"
    return f"{e['time'][11:19]} {f.get('user')} {what}"[:160]


def activity(capture: Path | None, wins: list[Path]) -> dict[str, Counter]:
    """Window -> the persona's benign actions in it (kind=value), from benign-activity.log."""
    out: dict[str, Counter] = defaultdict(Counter)
    if not capture:
        return out
    span = {}
    for w in wins:
        m = E.meta(w)
        cw = m["capture"]["window"]
        span[w.name] = (m["host"], _epoch(cw["start"]), _epoch(cw["end"]))
    for log in capture.glob("*/benign-activity.log"):
        host = log.parent.name
        for line in log.read_text(errors="ignore").splitlines():
            m = RE_ACT.match(line)
            if not m:
                continue
            t = _epoch(m.group(1))
            for name, (h, a, b) in span.items():
                if h == host and a <= t < b:
                    out[name][f"{m.group(2)}={m.group(3)}"] += 1
    return out


def daemon_gaps(capture: Path | None) -> dict[str, list[dict]]:
    """Per host, the audit daemon's stops and the following start, from the raw audit log."""
    out: dict[str, list[dict]] = {}
    if not capture:
        return out
    for log in capture.glob("*/audit.log"):
        gaps, stopped = [], None
        for line in log.read_text(errors="ignore").split("\n"):
            m = RE_DAEMON.match(line)
            if not m:
                continue
            kind, t = m.group(1), int(m.group(2))
            if kind in ("END", "ABORT"):
                stopped = t
            elif stopped is not None:
                gaps.append({"stopped": datetime.fromtimestamp(stopped, timezone.utc).isoformat()[:19],
                             "seconds": t - stopped})
                stopped = None
        out[log.parent.name] = gaps
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--operation", required=True, help="the capture's name in cases_lab (meta campaign)")
    ap.add_argument("--capture", type=Path, default=None, help="the capture folder, for activity logs and daemon gaps")
    ap.add_argument("--library", type=Path, default=LIBRARY)
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    wins = E.windows([args.operation])
    if not wins:
        sys.exit(f"no windows of {args.operation!r} in {E.LAB}")
    ev = {w.name: _events(w) for w in wins}
    dirty = [w.name for w in wins if not _attack_free(w, ev[w.name])]
    if dirty:
        sys.exit(f"not a benign-only capture: CALDERA agent activity in {dirty[:5]}")
    acts = activity(args.capture, wins)
    hosts = sorted({E.host(w) for w in wins})
    fz = E.freeze_status()
    print(f"ARGUS freeze {fz['manifest']} matches={fz['matches']} · {len(wins)} benign windows on {len(hosts)} hosts")
    out = {"freeze": fz, "operation": args.operation, "windows": len(wins),
           "per_host": dict(Counter(E.host(w) for w in wins)),
           "daemon_gaps": daemon_gaps(args.capture), "arms": {}}
    for arm, cfg in arms(args.library).items():
        rows = []
        for w in wins:
            r = E.score_window(w, cfg)
            gate = E.meta(w).get("capture_gate", "pass")
            alerts = {k: {"score": a["score"], "weighted": a["weighted"],
                          "evidence": [_show(ev[w.name][i]) for i in sorted(a["events"])[:4] if i in ev[w.name]],
                          "events": len(a["events"])}
                      for k, a in r["alerts"].items()}
            rows.append({"window": w.name, "host": E.host(w), "gate": gate, "disposition": r["disposition"],
                         "flagged": r["disposition"] in E.FLAGGED, "alerts": alerts, "context": r["context"],
                         "blind_spots": r["blind_spots"], "episodes": [e["root_image"] for e in r["episodes"]],
                         "lookalikes": dict(acts.get(w.name, {}))})

        def summ(rs):
            n, f = len(rs), sum(r["flagged"] for r in rs)
            return {"windows": n, "flagged": f, "per_20_host_windows": round(20 * f / n, 2) if n else None,
                    "undecidable": sum(r["disposition"] == "undecidable" for r in rs),
                    "with_blind_spot": sum(bool(r["blind_spots"]) for r in rs)}
        m = {"all": summ(rows), "gate_pass": summ([r for r in rows if r["gate"] == "pass"]),
             "by_host": {h: summ([r for r in rows if r["host"] == h]) for h in hosts},
             "alerting_rules": dict(Counter(k for r in rows for k in r["alerts"]).most_common()),
             "context_primitives": dict(Counter(k for r in rows for k in r["context"]).most_common())}
        out["arms"][arm] = {"metrics": m, "windows": rows}
        print(f"\n[{arm}] {json.dumps(m['all'])}\n  gate-pass {json.dumps(m['gate_pass'])}")
        print(f"  by host {json.dumps(m['by_host'])}")
        print(f"  alerting rules {m['alerting_rules']}\n  context only {m['context_primitives']}")
        for r in rows:
            if r["flagged"] or r["disposition"] == "undecidable":
                print(f"  {r['window']:<22} -> {r['disposition']:<11} {list(r['alerts'])}"
                      + ("" if r["gate"] == "pass" else f"  [gate {r['gate']}]"))
                for k, a in r["alerts"].items():
                    for x in a["evidence"][:2]:
                        print(f"      {k[:40]:<40} {x}")
                if r["lookalikes"]:
                    print(f"      look-alikes in window: {r['lookalikes']}")
    print(f"\naudit daemon stops: {json.dumps(out['daemon_gaps'])}")
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "summary.json").write_text(json.dumps(out, indent=1, default=sorted))
        print(f"wrote {args.out}/summary.json")


if __name__ == "__main__":
    main()
