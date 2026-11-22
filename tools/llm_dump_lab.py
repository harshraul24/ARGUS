"""Baseline: "dump the telemetry into an LLM and ask", on the real lab windows.

The comparison arm for ARGUS's learned rules (LAB_COMPARISON.md). The model sees what ARGUS
sees for each window: every event (program run, outbound connection, sensitive-file access)
with the process that did it and that process's parent, one line per event. Secrets are
redacted before anything leaves the machine. Nothing else is filtered, fenced or checked:
that is the approach being measured. The model is asked for a disposition and the events it
believes are attacker activity, and is graded exactly as tools/eval_lab.py grades ARGUS:
- windows flagged (malicious or suspicious), attack and benign;
- attack steps detected (a step counts when any event it cites belongs to the step);
- event precision of the events it cites in flagged windows;
- cited event ids that do not exist in the window (fabricated).

Cost is measured too: model calls, prompt size and latency. Every call repeats for every new
window, whereas ARGUS's learned rules cost model calls once and then run without a model.
With --repeats N each window is asked N times with different seeds, to measure whether the
same input gives the same verdict.

Labels are read only to grade. Same model as rule learning (gpt-oss:120b-cloud), so the
method is the only variable. Calls are cached (.argus_cache/llm_dump): a rerun replays
without a key. The key is typed at a hidden prompt for this run only and never stored.

Usage (from the ARGUS root):
  .venv/bin/python tools/llm_dump_lab.py --operations run1 smoke --out eval_runs/<date>-llm-dump
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import re
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "source code"))
sys.path.insert(0, str(ROOT / "tools"))

import lab_common as E                                           # noqa: E402
from argus.llm.cache import ResponseCache                        # noqa: E402
from argus.llm.client import LLMClient                           # noqa: E402
from argus.normalize.redact import redact                        # noqa: E402

CACHE = ROOT / ".argus_cache" / "llm_dump"
MODEL = "gpt-oss:120b-cloud"
MAX_CHARS = 280_000          # about 70k tokens; the model's context holds 128k. Larger is reported

PROMPT = (
    "You are a senior SOC analyst. Below is the telemetry recorded on one Linux host during one "
    "30-minute window: every program started (process_create), every outbound network "
    "connection, and every access to a sensitive file, in time order. Each line is\n"
    "  event-id | time | type | user | process (p-id) <- parent (p-id) | program path | details\n"
    "Decide whether this window contains attacker activity. Respond ONLY with JSON of the form "
    '{"disposition":"malicious|suspicious|benign","mitre_technique":"Txxxx or none",'
    '"severity":0.0,"malicious_events":["e1","e2"],"reason":"one sentence"}. '
    "severity is between 0 and 1. List in malicious_events every event id you believe is "
    "attacker activity; leave it empty if the window is benign.\n\n=== TELEMETRY ===\n")


def _key() -> str | None:
    """The key for this run, typed at a hidden prompt (or OLLAMA_API_KEY if set)."""
    if os.environ.get("OLLAMA_API_KEY") or not sys.stdin.isatty():
        return None
    k = getpass.getpass("  LLM API key (OLLAMA_API_KEY; empty = replay from cache only): ")
    k = k.replace("\x1b[200~", "").replace("\x1b[201~", "").strip()
    print(f"  key received ({len(k)} characters)" if k else
          "  no key entered: cached calls replay, uncached calls will be refused", flush=True)
    return k or None


def _clean(v) -> str:
    text, _ = redact(str(v if v is not None else ""))
    return (text or "").replace("\n", " ").replace("|", "/")[:400]


def render(window: Path) -> tuple[str, dict[str, str], bool]:
    """The window as numbered lines, the short-id -> event-id map, and whether it was cut."""
    events = [json.loads(x) for x in (window / "events.jsonl").read_text().splitlines() if x.strip()]
    lin = json.loads((window / "lineage.json").read_text()) if (window / "lineage.json").exists() else {}
    actors, procs = lin.get("actors", {}), lin.get("processes", {})
    pid: dict[str, str] = {}

    def p(key):
        if not key:
            return "?"
        if key not in pid:
            pid[key] = f"p{len(pid) + 1}"
        return pid[key]

    lines, ids = [], {}
    for i, e in enumerate(sorted(events, key=lambda e: (e.get("ts") or 0))):
        f = e.get("facts", {})
        short = f"e{i + 1}"
        ids[short] = e["event_id"]
        me = (actors.get(e["event_id"]) or [None])[0]
        parent = (procs.get(me) or {}).get("parent") if me else None
        pimg = (procs.get(parent) or {}).get("image") or f.get("parent_image") or "?"
        t = e.get("event_type", "")
        if t == "process_create":
            detail = f.get("command_line", "")
        elif t == "network_connection":
            detail = f"-> {f.get('dst_ip')}:{f.get('dst_port')} success={f.get('success')}"
        else:
            detail = f"{f.get('file_path', '')} ({f.get('audit_key', '')})"
        lines.append(" | ".join([short, str(e.get("time", ""))[11:19], t, _clean(f.get("user")),
                                 f"{_clean(f.get('image'))} ({p(me)}) <- {_clean(pimg)} ({p(parent)})",
                                 _clean(f.get("image_path")), _clean(detail)]))
    blob = "\n".join(lines)
    return blob[:MAX_CHARS], ids, len(blob) > MAX_CHARS


def parse(text: str) -> dict:
    try:
        j = json.loads(text)
        return j if isinstance(j, dict) else {"disposition": "?", "reason": "not a JSON object"}
    except json.JSONDecodeError:
        m = re.search(r"\{.*\}", text or "", re.S)
        if m:
            try:
                return json.loads(m.group(0))
            except json.JSONDecodeError:
                pass
        return {"disposition": "?", "reason": f"unparseable model output: {(text or '')[:200]}"}


def metrics(rows: list[dict], steps: list[dict]) -> dict:
    flagged = Counter((r["category"], r["flagged"]) for r in rows)
    att = sum(1 for r in rows if r["category"] == "attack")
    ben = sum(1 for r in rows if r["category"] == "benign")
    k = sum(s["detected"] for s in steps)
    sel = sum(r["selected"] for r in rows)
    return {"attack_windows_flagged": f"{flagged[('attack', True)]}/{att}",
            "benign_windows_flagged": f"{flagged[('benign', True)]}/{ben}",
            "steps_detected": f"{k}/{len(steps)}", "step_recall_ci95": E.wilson(k, len(steps)) if steps else None,
            "event_precision": round(sum(r["malicious_selected"] for r in rows) / sel, 4) if sel else None,
            "events_cited": sel, "fabricated_ids": sum(r["fabricated"] for r in rows),
            "unparseable": sum(1 for r in rows if r["disposition"] not in ("malicious", "suspicious", "benign"))}


def run(wins: list[Path], client: LLMClient) -> tuple[list[dict], list[dict], dict]:
    rows, steps = [], []
    cost = {"calls": 0, "live_calls": 0, "cached": 0, "prompt_chars": 0, "seconds": 0.0, "truncated": []}
    for w in wins:
        lab, meta = E.labels(w), E.meta(w)
        blob, ids, cut = render(w)
        prompt = PROMPT + blob
        t0 = time.time()
        r = client.complete(prompt)
        cost["calls"] += 1
        cost["live_calls"] += not r.cached
        cost["cached"] += r.cached
        cost["prompt_chars"] += len(prompt)
        cost["seconds"] += time.time() - t0
        if cut:
            cost["truncated"].append(w.name)
        ans = parse(r.text)
        disp = str(ans.get("disposition", "?")).lower().strip()
        flagged = disp in E.FLAGGED
        cited = [str(x).strip() for x in (ans.get("malicious_events") or []) if str(x).strip()]
        fabricated = [c for c in cited if c not in ids]
        sel = {ids[c] for c in cited if c in ids} if flagged else set()
        mal = set(lab["malicious_event_ids"])
        gate = meta.get("capture_gate", "pass")
        for a in lab.get("abilities", []):
            steps.append({"window": w.name, "step": a["name"], "status": a.get("status"),
                          "bootstrap": bool(a.get("bootstrap")), "gate": gate,
                          "detected": bool(sel & set(a["event_ids"]))})
        rows.append({"window": w.name, "category": lab["category"], "gate": gate, "disposition": disp,
                     "flagged": flagged, "technique": ans.get("mitre_technique"), "severity": ans.get("severity"),
                     "selected": len(sel), "malicious_selected": len(sel & mal), "malicious": len(mal),
                     "fabricated": len(fabricated), "reason": str(ans.get("reason", ""))[:300],
                     "events": len(ids), "prompt_chars": len(prompt), "truncated": cut})
        print(f"  {w.name:<24} {lab['category']:<7} -> {disp:<11} cited {len(sel)} (mal {len(sel & mal)}/{len(mal)})"
              f"{'  CUT' if cut else ''}{'  cached' if r.cached else f'  {time.time() - t0:.0f}s'}", flush=True)
    cost["seconds"] = round(cost["seconds"], 1)
    return rows, steps, cost


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--operations", nargs="+", required=True, help="lab operations (lab_split.json names)")
    ap.add_argument("--model", default=MODEL)
    ap.add_argument("--repeats", type=int, default=1, help="ask each window N times (seeds 7, 8, ...)")
    ap.add_argument("--out", type=Path, default=None)
    args = ap.parse_args()

    key = _key()
    base = os.environ.get("OLLAMA_BASE_URL", "https://ollama.com")
    cache = ResponseCache(CACHE)
    out = {"generated": time.strftime("%Y-%m-%dT%H:%M:%S"), "model": args.model, "provider": "ollama",
           "freeze": E.freeze_status(), "method": "one call per window: events + process/parent, redacted, unfiltered",
           "operations": {}}
    for op in args.operations:
        wins = E.windows([op])
        print(f"\n[{op}] {len(wins)} windows · {args.model}", flush=True)
        reps = []
        for rep in range(args.repeats):
            client = LLMClient("ollama", args.model, cache=cache, api_key=key, base_url=base, seed=7 + rep)
            try:
                rows, steps, cost = run(wins, client)
            except Exception as exc:                       # a refused key or a dead endpoint: say so
                sys.exit(f"model call failed ({type(exc).__name__}: {str(exc)[:200]}); nothing was written")
            m = {"all": metrics(rows, steps),
                 "gate_pass": metrics([r for r in rows if r["gate"] == "pass"],
                                      [s for s in steps if s["gate"] == "pass"]),
                 "cost": cost}
            reps.append({"seed": 7 + rep, "metrics": m, "windows": rows, "steps": steps})
            print(f"  seed {7 + rep}: {json.dumps(m['all'])}\n  cost: {json.dumps(cost)}", flush=True)
        stable = None
        if len(reps) > 1:
            by = [{r["window"]: r["flagged"] for r in x["windows"]} for x in reps]
            stable = sum(1 for w in by[0] if len({b[w] for b in by}) == 1)
            stable = f"{stable}/{len(by[0])}"
            print(f"  same flagged/not-flagged verdict in every repeat: {stable} windows")
        out["operations"][op] = {"repeats": reps, "verdict_stable_windows": stable}
    key = None                                             # noqa: F841 — the key goes no further
    if args.out:
        args.out.mkdir(parents=True, exist_ok=True)
        (args.out / "summary.json").write_text(json.dumps(out, indent=1, default=sorted))
        print(f"\nwrote {args.out}/summary.json")


if __name__ == "__main__":
    main()
