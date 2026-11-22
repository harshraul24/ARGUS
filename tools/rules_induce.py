"""S3 on Linux, for the thesis evaluation — learn rules from the lab's DESIGN operations, then
grade them on the design labels. Analysts use the workbench instead (Rule library → Learn
rules); both run the same pipeline, argus.rules.learn.

Design operations only (lab_split.json: the first three in capture order). Test operations
are never loaded here: not for episodes, not for history, not for grading.

What this adds to argus.rules.learn:
  - the F8 analyst path, simulated on design data from the design labels: an analyst
    reviews every alert of a shadow rule (approval on complete review,
    argus.rules.feedback); `--no-approval` turns it off. In the workbench a real analyst
    approves or retires rules instead
  - grading: ONLY HERE are labels read, and only the design operations' labels. Design
    data, not a result: the test operations are scored once, after the final freeze
  - <out>/library.json, summary.json and report.md; `--install` copies the library to
    eval_runs/lab_library.json, which eval_lab.py and the workbench load

Every model call goes through argus.llm.client (redaction gate + response cache), so a
re-run replays from the cache with no key and no spend.

Usage (from the ARGUS root):
  .venv/bin/python tools/rules_induce.py --episodes-only          # no model calls
  .venv/bin/python tools/rules_induce.py --install                # prompts for the key
"""
from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "source code"))
sys.path.insert(0, str(ROOT / "tools"))

import lab_common as E                                             # noqa: E402
from argus.llm.cache import ResponseCache                          # noqa: E402
from argus.llm.client import LLMClient                             # noqa: E402
from argus.rules import learn as L                                 # noqa: E402
from argus.rules.library import RuleLibrary                        # noqa: E402

SIGMA = ROOT / "intel" / "snapshots" / "lab" / "argus_sigma_rules.json"
INSTALLED = ROOT / "eval_runs" / "lab_library.json"
DEFAULT_MODEL = "gpt-oss:120b-cloud"


def _key() -> str | None:
    """The key for this run, typed at a hidden prompt (or OLLAMA_API_KEY if set)."""
    if os.environ.get("OLLAMA_API_KEY") or not sys.stdin.isatty():
        return None
    k = getpass.getpass("  LLM API key (OLLAMA_API_KEY; empty = replay from cache only): ")
    # a terminal's bracketed-paste markers and stray whitespace are not part of the key
    k = k.replace("\x1b[200~", "").replace("\x1b[201~", "").strip()
    print(f"  key received ({len(k)} characters)" if k else
          "  no key entered: cached calls replay, uncached calls will be refused (401)", flush=True)
    return k or None


def sigma_rules() -> list[dict]:
    return json.loads(SIGMA.read_text())["rules"] if SIGMA.exists() else []


def windows() -> tuple[list[L.Window], dict]:
    sp = E.split()
    wins = E.windows(sp["design"])
    assert not any(E.operation(w) in sp["test"] for w in wins)
    return [L.Window(w.name, w, E.host(w), E.operation(w)) for w in wins], sp


def simulated_approval(lib: RuleLibrary, fired: dict[str, dict[str, set]]) -> list:
    """F8 on design data: every alert window of a shadow rule is reviewed, the verdict being
    whether the rule's events there are labelled malicious."""
    from argus.rules import feedback as F
    store, totals = F.FeedbackStore(), {}
    for e in lib.by_status("shadow"):
        hits = fired.get(e.uid, {})
        totals[e.uid] = len(hits)
        for n, ev in sorted(hits.items()):
            m = set(E.labels(E.LAB / n)["malicious_event_ids"])
            store.add(F.Verdict(e.uid, n, "malicious" if ev & m else "benign", events=len(ev),
                                note="simulated analyst (design labels)"))
    return F.apply(lib, store, totals=totals)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--provider", default="ollama")
    ap.add_argument("--model", default=os.environ.get("ARGUS_RULE_MODEL", DEFAULT_MODEL))
    ap.add_argument("--workers", type=int, default=4)
    ap.add_argument("--max-repairs", type=int, default=2)
    ap.add_argument("--max-rate", type=float, default=0.25, help="C4 limit, also the novelty limit")
    ap.add_argument("--episodes-only", action="store_true", help="find and render episodes; no model")
    ap.add_argument("--memory-from", default=None,
                    help="a library.json whose outcomes become rule memory in every prompt")
    ap.add_argument("--cache", default=str(ROOT / ".argus_cache" / "lab_induce"))
    ap.add_argument("--out", default=str(ROOT / "eval_runs" / f"{time.strftime('%Y-%m-%d')}-lab-induce"))
    ap.add_argument("--install", action="store_true", help=f"copy the library to {INSTALLED.relative_to(ROOT)}")
    ap.add_argument("--no-approval", action="store_true",
                    help="no simulated analyst approval (C5 from deciding hand-written and Sigma rules only)")
    args = ap.parse_args()
    t0 = time.time()
    out = Path(args.out)
    wins, sp = windows()
    if not wins:
        sys.exit(f"no windows of the design operations {sp['design']} in {E.LAB}")

    if args.episodes_only:
        _, by_host, jobs = L.episodes(wins, args.max_rate)
        print(f"{len(wins)} windows of design operations {sp['design']} on {len(by_host)} hosts; "
              f"{len(jobs)} episodes; prompt text {sum(len(j['text']) for j in jobs):,} chars")
        for j in jobs:
            d = j["ep"].to_dict()
            print(f"  {d['eid']:<40} {d['root_image']:<20} novel {d['novel_launches']:>3} "
                  f"procs {d['processes']:>4} claims {d['claims']:>5} text {len(j['text']):>6}")
        return

    mem = ""
    if args.memory_from:
        from argus.rules.feedback import memory as rule_memory
        mem = rule_memory(RuleLibrary.load(args.memory_from))
    key = _key() if args.provider == "ollama" else None
    base = os.environ.get("OLLAMA_BASE_URL", "https://ollama.com") if args.provider == "ollama" else None
    cache = ResponseCache(args.cache)

    def progress(stage, done, total):
        print(f"  {stage:<9} {done}/{total}  ({time.time() - t0:.0f}s)", flush=True)

    try:
        res = L.learn(wins, lambda: LLMClient(args.provider, args.model, cache=cache, api_key=key, base_url=base),
                      args.model, sigma=sigma_rules(), memory=mem, max_rate=args.max_rate,
                      max_repairs=args.max_repairs, workers=args.workers,
                      approve=None if args.no_approval else simulated_approval, progress=progress)
    except L.KeyRefused as exc:
        print(f"\nABORTED: no model call succeeded ({exc}).\nThe endpoint refused the API key (401/403): "
              "check it is active at https://ollama.com/settings/keys. Nothing was written.")
        sys.exit(2)
    finally:
        key = None
    lib, names, fired = res.library, res.windows, res.fired
    out.mkdir(parents=True, exist_ok=True)
    if mem:
        (out / "memory.txt").write_text(mem)
    lib.save(out / "library.json")
    if args.install:
        shutil.copyfile(out / "library.json", INSTALLED)

    # ---- grading: design labels, read only from here on
    lab = {n: E.labels(E.LAB / n) for n in names}

    def grade(ids: list[str], src: dict[str, dict[str, set]]) -> dict:
        a = b = af = bf = sel = mal = steps = det = 0
        for n in names:
            Lb = lab[n]
            ev = set().union(*[src[i].get(n, set()) for i in ids]) if ids else set()
            m = set(Lb["malicious_event_ids"])
            if Lb["category"] == "attack":
                a, af = a + 1, af + bool(ev)
            else:
                b, bf = b + 1, bf + bool(ev)
            sel += len(ev)
            mal += len(ev & m)
            for st in Lb.get("abilities", []):
                steps += 1
                det += bool(ev & set(st.get("event_ids", [])))
        return {"rules": len(ids), "attack_windows": f"{af}/{a}", "benign_windows": f"{bf}/{b}",
                "event_precision": round(mal / sel, 4) if sel else None,
                "steps_detected": f"{det}/{steps}", "steps": [det, steps]}

    def rule_grade(u) -> dict:
        g = grade([u], fired)
        g["good"] = g["attack_windows"][0] != "0" and (g["event_precision"] or 0) >= 0.5
        return g

    chk = lambda u, name: bool((lib.entries[u].checks.get(name) or {}).get("passed"))
    survivors = list(fired)
    sets = {
        "C1–C3 survivors (after repair)": survivors,
        "C1–C4 (shadow + active)": [u for u in survivors if lib.entries[u].status in ("shadow", "active", "retired")],
        "C1–C5 active": [e.uid for e in lib.by_status("active")],
        "C1–C5 if written rules could confirm": [u for u in survivors if chk(u, "C4_quiet") and (
            chk(u, "C5_confirmed") or (lib.entries[u].checks.get("C5_confirmed") or {}).get("llm_agreement"))],
    }
    set_table = {name: grade(ids, fired) for name, ids in sets.items()}
    set_table["deciding hand-written rules (C5 source)"] = grade(list(res.hand_hits), res.hand_hits)
    set_table["Sigma >= medium, quiet (C5 source)"] = grade(sorted(res.quiet_sigma), res.sigma_hits)
    both = {**fired, **{f"hand:{t}": v for t, v in res.hand_hits.items()}}
    set_table["hand-written + C1–C5 active"] = grade(
        [f"hand:{t}" for t in res.hand_hits] + [e.uid for e in lib.by_status("active")], both)

    rows = []
    for e in sorted(lib.entries.values(), key=lambda e: (STATUS_ORDER[e.status], e.uid)):
        rows.append({"uid": e.uid, "status": e.status, "technique": e.rule.get("technique"),
                     "name": e.rule.get("name"), "origin": e.origin, "reason": e.history[-1]["reason"],
                     "checks": e.checks, "grade": rule_grade(e.uid) if e.uid in fired else None,
                     "rule": e.rule})
    first_fail = Counter(e.history[-1]["reason"].split(":")[0] for e in lib.entries.values()
                         if e.status == "rejected")
    causes = Counter()
    for e in lib.entries.values():
        causes.update(e.checks.get("C2_own_evidence", {}).get("causes", {}))
    repairs = Counter(a.round for ind in res.inductions.values() for a in ind.attempts)
    by_host = {w.host for w in wins}
    summ = {"generated": time.strftime("%Y-%m-%dT%H:%M:%S"), "freeze": E.freeze_status(),
            "provider": args.provider, "model": args.model, "max_rate": args.max_rate,
            "max_repairs": args.max_repairs, "design_operations": sp["design"], "design_windows": len(names),
            "hosts": sorted(by_host), "sigma_rules": res.sigma_rules, "sigma_quiet": len(res.quiet_sigma),
            "approval": "off" if args.no_approval else "simulated from design labels (F8)",
            "approvals": [{"uid": u, "to": to, "why": why} for u, to, why in res.approvals],
            "merged_duplicates": [{"retired": u, "kept": k} for u, k in res.merged],
            "memory_from": args.memory_from, "memory_chars": len(mem),
            "episodes": [j["ep"].to_dict() | {"text_chars": len(j["text"])} for j in res.episodes],
            "inductions": {k: {"calls": v.calls, "errors": v.errors, "reasoning": v.reasoning,
                               "attempts": len(v.attempts)} for k, v in sorted(res.inductions.items())},
            "meter": res.meter, "library": lib.counts(),
            "attempts_by_round": dict(sorted(repairs.items())),
            "first_failed_check": dict(first_fail), "c2_causes": dict(causes),
            "sets_design": set_table, "rules": rows, "seconds": round(time.time() - t0, 1)}
    (out / "summary.json").write_text(json.dumps(summ, indent=1, default=sorted))
    (out / "report.md").write_text(report(summ))
    print(json.dumps({k: summ[k] for k in ("library", "first_failed_check", "meter")}, indent=1))
    for name, t in set_table.items():
        print(f"  {name:<44} {t}")
    print(f"wrote {out}/report.md ({summ['seconds']}s)" + (f"; installed {INSTALLED}" if args.install else ""))


STATUS_ORDER = {"active": 0, "shadow": 1, "retired": 2, "candidate": 3, "rejected": 4}


def _show_rule(r: dict) -> str:
    inds = []
    for i in r.get("indicators") or []:
        inds.append(json.dumps(i.get("select"), ensure_ascii=False)[:220])
    return " · ".join(inds)


def report(s: dict) -> str:
    fz = s["freeze"]
    m = s["meter"]
    L = ["# S3 on Linux — rules written by an LLM from novel lab episodes, judged without labels\n",
         f"Generated {s['generated']} by `tools/rules_induce.py`. ARGUS freeze `{fz['manifest']}`: "
         f"**{'matches' if fz['matches'] else 'DOES NOT MATCH: ' + ', '.join(fz['changed'][:4])}**.\n",
         f"Model `{s['model']}` ({s['provider']}), temperature 0, seed 7. Design operations only "
         f"({', '.join(s['design_operations'])}; {s['design_windows']} windows on {len(s['hosts'])} hosts). "
         f"Test operations were not loaded. Novelty and C4 limit {s['max_rate']:.0%} of the host's "
         f"other windows; at most {s['max_repairs']} repair rounds. C5 (checks.py, A3) confirms only on "
         f"agreement from a source that may decide on its own and is itself quiet by C4's bar on that "
         f"host: a deciding hand-written rule, one of {s['sigma_quiet']} such Sigma rules (of "
         f"{s['sigma_rules']} rated medium or above), or analyst approval ({s['approval']}; "
         f"{sum(a['to'] == 'active' for a in s['approvals'])} promoted, "
         f"{sum(a['to'] == 'retired' for a in s['approvals'])} retired).\n",
         f"Model calls: {m['calls']} ({m['live_calls']} live, {m['cache_hits']} from cache), "
         f"{m['model_seconds']} s of model time, ~{m['approx_tokens_in']:,} tokens in, "
         f"~{m['approx_tokens_out']:,} out.\n",
         f"**Library:** {s['library']}. Attempts by round: {s['attempts_by_round']}. "
         f"Rejections by first failed check: {s['first_failed_check']}. C2 causes: {s['c2_causes']}.\n",
         "## Selected sets on the design operations (labels used only here)\n",
         "Design data, not a result: the model saw these windows. The test operations are scored "
         "once, after the final freeze (LAB_EVAL_PLAN.md §6).\n",
         "| set | rules | attack windows | benign windows | event precision | attack steps |",
         "|---|---|---|---|---|---|"]
    for name, t in s["sets_design"].items():
        L.append(f"| {name} | {t['rules']} | {t['attack_windows']} | {t['benign_windows']} | "
                 f"{t['event_precision']} | {t['steps_detected']} |")
    L += ["", "## Episodes the model was shown\n", "| episode | root | novel launches | processes | prompt chars | rules written | calls |",
          "|---|---|---|---|---|---|---|"]
    for ep in s["episodes"]:
        ind = s["inductions"].get(ep["eid"], {})
        L.append(f"| `{ep['eid'].split('#')[0]}` | {ep['root_image']} | {ep['novel_launches']} | "
                 f"{ep['processes']} | {ep['text_chars']:,} | {ind.get('attempts', 0)} | {ind.get('calls', 0)} |")
    L += ["", "## Every rule\n", "| rule | status | reason | grade: attack · benign · precision | select |",
          "|---|---|---|---|---|"]
    for r in s["rules"]:
        g = r["grade"] or {}
        L.append(f"| `{r['uid']}` | {r['status']} | {r['reason'][:140].replace('|', '/')} | "
                 f"{g.get('attack_windows', '')} · {g.get('benign_windows', '')} · {g.get('event_precision', '')} | "
                 f"`{_show_rule(r['rule']).replace('|', '/')[:260]}` |")
    return "\n".join(L) + "\n"


if __name__ == "__main__":
    main()
