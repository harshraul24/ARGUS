"""ARGUS CLI — a client of the same code the API serves.

    python -m argus.cli triage  <case_dir>
    python -m argus.cli bench   <data_dir> [--no-coverage]
"""
from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from argus.case import ground_truth, load_case
from argus.models import Disposition
from argus.reason.engine import Config, reason
from argus.assurance import confound as cg
from argus.assurance import observability as obs
from argus.llm.cache import ResponseCache
from argus.llm.client import LLMClient, TEST_DOUBLES
from argus.llm.verbalizer import polish, render

ATTACK_DISPOSITIONS = {Disposition.MALICIOUS, Disposition.SUSPICIOUS}


def triage(case_dir: Path, cfg: Config) -> dict:
    lc = load_case(case_dir)
    decision = reason(lc.case_id, lc.claims, lc.health, cfg, lc.protocol_artifacts)
    return decision.model_dump(mode="json")


def cmd_triage(args) -> None:
    cfg = Config(enable_coverage=not args.no_coverage,
                 confound=None if args.no_confound_guard else cg.load(),
                 observability=obs.load(),
                 enable_observability=not args.no_observability)
    print(json.dumps(triage(Path(args.case), cfg), indent=2))


def cmd_bench(args) -> None:
    guard = None if args.no_confound_guard else cg.load()
    cfg = Config(enable_coverage=not args.no_coverage, confound=guard,
                 observability=obs.load(),
                 enable_observability=not args.no_observability)
    root = Path(args.data)
    rows = []
    for d in sorted(root.iterdir()):
        if not (d / "meta.json").exists():
            continue
        gt = ground_truth(d)
        lc = load_case(d)
        dec = reason(lc.case_id, lc.claims, lc.health, cfg, lc.protocol_artifacts)
        top = dec.top
        predicted_attack = dec.disposition in ATTACK_DISPOSITIONS
        rows.append({
            "scenario": d.name, "gt": gt, "decision": dec,
            "predicted_attack": predicted_attack,
            "correct": predicted_attack == gt["is_attack"],
            "technique_top": (top.technique == gt["technique"]) if (top and gt.get("technique")) else None,
            "technique_found": (gt["technique"] in [h.technique for h in dec.hypotheses if h.score > 0])
                               if gt.get("technique") else None,
        })

    mode = []
    if args.no_coverage:
        mode.append("NO-COVERAGE")
    if args.no_confound_guard:
        mode.append("NO-CONFOUND-GUARD")
    if args.no_observability:
        mode.append("NO-OBSERVABILITY")
    print("=" * 112)
    print("ARGUS v3" + (f"  [ABLATION: {', '.join(mode)}]" if mode else "  [full]"))
    print("=" * 112)
    print(f"{'scenario':<34}{'truth':<8}{'claims':>7}  {'disposition':<14}{'top hypothesis':<34}{'score':>6} {'ok':>3}")
    print("-" * 112)
    for r in rows:
        d = r["decision"]
        top = d.top
        label = f"{top.technique} {top.name[:22]}" if top and top.score > 0 else "-"
        print(f"{r['scenario'][:33]:<34}"
              f"{('ATTACK' if r['gt']['is_attack'] else 'benign'):<8}"
              f"{d.claims_total:>7}  "
              f"{d.disposition.value:<14}"
              f"{label:<34}"
              f"{(top.score if top else 0):>6.2f} "
              f"{'Y' if r['correct'] else 'N':>3}")
    print("-" * 112)
    n = sum(r["correct"] for r in rows)
    atk = [r for r in rows if r["gt"]["is_attack"]]
    ben = [r for r in rows if not r["gt"]["is_attack"]]
    tech_top = [r for r in atk if r["technique_top"]]
    tech_found = [r for r in atk if r["technique_found"]]
    print(f"accuracy {n}/{len(rows)}   "
          f"attack recall {sum(r['correct'] for r in atk)}/{len(atk)}   "
          f"benign specificity {sum(r['correct'] for r in ben)}/{len(ben)}   "
          f"technique top-1 {len(tech_top)}/{len(atk)}   "
          f"technique found {len(tech_found)}/{len(atk)}")

    if args.json:
        Path(args.json).write_text(json.dumps(
            [{"scenario": r["scenario"], "gt": r["gt"], "correct": r["correct"],
              "technique_top": r["technique_top"], "technique_found": r["technique_found"],
              "decision": r["decision"].model_dump(mode="json")} for r in rows], indent=2))
        print(f"\nwrote {args.json}")


def cmd_explain(args) -> None:
    """Analyst-readable explanation. Content is template-generated from the
    decision; an LLM may only adjust phrasing, and any sentence it returns that
    does not trace back to a template sentence is dropped."""
    lc = load_case(Path(args.case))
    dec = reason(lc.case_id, lc.claims, lc.health,
                 Config(confound=cg.load(), observability=obs.load()),
                 lc.protocol_artifacts)
    ex = render(dec)
    if args.llm and args.llm != "none":
        client = LLMClient(provider=args.llm, model=args.llm_model, cache=ResponseCache())
        ex = polish(ex, client)
        if client.is_test_double:
            print("[provider is a TEST DOUBLE - no model was called]\n")
    print(ex.text)
    if ex.dropped:
        print(f"\n[{len(ex.dropped)} sentence(s) dropped: not traceable to the decision]")


def cmd_claims(args) -> None:
    """Dump every claim extracted for a case — the evidence the reasoner saw."""
    lc = load_case(Path(args.case))
    claims = lc.claims
    if args.type:
        claims = [c for c in claims if c.claim_type == args.type]
    if args.modality:
        claims = [c for c in claims if c.modality == args.modality]
    if args.grep:
        needle = args.grep.lower()
        claims = [c for c in claims
                  if needle in json.dumps(c.facts).lower()
                  or needle in c.claim_type.lower() or needle in str(c.entity).lower()]

    if args.json:
        print(json.dumps([c.model_dump(mode="json") for c in claims], indent=2))
        return

    # summary first
    by_type: dict[str, int] = {}
    by_mod: dict[str, int] = {}
    for c in lc.claims:
        by_type[c.claim_type] = by_type.get(c.claim_type, 0) + 1
        by_mod[c.modality] = by_mod.get(c.modality, 0) + 1

    print("=" * 100)
    print(f" CLAIMS — {lc.case_id}")
    print("=" * 100)
    print(f"\n  total {len(lc.claims)}   shown {len(claims)}")
    print(f"  by modality : " + "  ".join(f"{k}={v}" for k, v in sorted(by_mod.items())))
    print(f"  by type     :")
    for k, v in sorted(by_type.items(), key=lambda x: -x[1]):
        print(f"      {k:<32}{v:>6}")

    if lc.health:
        print(f"\n  sensor health:")
        for sid, h in lc.health.items():
            bits = [f"observability={h.observability():.3f}"]
            if h.loss_pct:
                bits.append(f"loss={h.loss_pct}%")
            if h.blind_to:
                bits.append(f"blind_to={h.blind_to}")
            if h.invalidated_before:
                bits.append(f"invalidated_before={h.invalidated_before}")
            print(f"      {sid:<10}{'  '.join(bits)}")

    print("\n" + "-" * 100)
    print(f"  {'claim_id':<12}{'modality':<10}{'claim_type':<28}{'ctrl':<6}{'time':<26}entity")
    print("-" * 100)
    for c in claims[: args.limit]:
        print(f"  {c.claim_id:<12}{c.modality:<10}{c.claim_type:<28}"
              f"{c.control.value:<6}{str(c.time or '-')[:25]:<26}{str(c.entity)[:22]}")
        if args.facts:
            for k, v in c.facts.items():
                if k.startswith("_"):
                    continue
                print(f"      {k:<26}{str(v)[:60]}")
    if len(claims) > args.limit:
        print(f"\n  ... {len(claims) - args.limit} more (raise --limit or use --json)")


def cmd_scan(args) -> None:
    rep = cg.scan_corpus(Path(args.data))
    cg.save(rep)
    print(json.dumps(rep.to_dict(), indent=2))
    print(f"\nwrote {cg.DEFAULT_PATH}")

    om = obs.scan_corpus(Path(args.data))
    obs.save(om)
    print("\nOBSERVABILITY MODEL  O(sensor, claim_type) over "
          f"{om.n_captures} captures:")
    for k, v in sorted(om.rates.items(), key=lambda x: x[1]):
        flag = "  <- weak, absence means little" if v <= 0.5 else ""
        print(f"  {k:<44}{v:>6.0%}{flag}")
    print(f"\nwrote {obs.DEFAULT_PATH}")


# ------------------------------------------------------------- presentation

_DISPO_COLOR = {"malicious": "31;1", "suspicious": "33;1",
                "benign": "32;1", "undecidable": "37;1"}
_DEFAULT_OLLAMA_MODEL = "gpt-oss:120b-cloud"
_CASE_ROOTS = ["cases_lab", "cases_linux", "cases", "."]


def _tty() -> bool:
    return sys.stdout.isatty()


def _c(s: str, code: str) -> str:
    return f"\033[{code}m{s}\033[0m" if _tty() else s


def _bar(x: float, width: int = 18) -> str:
    x = max(0.0, min(1.0, float(x or 0.0)))
    n = int(round(x * width))
    return "█" * n + "░" * (width - n)


def _safe_meta(case_dir: Path) -> dict:
    p = Path(case_dir) / "meta.json"
    try:
        return json.loads(p.read_text()) if p.exists() else {}
    except Exception:
        return {}


def _discover_cases() -> list[Path]:
    """Find every directory holding a meta.json under the common case roots."""
    found: dict[str, Path] = {}
    for r in _CASE_ROOTS:
        rp = Path(r)
        if not rp.exists():
            continue
        for pattern in ("*/meta.json", "*/*/meta.json"):
            for meta in rp.glob(pattern):
                found[str(meta.parent.resolve())] = meta.parent
    return sorted(found.values(), key=lambda p: str(p).lower())


def _ensure_ollama_env(provider: str | None) -> None:
    """Ollama Cloud needs a base URL + key; default to the cloud endpoint and
    prompt for the key once if it is not already in the environment."""
    if provider != "ollama":
        return
    os.environ.setdefault("OLLAMA_BASE_URL", "https://ollama.com")
    if not os.environ.get("OLLAMA_API_KEY"):
        import getpass
        try:
            k = getpass.getpass("  Ollama API key (Enter to use local daemon): ").strip()
        except Exception:
            k = ""
        if k:
            os.environ["OLLAMA_API_KEY"] = k


def _pretty_report(case_dir: Path, cfg: Config,
                   llm: str | None = None, llm_model: str | None = None) -> None:
    """Human-readable triage: verdict, hypotheses, coverage, ground-truth check,
    and the analyst summary (LLM-polished when a provider is given)."""
    lc = load_case(case_dir)
    client = None
    if llm and llm != "none":
        try:
            client = LLMClient(provider=llm, model=llm_model, cache=ResponseCache())
        except Exception as exc:
            print(_c(f"  [LLM unavailable: {type(exc).__name__}: {exc}]", "31"))
            client = None

    dec = reason(lc.case_id, lc.claims, lc.health, cfg, lc.protocol_artifacts)
    out = dec.model_dump(mode="json")
    ex = render(dec)
    if client is not None:
        try:
            ex = polish(ex, client)
        except Exception as exc:
            print(_c(f"  [LLM polish failed: {type(exc).__name__} — showing template]", "31"))

    W = 74
    dispo = str(out.get("disposition", "?"))
    sev = out.get("severity", 0.0) or 0.0
    print("\n" + "═" * W)
    print(f" ARGUS triage — {out.get('case_id') or Path(case_dir).name}")
    print("═" * W)
    print(f"\n  disposition : {_c(dispo.upper(), _DISPO_COLOR.get(dispo, '37'))}")
    print(f"  severity    : {_bar(sev)}  {sev:.3f}")
    print(f"  claims      : {out.get('claims_considered')}/{out.get('claims_total')}")

    gt = _safe_meta(case_dir).get("ground_truth") or {}
    if gt:
        techs = gt.get("techniques") or ([gt["primary_technique"]] if gt.get("primary_technique") else [])
        landed = any(a.get("result") == "success" for a in gt.get("actions", []))
        fired = {h["technique"] for h in out.get("hypotheses", []) if h.get("score", 0) > 0}
        match = _c("✓ match", "32") if (set(techs) & fired) else _c("✗ miss", "31")
        print(f"  ground truth: {', '.join(techs)}   objective reached: "
              f"{'yes' if landed else 'no'}   {match}")

    hyps = out.get("hypotheses", [])
    if hyps:
        print("\n  hypotheses")
        for h in hyps:
            sc = h.get("score", 0)
            print(f"    {h.get('technique', ''):<8} {_bar(sc, 16)} {sc:>4.2f}  {h.get('name', '')}")
            for r in h.get("rationale", [])[:2]:
                print(f"        · {r}")
            for g in (h.get("coverage_gaps") or []):
                print("        " + _c(f"! coverage gap: {g}", "33"))

    for label, key in (("blind spots (could not see)", "blind_spots"),
                       ("next actions", "next_actions")):
        items = out.get(key) or []
        if items:
            print("\n  " + _c(label, "33;1") if key == "blind_spots" else "\n  " + label)
            for it in items:
                print(f"    - {it}")

    tag = f"[{llm}/{client.model}]" if client is not None else "[template — no LLM]"
    print(f"\n  analyst summary {_c(tag, '90')}")
    for line in ex.text.splitlines():
        print(f"    {line}")
    if getattr(ex, "dropped", None):
        print("    " + _c(f"[{len(ex.dropped)} ungrounded sentence(s) dropped by the grounding gate]", "90"))
    print("═" * W + "\n")


def _report_cfg(args) -> Config:
    return Config(enable_coverage=not getattr(args, "no_coverage", False),
                  confound=None if getattr(args, "no_confound_guard", False) else cg.load(),
                  observability=obs.load(),
                  enable_observability=not getattr(args, "no_observability", False))


def cmd_report(args) -> None:
    llm = None if args.no_llm else (args.llm or "ollama")
    model = args.llm_model or (_DEFAULT_OLLAMA_MODEL if llm == "ollama" else None)
    _ensure_ollama_env(llm)
    _pretty_report(Path(args.case), _report_cfg(args), llm=llm, llm_model=model)


def cmd_interactive(args) -> None:
    """Guided flow: pick a case, pick an LLM, see a presentable report."""
    cases = _discover_cases()
    if not cases:
        print("No cases found (looked in: " + ", ".join(_CASE_ROOTS) + ")")
        return
    print("\n" + _c("ARGUS — select a case", "1"))
    for i, c in enumerate(cases, 1):
        meta = _safe_meta(c)
        tag = meta.get("category", "")
        title = (meta.get("title") or "")[:40]
        print(f"  {i:>2}. {c.name:<26} {tag:<8} {title}")
    try:
        sel = input(f"\ncase number [1-{len(cases)}] (default 1): ").strip() or "1"
        case = cases[int(sel) - 1]
    except (ValueError, IndexError):
        print("invalid selection")
        return

    prov = input("LLM provider [ollama] (Enter to accept, 'none' to skip): ").strip() or "ollama"
    model = None
    if prov == "ollama":
        model = input(f"  model [{_DEFAULT_OLLAMA_MODEL}]: ").strip() or _DEFAULT_OLLAMA_MODEL
    _ensure_ollama_env(prov)
    cfg = Config(confound=cg.load(), observability=obs.load())
    _pretty_report(case, cfg, llm=None if prov == "none" else prov, llm_model=model)


def cmd_ui(args) -> None:
    """Serve the analyst triage workbench (argus.api.workbench) on localhost."""
    import os
    import webbrowser

    import uvicorn
    if args.library:
        os.environ["ARGUS_LIBRARY"] = args.library
    if args.roots:
        os.environ["ARGUS_CASE_ROOTS"] = args.roots
    url = f"http://127.0.0.1:{args.port}/ui/"
    print(f"ARGUS workbench on {url}  (Ctrl-C to stop)")
    if not args.no_browser:
        webbrowser.open(url)
    uvicorn.run("argus.api.app:app", host="127.0.0.1", port=args.port, log_level="warning")


def main() -> None:
    p = argparse.ArgumentParser(prog="argus")
    sub = p.add_subparsers(dest="cmd")

    t = sub.add_parser("triage", help="triage one case directory")
    t.add_argument("case")
    t.add_argument("--no-coverage", action="store_true")
    t.add_argument("--no-confound-guard", action="store_true")
    t.add_argument("--no-observability", action="store_true")
    t.set_defaults(func=cmd_triage)

    e = sub.add_parser("explain", help="analyst-readable explanation of a case")
    e.add_argument("case")
    e.add_argument("--llm", default=None)
    e.add_argument("--llm-model", default=None)
    e.set_defaults(func=cmd_explain)

    b = sub.add_parser("bench", help="run every scenario under a data directory")
    b.add_argument("data")
    b.add_argument("--no-coverage", action="store_true")
    b.add_argument("--no-confound-guard", action="store_true")
    b.add_argument("--no-observability", action="store_true")
    b.add_argument("--json", default=None)
    b.set_defaults(func=cmd_bench)

    c = sub.add_parser("claims", help="list every claim extracted for a case")
    c.add_argument("case")
    c.add_argument("--type", default=None, help="filter by claim_type")
    c.add_argument("--modality", default=None, help="identity | endpoint | network | cti")
    c.add_argument("--grep", default=None, help="substring match on facts/type/entity")
    c.add_argument("--facts", action="store_true", help="show each claim's facts")
    c.add_argument("--limit", type=int, default=60)
    c.add_argument("--json", action="store_true")
    c.set_defaults(func=cmd_claims)

    sc = sub.add_parser("scan", help="corpus scan for capture confounds")
    sc.add_argument("data")
    sc.set_defaults(func=cmd_scan)

    # presentable, LLM-by-default report for one case
    r = sub.add_parser("report", help="presentable triage report (LLM on by default)")
    r.add_argument("case")
    r.add_argument("--llm", default=None,
                   help="provider (default: ollama). Use --no-llm to run engine-only.")
    r.add_argument("--llm-model", default=None)
    r.add_argument("--no-llm", action="store_true", help="engine only, no model")
    r.add_argument("--no-coverage", action="store_true")
    r.add_argument("--no-confound-guard", action="store_true")
    r.add_argument("--no-observability", action="store_true")
    r.set_defaults(func=cmd_report)

    # interactive: pick a case, pick an LLM, see the report
    it = sub.add_parser("interactive", aliases=["i"],
                        help="guided: choose a case + LLM, then report")
    it.set_defaults(func=cmd_interactive)

    ui = sub.add_parser("ui", help="analyst triage workbench in the browser (localhost only)")
    ui.add_argument("--port", type=int, default=8765)
    ui.add_argument("--library", default=None,
                    help="rule library JSON (default: eval_runs/lab_library.json if present; 'none' for ARGUS alone)")
    ui.add_argument("--roots", default=None, help="corpora to list, colon-separated (default: cases_*)")
    ui.add_argument("--no-browser", action="store_true")
    ui.set_defaults(func=cmd_ui)

    args = p.parse_args()
    if not getattr(args, "func", None):
        # no subcommand -> drop into the guided flow
        cmd_interactive(args)
        return
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
