"""Triage workbench — the analyst-facing side of the ARGUS API (served at /ui).

A post-hoc SOC triage loop over Linux case directories on disk (lab windows, captures):

    queue      every case in a corpus, triaged in the background, ranked by priority
    case view  the verdict and why; the evidence behind each hypothesis with its defeaters;
               the process tree of the episode; an evidence timeline; what each sensor
               could and could not see; shadow rules (measured, never deciding)
    feedback   the analyst's outcome for the case and verdicts on individual rules, written
               to disk in the form the rule-library feedback loop reads (argus.rules.feedback)
    library    the LLM-written rule library with each rule's checks and history; the analyst
               approves or retires rules, and starts a learning run (argus.rules.learn) from
               the page: the API key is typed in for that run, held in memory while it runs,
               and never stored, logged or returned
    gaps       which sensor blind spots cost decisions, across the triaged cases
    import     a lab capture (one folder, `<host>/audit.log` per victim) becomes cases: picked
               from the lab's capture folder or copied in from the page, converted by
               argus.collectors.lab_capture, and, with a CALDERA report, added to lab_split.json
               in capture order (its role, design or test, follows from that order alone)

Ground truth is never part of the analyst view. A separate endpoint returns a corpus's
labels for an explicit evaluation overlay (thesis demonstrations), off by default.

Everything shown that came from telemetry (command lines, paths, user names) is text
an attacker may have written; the front end escapes all of it.
"""
from __future__ import annotations

import asyncio
import json
import os
import re
import shutil
import time
from collections import Counter
from pathlib import Path
from typing import Literal

from fastapi import APIRouter, BackgroundTasks, HTTPException, Request
from pydantic import BaseModel, Field

from argus.api.store import Case, CaseStore
from argus.assurance import confound as cg
from argus.assurance import observability as obsmod
from argus.reason import hypotheses as H
from argus.reason.engine import Config

ROOT = Path(__file__).resolve().parents[3]          # the ARGUS project folder
DEFAULT_ROOTS = ("cases_lab", "cases_linux", "cases_benign")
# the installed Linux rule library (written by a learning run here or by tools/rules_induce.py);
# ARGUS runs alone until one exists
DEFAULT_LIBRARY = ROOT / "eval_runs" / "lab_library.json"
LEARN_ARCHIVE = ROOT / "eval_runs"                   # each learning run's library, kept dated
LEARN_CACHE = ROOT / ".argus_cache" / "lab_induce"   # shared with tools/rules_induce.py
LEARN_PROVIDER = os.environ.get("ARGUS_LEARN_PROVIDER", "ollama")
DEFAULT_MODEL = os.environ.get("ARGUS_RULE_MODEL", "gpt-oss:120b-cloud")
SIGMA = ROOT / "intel" / "snapshots" / "lab" / "argus_sigma_rules.json"
SPLIT = ROOT / "lab_split.json"
LAB = ROOT / "cases_lab"                             # where imported windows go
CAPTURES = Path(os.environ.get("ARGUS_CAPTURES", ROOT / "Test Setup" / "lab" / "captured"))
FEEDBACK_DIR = Path(os.environ.get("ARGUS_FEEDBACK_DIR", ROOT / "eval_runs" / "analyst_feedback"))

router = APIRouter(prefix="/workbench", tags=["workbench"])


# ============================================================ configuration

def _install_path() -> Path | None:
    """Where the installed library lives (None: ARGUS runs alone, by choice)."""
    p = os.environ.get("ARGUS_LIBRARY")
    if p == "none":
        return None
    return Path(p) if p else DEFAULT_LIBRARY


def _library_path() -> Path | None:
    p = _install_path()
    return p if p and p.exists() else None


def _config() -> tuple[Config, dict]:
    """ARGUS's frozen configuration, plus the rule library's active rules (deciding) and
    shadow rules (measured only) when a library is present."""
    hyps, shadow, info = list(H.HYPOTHESES), [], {"library": None}
    lib = _library_path()
    if lib:
        from argus.rules.library import RuleLibrary
        L = RuleLibrary.load(lib)
        hyps += L.hypotheses("active")
        shadow = L.hypotheses("shadow")
        info = {"library": str(lib.relative_to(ROOT)) if lib.is_relative_to(ROOT) else str(lib),
                "active": len(L.by_status("active")), "shadow": len(L.by_status("shadow"))}
    cfg = Config(confound=cg.load(), observability=obsmod.load(), hypotheses=hyps, shadow=shadow)
    return cfg, info


CFG, CFG_INFO = _config()
store = CaseStore(cfg=CFG)


def _reload() -> None:
    """Use the installed library from now on. Cases are triaged again on request."""
    global CFG, CFG_INFO, store
    CFG, CFG_INFO = _config()
    store = CaseStore(cfg=CFG)
_slots = asyncio.Semaphore(2)                        # triage two cases at a time


def _roots() -> list[str]:
    env = os.environ.get("ARGUS_CASE_ROOTS")
    names = env.split(":") if env else list(DEFAULT_ROOTS)
    return [n for n in names if (ROOT / n).is_dir()] + (["live"] if LIVE is not None else [])


def _is_case(d: Path) -> bool:
    return d.is_dir() and ((d / "events.jsonl").exists() or (d / "host").is_dir()
                           or (d / "meta.json").exists())


def _case_dir(root: str, name: str) -> Path:
    if root not in _roots() or "/" in name or "\\" in name or name.startswith("."):
        raise HTTPException(404, "unknown corpus or case")
    d = ROOT / root / name
    if not _is_case(d):
        raise HTTPException(404, "unknown case")
    return d


def _split(case_id: str) -> tuple[str, str]:
    if ":" not in case_id:
        raise HTTPException(404, "case ids are <corpus>:<case>")
    root, name = case_id.split(":", 1)
    return root, name


def _meta(d: Path) -> dict:
    m = {}
    if (d / "meta.json").exists():
        try:
            m = json.loads((d / "meta.json").read_text())
        except json.JSONDecodeError:
            m = {}
    w = (m.get("capture") or {}).get("window") or {}
    return {"host": m.get("host") or m.get("target") or "", "campaign": m.get("campaign") or "",
            "start": w.get("start") or m.get("start") or "", "end": w.get("end") or m.get("end") or "",
            "dataset": m.get("dataset") or ""}


# ============================================================ view model

def _summary(c) -> str:
    f = c.facts
    t = c.claim_type
    if t == "process_create":
        return str(f.get("command") or f.get("image") or "")
    if t.startswith("file_"):
        return str(f.get("file_path") or "")
    if t in ("host_network_connection", "network_connection", "conn"):
        return f"{f.get('dst_ip', '')}:{f.get('dst_port', '')} {f.get('protocol') or ''}".strip()
    return str(c.event or "")


def _claim_row(c, by: dict[str, list[str]]) -> dict:
    f = c.facts
    ctrl = max((p.control.value for p in c.provenance), default="")
    return {"id": c.claim_id, "time": c.time, "host": f.get("host") or c.entity, "type": c.claim_type,
            "image": f.get("image"), "summary": _summary(c)[:400], "evidence_for": by.get(c.claim_id, []),
            "control": ctrl, "event_id": f.get("_event_id")}


def _names(case_id: str) -> dict[str, str]:
    """Process names from the window's lineage.json. An ancestor launched in an earlier window
    performed nothing in this one, so the graph built from this window's claims cannot name it."""
    try:
        if case_id.startswith("live:"):
            side = LIVE.cases[case_id].folder / "lineage.json"
        else:
            side = _case_dir(*_split(case_id)) / "lineage.json"
        procs = json.loads(side.read_text()).get("processes", {})
    except Exception:                                  # no sidecar, or not a corpus case
        return {}
    return {k: v["image"] for k, v in procs.items() if isinstance(v, dict) and v.get("image")}


def _tree(claims, evidence: set[str], root: str | None = None, cap: int = 400,
          names: dict[str, str] | None = None) -> list[dict]:
    """The process tree: nodes with image, folder class, launch command and whether any claim
    the node performed is evidence. Roots first, children nested.

    With an episode, only the root's own subtree is drawn; without one, only the processes
    behind the evidence and their ancestors (a record naming more than three performing
    processes names no single actor and is skipped)."""
    from argus.reason.lineage import ProcessGraph
    g = ProcessGraph.from_claims(claims)
    if g is None:
        return []
    if root and (root in g.parent or root in g.claims_of):
        keys = g.subtree(root)
    else:
        keys = set()
        for c in claims:
            if c.claim_id in evidence:
                actors = g.actors(c)
                if len(actors) <= 3:                   # a merged record names no single actor
                    for a in actors:
                        keys.update(g.ancestry(a))
    if len(keys) > cap:
        # keep the tree connected: breadth-first from its tops, never a sorted slice (which
        # could drop the root and split one episode into several trees)
        queue = sorted(k for k in keys if g.parent.get(k) not in keys)
        kept: list[str] = []
        while queue and len(kept) < cap:
            k = queue.pop(0)
            if k not in kept:
                kept.append(k)
                queue.extend(sorted(c for c in g.children.get(k, ()) if c in keys))
        keys = set(kept)
    nodes = {}
    for k in keys:
        mine = g.claims_of.get(k, [])
        launch = next((c for c in mine if c.claim_type == "process_create"
                       and g.actors(c) and g.actors(c)[0] == k), None)
        image = g.image.get(k) or (names or {}).get(k) or ("(started before capture)" if k.endswith("@pre") else "?")
        nodes[k] = {"key": k, "image": image, "user_writable": g.writable(k),
                    "command": (_summary(launch)[:300] if launch else None),
                    "claims": len(mine), "types": dict(Counter(c.claim_type for c in mine).most_common(4)),
                    "evidence": sum(1 for c in mine if c.claim_id in evidence), "children": []}
    roots = []
    for k, n in sorted(nodes.items()):
        p = g.parent.get(k)
        (nodes[p]["children"] if p in nodes and p != k else roots).append(n)
    return roots


def _hyp(r, claims_by_id, by) -> dict:
    return {"rule_id": r.rule_id or r.technique, "technique": r.technique, "name": r.name,
            "tactic": r.tactic, "score": round(r.score, 4), "rationale": r.rationale,
            "defeaters": [{"kind": d.kind.value, "reason": d.reason, "weight": d.weight} for d in r.defeaters],
            "coverage_gaps": r.coverage_gaps,
            "support": [_claim_row(claims_by_id[i], by) for i in r.support if i in claims_by_id][:40],
            "support_total": len(r.support)}


def view(case: Case) -> dict:
    d = case.decision
    if d is None:
        return {"case_id": case.case_id, "status": case.status, "error": case.error}
    claims_by_id = {c.claim_id: c for c in case.claims}
    deciding = [r for r in d.hypotheses if r.score > 0]
    by: dict[str, list[str]] = {}
    for r in deciding + list(d.shadow):
        for i in r.support:
            by.setdefault(i, []).append(r.rule_id or r.technique)
    evidence = set(by)
    root = None
    if d.episodes:
        scope_ids = set(d.episodes[0].get("claim_ids", []))
        scope = [claims_by_id[i] for i in scope_ids if i in claims_by_id]
        scope_name = f"episode rooted at {d.episodes[0].get('root_image')}"
        root = d.episodes[0].get("root")
    else:
        scope = [claims_by_id[i] for i in evidence if i in claims_by_id]
        scope_name = "processes behind the evidence"
    timeline = sorted((_claim_row(claims_by_id[i], by) for i in evidence if i in claims_by_id),
                      key=lambda r: str(r["time"] or ""))
    try:
        from argus.llm.verbalizer import render
        explanation = render(d).text
    except Exception as exc:                          # explanation is a convenience, never a blocker
        explanation = f"(no explanation: {type(exc).__name__})"
    top = d.top if d.top and d.top.score > 0 else None
    return {
        "case_id": case.case_id, "status": case.status,
        "verdict": {"disposition": d.disposition.value, "severity": d.severity, "priority": d.priority,
                    "top": ({"name": top.name, "rule_id": top.rule_id or top.technique, "score": top.score}
                            if top else None),
                    "blind_spots": d.blind_spots, "next_actions": d.next_actions, "notes": d.notes,
                    "suppressed": d.suppressed, "claims_total": d.claims_total},
        "explanation": explanation,
        "revisions": [r.__dict__ for r in case.revisions],
        "hypotheses": [_hyp(r, claims_by_id, by) for r in deciding],
        "shadow": [_hyp(r, claims_by_id, by) for r in d.shadow],
        "tree": {"scope": scope_name, "roots": _tree(scope, evidence, root, names=_names(case.case_id))},
        "timeline": timeline,
        "sensors": {k: v.model_dump() for k, v in case.health.items()},
        "claim_types": dict(Counter(c.claim_type for c in case.claims).most_common()),
    }


# ============================================================ routes

@router.get("/config")
async def config() -> dict:
    return {"roots": _roots(), "config": CFG.as_dict(), **CFG_INFO,
            "feedback_dir": str(FEEDBACK_DIR)}


@router.get("/cases")
async def cases(root: str) -> dict:
    if root == "live" and LIVE is not None:
        return _live_cases()
    if root not in _roots():
        raise HTTPException(404, "unknown corpus")
    out = []
    for d in sorted(p for p in (ROOT / root).iterdir() if _is_case(p)):
        cid = f"{root}:{d.name}"
        c = await store.get(cid)
        row = {"case_id": cid, "name": d.name, **_meta(d), "status": c.status if c else "new"}
        if c and c.decision:
            dec = c.decision
            row.update({"disposition": dec.disposition.value, "severity": dec.severity,
                        "priority": dec.priority, "blind_spots": len(dec.blind_spots),
                        "top": dec.top.name if dec.top and dec.top.score > 0 else None, "episode": bool(dec.episodes),
                        "shadow": len(dec.shadow)})
        out.append(row)
    return {"root": root, "cases": out}


async def _triage(cid: str, path: Path) -> None:
    async with _slots:
        c = await store.get(cid)
        if c and c.status in ("running", "complete"):
            return
        c = await store.create(cid)
        await store.ingest_path(c, path)


@router.post("/triage/{case_id}")
async def triage(case_id: str, bg: BackgroundTasks) -> dict:
    c = await store.get(case_id)
    if c and c.status in ("running", "complete"):     # already decided (a live case is decided as it arrives)
        return {"case_id": case_id, "status": c.status}
    root, name = _split(case_id)
    d = _case_dir(root, name)
    if not c or c.status == "failed":
        bg.add_task(_triage, case_id, d)
    return {"case_id": case_id, "status": c.status if c else "queued"}


@router.post("/triage_all")
async def triage_all(root: str, bg: BackgroundTasks) -> dict:
    if root == "live":
        return {"root": root, "queued": 0}           # live cases are decided as their events arrive
    if root not in _roots():
        raise HTTPException(404, "unknown corpus")
    n = 0
    for d in sorted(p for p in (ROOT / root).iterdir() if _is_case(p)):
        cid = f"{root}:{d.name}"
        if not await store.get(cid):
            bg.add_task(_triage, cid, d)
            n += 1
    return {"root": root, "queued": n}


@router.get("/case/{case_id}")
async def case_view(case_id: str) -> dict:
    c = await store.get(case_id)
    if not c:
        raise HTTPException(404, "not triaged yet")
    return await asyncio.to_thread(view, c)


@router.get("/case/{case_id}/groundtruth")
async def groundtruth(case_id: str) -> dict:
    """EVALUATION ONLY: the corpus's labels, mapped onto this case's claims."""
    root, name = _split(case_id)
    d = _case_dir(root, name)
    lab = d / "labels.json"
    if not lab.exists():
        return {"available": False}
    L = json.loads(lab.read_text())
    mal = set(L.get("malicious_event_ids") or [])
    c = await store.get(case_id)
    ids = [x.claim_id for x in (c.claims if c else []) if x.facts.get("_event_id") in mal]
    return {"available": True, "category": L.get("category"), "malicious_claims": ids,
            "steps": [{"name": a.get("name"), "status": a.get("status")} for a in L.get("abilities") or []],
            "source": L.get("source")}


class Feedback(BaseModel):
    case_id: str
    outcome: Literal["true_positive", "false_positive", "benign", "unknown"]
    rule_verdicts: dict[str, Literal["malicious", "benign"]] = {}
    analyst: str | None = None
    note: str | None = None


def _read_jsonl(p: Path) -> list[dict]:
    if not p.exists():
        return []
    return [json.loads(x) for x in p.read_text().splitlines() if x.strip()]


@router.post("/feedback")
async def feedback(fb: Feedback) -> dict:
    """Append-only: the case outcome, and per-rule verdicts in the shape the rule-library
    feedback loop reads (argus.rules.feedback.Verdict)."""
    c = await store.get(fb.case_id)
    if not c or not c.decision:
        raise HTTPException(404, "triage the case first")
    FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)
    at = time.strftime("%Y-%m-%dT%H:%M:%S")
    rec = {"at": at, **fb.model_dump(), "disposition": c.decision.disposition.value,
           "config": CFG_INFO}
    with open(FEEDBACK_DIR / "case_outcomes.jsonl", "a") as fh:
        fh.write(json.dumps(rec) + "\n")
    support = {r.rule_id or r.technique: r.support for r in list(c.decision.hypotheses) + list(c.decision.shadow)}
    with open(FEEDBACK_DIR / "rule_verdicts.jsonl", "a") as fh:
        for rid, v in fb.rule_verdicts.items():
            fh.write(json.dumps({"rule_id": rid, "capture": fb.case_id, "verdict": v,
                                 "events": len(support.get(rid, [])),
                                 "note": f"analyst {fb.analyst or ''} {at}".strip()}) + "\n")
    return {"recorded": True, "case_id": fb.case_id, "rule_verdicts": len(fb.rule_verdicts)}


@router.get("/feedback/{case_id}")
async def feedback_for(case_id: str) -> dict:
    return {"case_id": case_id,
            "outcomes": [r for r in _read_jsonl(FEEDBACK_DIR / "case_outcomes.jsonl") if r["case_id"] == case_id],
            "rule_verdicts": [r for r in _read_jsonl(FEEDBACK_DIR / "rule_verdicts.jsonl") if r["capture"] == case_id]}


def _checks_view(checks: dict) -> list[dict]:
    """The five checks in order (argus.rules.checks.CHECKS), each passed, failed or not reached."""
    from argus.rules import checks as C
    out = []
    for key, name, question in C.CHECKS:
        c = checks.get(key)
        state = "not_reached" if c is None else ("passed" if c.get("passed") else "failed")
        out.append({"key": key, "id": key.split("_")[0], "name": name, "question": question, "state": state,
                    "detail": (c or {}).get("detail", "")[:300], "source": (c or {}).get("source")})
    return out


@router.get("/library")
async def library() -> dict:
    from argus.rules.library import RuleLibrary
    lib = _library_path()
    if not lib:
        return {"library": None, "entries": []}
    L = RuleLibrary.load(lib)                         # check records in today's form
    out = []
    for e in sorted(L.entries.values(), key=lambda e: e.uid):
        r = e.rule
        out.append({"uid": e.uid, "name": r.get("name"), "technique": r.get("technique"),
                    "status": e.status, "reason": (e.history or [{}])[-1].get("reason", ""),
                    "checks": _checks_view(e.checks),
                    "origin": (e.origin or {}).get("capture"),
                    "history": e.history,
                    "select": [i.get("select") for i in r.get("indicators", [])]})
    return {"library": CFG_INFO.get("library"), "counts": L.counts(), "entries": out}


@router.get("/gaps")
async def gaps() -> dict:
    return {"gaps": await store.coverage_gaps()}


# ============================================================ rule learning (S3) from the page

class LearnRequest(BaseModel):
    model: str | None = None
    # used for this run only: held by the run's model client, never stored, logged or returned
    api_key: str = Field("", repr=False)


class LearnJob(BaseModel):
    state: Literal["idle", "running", "done", "failed"] = "idle"
    stage: str = ""
    done: int = 0
    total: int = 0
    model: str = ""
    started: float | None = None
    finished: float | None = None
    message: str = ""
    result: dict = {}


JOB = LearnJob()


def _design_windows():
    """The lab's design operations (lab_split.json: the first `design_count`, in capture
    order) and their windows. Test operations are never learned from."""
    from argus.rules.learn import Window
    if not SPLIT.exists():
        return [], []
    sp = json.loads(SPLIT.read_text())
    design = sp["operations"][: sp.get("design_count", 3)]
    out = []
    for d in sorted(LAB.iterdir()) if LAB.is_dir() else []:
        if (d / "events.jsonl").exists() and (d / "meta.json").exists():
            m = json.loads((d / "meta.json").read_text())
            if m.get("campaign") in design:
                out.append(Window(d.name, d, m.get("host", "?"), m["campaign"]))
    return design, out


def _progress(stage: str, done: int, total: int) -> None:
    JOB.stage, JOB.done, JOB.total = stage, done, total


def _learn(windows, model: str, key: str | None) -> None:
    """One learning run, in a worker thread. The key reaches only the model clients."""
    from argus.llm.cache import ResponseCache
    from argus.llm.client import LLMClient
    from argus.rules import learn as L
    from argus.rules.feedback import memory as rule_memory
    from argus.rules.library import RuleLibrary
    try:
        installed = _install_path()
        old = RuleLibrary.load(installed) if installed and installed.exists() else None
        cache = ResponseCache(LEARN_CACHE)
        base = os.environ.get("OLLAMA_BASE_URL", "https://ollama.com") if LEARN_PROVIDER == "ollama" else None
        sigma = json.loads(SIGMA.read_text())["rules"] if SIGMA.exists() else []
        res = L.learn(windows, lambda: LLMClient(LEARN_PROVIDER, model, cache=cache, api_key=key, base_url=base),
                      model, sigma=sigma, memory=rule_memory(old) if old else "", progress=_progress)
        lib, merged = L.combine(old, res.library, windows)
        stamp = time.strftime("%Y-%m-%d-%H%M%S")
        run_dir = LEARN_ARCHIVE / f"{stamp}-workbench-learn"
        run_dir.mkdir(parents=True, exist_ok=True)
        res.library.save(run_dir / "library.json")
        if installed:
            installed.parent.mkdir(parents=True, exist_ok=True)
            lib.save(installed)
        new = set(res.library.entries) - set(old.entries if old else {})
        JOB.result = {"new_rules": len(new),
                      "new_active": sum(1 for u in new if lib.entries[u].status == "active"),
                      "awaiting_review": sum(1 for u in new if lib.entries[u].status == "shadow"),
                      "duplicates_retired": len(res.merged) + len(merged),
                      "library": lib.counts(), "model_calls": res.meter.get("calls", 0),
                      "run": str(run_dir.relative_to(ROOT)) if run_dir.is_relative_to(ROOT) else str(run_dir)}
        _reload()
        JOB.state, JOB.message = "done", "Learning finished."
    except L.KeyRefused:
        JOB.state, JOB.message = "failed", "The model service refused the API key. Nothing was changed."
    except Exception as exc:                         # a failed run changes nothing
        JOB.state, JOB.message = "failed", f"Learning failed: {type(exc).__name__}: {str(exc)[:200]}"
    finally:
        key = None                                   # noqa: F841 — drop the last reference here
        JOB.finished = time.time()


@router.get("/learn")
async def learn_status() -> dict:
    design, wins = _design_windows()
    return {**JOB.model_dump(), "default_model": DEFAULT_MODEL,
            "source": {"operations": design, "windows": len(wins),
                       "hosts": sorted({w.host for w in wins})}}


@router.post("/learn")
async def learn_start(req: LearnRequest) -> dict:
    if JOB.state == "running":
        raise HTTPException(409, "a learning run is already in progress")
    if IMPORT.state == "running":
        raise HTTPException(409, "a capture is being imported; learn when it has finished")
    design, wins = _design_windows()
    if not wins:
        raise HTTPException(400, "no design operations to learn from (lab_split.json, cases_lab)")
    model = (req.model or DEFAULT_MODEL).strip()
    key = req.api_key.strip() or None
    JOB.state, JOB.stage, JOB.done, JOB.total = "running", "starting", 0, 0
    JOB.model, JOB.started, JOB.finished, JOB.message, JOB.result = model, time.time(), None, "", {}
    asyncio.get_running_loop().run_in_executor(None, _learn, wins, model, key)
    return await learn_status()


class RuleDecision(BaseModel):
    action: Literal["approve", "retire"]
    note: str = ""


@router.post("/library/{uid}")
async def decide_rule(uid: str, d: RuleDecision) -> dict:
    """The analyst's decision on a rule: approve a shadow rule (it starts deciding), or retire
    a shadow or active rule. Recorded in the rule's history."""
    from argus.rules.library import LifecycleError, RuleLibrary
    path = _library_path()
    if path is None:
        raise HTTPException(404, "no rule library")
    if JOB.state == "running":
        raise HTTPException(409, "a learning run is in progress; decide when it has finished")
    lib = RuleLibrary.load(path)
    if uid not in lib.entries:
        raise HTTPException(404, "unknown rule")
    to = "active" if d.action == "approve" else "retired"
    why = f"analyst {'approved' if to == 'active' else 'retired'} it in the workbench" + (f": {d.note[:200]}" if d.note else "")
    try:
        if to == "active":
            lib.confirm_by_analyst(uid, why)          # the approval is the rule's C5 pass
        else:
            lib.transition(uid, to, why)
    except LifecycleError as exc:
        raise HTTPException(409, str(exc))
    lib.save(path)
    _reload()
    return {"uid": uid, "status": to, "counts": lib.counts()}


# ============================================================ importing a capture from the page

_FOLDER = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
_RUN = re.compile(r"^[a-z0-9][a-z0-9-]{0,23}$")     # no "_": it separates name, host and time
# what the page may copy into a capture folder: each host's logs, Zeek's logs and top-level
# JSON (the CALDERA report, ground_truth.json). Nothing else, and never outside the folder
_UPLOAD = re.compile(r"^(?:[A-Za-z0-9][A-Za-z0-9._-]{0,63}/(?:audit|auth)\.log"
                     r"|network/[a-z0-9_]{1,32}\.log"
                     r"|[A-Za-z0-9][A-Za-z0-9._-]{0,95}\.json)$")
MAX_UPLOAD = 4 << 30                                 # per file


class ImportRequest(BaseModel):
    folder: str
    name: str
    report: str | None = None


class ImportJob(BaseModel):
    state: Literal["idle", "running", "done", "failed"] = "idle"
    stage: str = ""
    done: int = 0
    total: int = 0
    name: str = ""
    message: str = ""
    result: dict = {}


IMPORT = ImportJob()


def _rel(p: Path) -> str:
    return str(p.relative_to(ROOT)) if p.is_relative_to(ROOT) else str(p)


def _split_file() -> dict:
    return json.loads(SPLIT.read_text()) if SPLIT.exists() else {"operations": [], "design_count": 3}


def _imported() -> dict[str, str]:
    """Operations already in cases_lab: name -> the capture folder it came from ("" if it was
    converted from a terminal, which does not record one)."""
    out: dict[str, str] = {}
    for d in sorted(LAB.iterdir()) if LAB.is_dir() else []:
        if d.name.startswith(".") or not (d / "meta.json").exists():
            continue
        try:
            m = json.loads((d / "meta.json").read_text())
        except (json.JSONDecodeError, OSError):
            continue
        if m.get("campaign"):
            out.setdefault(m["campaign"], m.get("capture_folder") or "")
    return out


def _taken(split: dict, imported: dict) -> set[str]:
    return set(imported) | set(split.get("operations") or []) | set(split.get("excluded") or {})


def _reports(d: Path) -> list[str]:
    """The capture's CALDERA operation reports: top-level JSON with steps and a host group."""
    out = []
    for f in sorted(d.glob("*.json")):
        if f.name == "ground_truth.json" or f.stat().st_size > 64 << 20:
            continue
        try:
            j = json.loads(f.read_text())
        except (json.JSONDecodeError, UnicodeDecodeError, OSError):
            continue
        if isinstance(j, dict) and "steps" in j and "host_group" in j:
            out.append(f.name)
    return out


def _suggest(folder: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", folder.lower()).strip("-")[:24].strip("-") or "capture"


def _capture(d: Path, imported: dict) -> dict:
    name = _suggest(d.name)
    done_as = next((n for n, f in imported.items() if f == d.name), None) \
        or (name if imported.get(name) == "" else None)
    return {"folder": d.name, "name": name, "hosts": sorted(p.parent.name for p in d.glob("*/audit.log")),
            "reports": _reports(d), "ground_truth": (d / "ground_truth.json").exists(),
            "network": (d / "network" / "conn.log").exists(),
            "size_mb": round(sum(f.stat().st_size for f in d.rglob("*") if f.is_file()) / 1e6, 1),
            "modified": time.strftime("%Y-%m-%d %H:%M", time.localtime(d.stat().st_mtime)),
            "imported_as": done_as}


@router.get("/captures")
async def captures() -> dict:
    split, imported = _split_file(), _imported()
    found = [d for d in CAPTURES.iterdir() if d.is_dir() and _FOLDER.match(d.name)
             and any(d.glob("*/audit.log"))] if CAPTURES.is_dir() else []
    found.sort(key=lambda d: d.stat().st_mtime, reverse=True)
    return {"folder": _rel(CAPTURES), "captures": [_capture(d, imported) for d in found],
            "split": {"operations": split.get("operations") or [], "design_count": split.get("design_count", 3)},
            "taken": sorted(_taken(split, imported)), "job": IMPORT.model_dump()}


@router.put("/captures/{folder}/{path:path}")
async def upload(folder: str, path: str, request: Request) -> dict:
    """Copy one file of a capture into the lab's capture folder (the page's Choose folder… and
    Add report…). Only a capture's own files, and never over an existing one."""
    dest = CAPTURES / folder / path
    if not _FOLDER.match(folder) or not _UPLOAD.match(path) \
            or not dest.resolve().is_relative_to(CAPTURES.resolve()):
        raise HTTPException(400, "not a capture file")
    if dest.exists():
        raise HTTPException(409, f"{folder}/{path} already exists")
    dest.parent.mkdir(parents=True, exist_ok=True)
    part, n = dest.with_name(dest.name + ".part"), 0
    try:
        with open(part, "wb") as fh:
            async for chunk in request.stream():
                n += len(chunk)
                if n > MAX_UPLOAD:
                    raise HTTPException(413, "file too large")
                fh.write(chunk)
        part.rename(dest)
    finally:
        part.unlink(missing_ok=True)
    return {"saved": f"{folder}/{path}", "bytes": n}


def _register(name: str) -> bool:
    """Add an evaluated operation to lab_split.json, after the ones already there: its role
    (design or test) follows from its position alone, never from a result."""
    sp = _split_file()
    ops = sp.setdefault("operations", [])
    if name in ops:
        return False
    ops.append(name)
    SPLIT.write_text(json.dumps(sp, indent=1) + "\n")
    return True


def _unregister(name: str) -> None:
    sp = _split_file()
    if (sp.get("operations") or [])[-1:] == [name]:
        sp["operations"].pop()
        SPLIT.write_text(json.dumps(sp, indent=1) + "\n")


def _iprogress(stage: str, done: int, total: int) -> None:
    IMPORT.stage, IMPORT.done, IMPORT.total = stage, done, total


def _import(src: Path, name: str, report: Path | None, gt: Path | None) -> None:
    """One import, in a worker thread. The windows are written to a staging folder and moved
    into cases_lab once all of them are written; a failed import leaves nothing behind."""
    from argus.collectors.lab_capture import convert
    stage, registered = LAB / f".importing-{name}", False
    try:
        shutil.rmtree(stage, ignore_errors=True)
        if report:                                   # registered before it is converted or scored
            registered = _register(name)
        s = convert(src, stage, name, report=report, ground_truth=gt, progress=_iprogress, source=src.name)
        for d in sorted(stage.iterdir()):
            d.rename(LAB / d.name)
        stage.rmdir()
        sp = _split_file()
        ops = sp.get("operations") or []
        role = ("design" if ops.index(name) < sp.get("design_count", 3) else "test") if name in ops else "triage"
        IMPORT.result = {"windows": len(s["windows"]), "hosts": s["hosts"], "role": role,
                         "labelled": s["labelled"], "steps": s["steps"], "steps_matched": s["steps_matched"],
                         "clock_offset_s": s["clock_offset_s"], "corpus": LAB.name}
        IMPORT.state, IMPORT.message = "done", "Import finished."
    except Exception as exc:                         # a failed import changes nothing
        shutil.rmtree(stage, ignore_errors=True)
        for d in LAB.glob(f"{name}_*"):              # the name was unused: these are this import's
            shutil.rmtree(d, ignore_errors=True)
        if registered:
            _unregister(name)
        IMPORT.state, IMPORT.message = "failed", f"Import failed: {type(exc).__name__}: {str(exc)[:200]}"


@router.get("/import")
async def import_status() -> dict:
    return IMPORT.model_dump()


@router.post("/import")
async def import_start(req: ImportRequest) -> dict:
    if IMPORT.state == "running":
        raise HTTPException(409, "an import is already in progress")
    if JOB.state == "running":
        raise HTTPException(409, "a learning run is in progress; import when it has finished")
    src = CAPTURES / req.folder
    if not _FOLDER.match(req.folder) or not src.is_dir() or not any(src.glob("*/audit.log")):
        raise HTTPException(404, "no capture with a <host>/audit.log in that folder")
    name = req.name.strip()
    if not _RUN.match(name):
        raise HTTPException(400, "a name is 1 to 24 lowercase letters, digits or hyphens")
    if name in _taken(_split_file(), _imported()) or any(LAB.glob(f"{name}_*")):
        raise HTTPException(409, f"the name {name} is already used")
    report = None
    if req.report:
        if req.report not in _reports(src):
            raise HTTPException(400, "not a CALDERA operation report in this capture")
        report = src / req.report
    gt = src / "ground_truth.json" if report and (src / "ground_truth.json").exists() else None
    LAB.mkdir(parents=True, exist_ok=True)
    IMPORT.state, IMPORT.stage, IMPORT.done, IMPORT.total = "running", "starting", 0, 0
    IMPORT.name, IMPORT.message, IMPORT.result = name, "", {}
    asyncio.get_running_loop().run_in_executor(None, _import, src, name, report, gt)
    return IMPORT.model_dump()


# ============================================================ ad-hoc (live) triage, event by event

class LiveRequest(BaseModel):
    run: str


LIVE = None                                          # argus.live.loop.LiveTriage, once started
LIVE_LISTED = 25                                     # quiet cases listed per host, most recent first
FLAGGED = ("malicious", "suspicious")


def _live_decide(c, folder: Path, cause: str, event_time: float) -> None:
    """The live loop's decision callback: the case is decided by the store in use now."""
    from datetime import datetime, timezone
    store.decide_live(c.case_id, folder, cause, datetime.fromtimestamp(event_time, timezone.utc).isoformat())


def _live_cases() -> dict:
    """Live cases: every flagged, undecidable or blind one, then each host's most recently
    active."""
    from datetime import datetime, timezone
    rows = []
    for lc in list(LIVE.cases.values()):
        c = store._cases.get(lc.case_id)
        dec = c.decision if c else None
        row = {"case_id": lc.case_id, "name": f"{lc.host} · {lc.root_image or '?'} · {lc.total} events",
               "host": lc.host, "campaign": LIVE.run, "status": c.status if c else "queued",
               "start": datetime.fromtimestamp(lc.first, timezone.utc).isoformat() if lc.first else "",
               "end": datetime.fromtimestamp(lc.last, timezone.utc).isoformat() if lc.last else "",
               "last": lc.last or 0.0, "root_image": lc.root_image, "command": lc.command, "events": lc.total,
               "decided_at": c.revisions[-1].at if c and c.revisions else None}
        if dec:
            row.update({"disposition": dec.disposition.value, "severity": dec.severity, "priority": dec.priority,
                        "blind_spots": len(dec.blind_spots),
                        "top": dec.top.name if dec.top and dec.top.score > 0 else None,
                        "episode": bool(dec.episodes), "shadow": len(dec.shadow), "revisions": len(c.revisions)})
        rows.append(row)
    notable = [r for r in rows if r.get("disposition") in ("malicious", "suspicious", "undecidable")
               or r.get("blind_spots")]
    # flagged first, by priority: a benign case that only carries a blind spot (a sensor
    # restart on its host) must not push an alert down the list
    notable.sort(key=lambda r: (r.get("disposition") not in FLAGGED, -(r.get("priority") or 0.0), -r["last"]))
    ids = {r["case_id"] for r in notable}
    per_host: dict[str, int] = {}
    quiet = []
    for r in sorted((r for r in rows if r["case_id"] not in ids), key=lambda r: -r["last"]):
        if per_host.get(r["host"], 0) < LIVE_LISTED:
            per_host[r["host"]] = per_host.get(r["host"], 0) + 1
            quiet.append(r)
    return {"root": "live", "cases": notable + quiet, "total": len(rows), "attention": len(notable),
            "flagged": sum(1 for r in rows if r.get("disposition") in FLAGGED), "listed_per_host": LIVE_LISTED}


@router.get("/live")
async def live_status() -> dict:
    runs = sorted(d.name for d in CAPTURES.iterdir() if d.is_dir() and _FOLDER.match(d.name)) if CAPTURES.is_dir() else []
    st = LIVE.status() if LIVE is not None else {"run": None, "running": False, "error": None, "hosts": {}}
    flagged = 0
    for h in st["hosts"].values():
        h.update(flagged=0, first_alert=None)
    for lc in list(LIVE.cases.values()) if LIVE is not None else []:
        c = store._cases.get(lc.case_id)
        h = st["hosts"].get(lc.host)
        if not c or h is None:
            continue
        if c.decision and c.decision.disposition.value in FLAGGED:
            flagged += 1
            h["flagged"] += 1
        first = next((r for r in c.revisions if r.disposition in FLAGGED), None)
        if first and (h["first_alert"] is None or first.at < h["first_alert"]["at"]):
            h["first_alert"] = {"at": first.at, "event_time": first.event_time, "case_id": lc.case_id}
    return {**st, "runs": runs, "cases": len(LIVE.cases) if LIVE is not None else 0, "flagged": flagged}


@router.post("/live")
async def live_start(req: LiveRequest) -> dict:
    """Start deciding a run's cases as its logs arrive (the receiver writes captured/<run>/)."""
    global LIVE
    from argus.live.loop import LiveTriage
    if LIVE is not None and LIVE.running:
        raise HTTPException(409, f"live triage is already running on {LIVE.run}")
    if not _FOLDER.match(req.run):
        raise HTTPException(400, "a run name is letters, digits, dot, dash or underscore")
    for cid in [k for k in store._cases if k.startswith(f"live:{req.run}:")]:
        del store._cases[cid]                        # a restart reads the run again from its start
    LIVE = LiveTriage(CAPTURES / req.run, ROOT / "live" / req.run, _live_decide, run=req.run)
    LIVE.start()
    return await live_status()


@router.post("/live/stop")
async def live_stop() -> dict:
    if LIVE is None or not LIVE.running:
        raise HTTPException(409, "live triage is not running")
    await asyncio.to_thread(LIVE.stop)
    return await live_status()
