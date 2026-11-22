"""ARGUS HTTP API.

Async submit-and-poll so it drops into a SOAR playbook without blocking, and so
late-arriving evidence revises an existing decision instead of starting over.

    POST   /triage                 submit a case            -> 202 + status_url
    GET    /triage/{case_id}       poll status / decision
    POST   /triage/{case_id}/evidence   append evidence, decision revises
    GET    /triage/{case_id}/claims     inspect the claim set
    POST   /feedback               analyst outcome
    GET    /coverage               sensor registry + measured health
    GET    /gaps                   ranked sensor-investment recommendations
    GET    /healthz
    GET    /ui/                    the analyst triage workbench (argus.api.workbench)

Run:
    uvicorn argus.api.app:app --reload
"""
from __future__ import annotations

from pathlib import Path
from typing import Any, Literal

from fastapi import BackgroundTasks, FastAPI, HTTPException, Response
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from argus.assurance import confound as cg
from argus.assurance import observability as obsmod
from argus.llm.cache import ResponseCache
from argus.llm.client import LLMClient
from argus.llm.verbalizer import polish, render
from argus.models import Claim, Decision
from argus.api.store import CaseStore
from argus.reason.engine import Config

app = FastAPI(
    title="ARGUS",
    version="3.0.0",
    description="Coverage-aware SOC triage. Reports what it could not see, "
                "and never reads sensor silence as refutation.",
)

store = CaseStore(cfg=Config(confound=cg.load(), observability=obsmod.load()))

# The analyst workbench: its own case store (same frozen configuration, plus the rule
# library's active and shadow rules when one is present) and the static front end.
from argus.api.workbench import router as workbench_router  # noqa: E402

app.include_router(workbench_router)
app.mount("/ui", StaticFiles(directory=Path(__file__).parent / "static", html=True), name="ui")


@app.get("/", include_in_schema=False)
async def index():
    return RedirectResponse("/ui/")


# ------------------------------------------------------------------ schemas

class TriageRequest(BaseModel):
    case_id: str | None = Field(None, description="Client-supplied id; generated if absent")
    case_path: str | None = Field(None, description="Directory of telemetry to load")
    claims: list[Claim] | None = Field(None, description="Pre-normalised claims (OCSF-derived)")


class TriageAccepted(BaseModel):
    case_id: str
    status: str
    status_url: str


class EvidenceRequest(BaseModel):
    claims: list[Claim]
    cause: str = "late evidence"


class FeedbackRequest(BaseModel):
    case_id: str
    outcome: Literal["true_positive", "false_positive", "benign", "unknown"]
    analyst: str | None = None
    note: str | None = None


class CaseStatus(BaseModel):
    case_id: str
    status: str
    created_at: str
    updated_at: str
    claims: int
    decision: Decision | None = None
    revisions: list[dict[str, Any]] = []
    error: str | None = None


# -------------------------------------------------------------------- routes

@app.get("/healthz")
async def healthz() -> dict:
    return {"ok": True, "service": "argus", "version": app.version}


@app.post("/triage", response_model=TriageAccepted, status_code=202)
async def submit(req: TriageRequest, bg: BackgroundTasks, response: Response):
    if not req.case_path and not req.claims:
        raise HTTPException(422, "provide either case_path or claims")

    case = await store.create(req.case_id)

    if req.case_path:
        p = Path(req.case_path)
        if not p.exists():
            raise HTTPException(404, f"case_path not found: {p}")
        bg.add_task(store.ingest_path, case, p)
    else:
        case.claims = list(req.claims or [])
        bg.add_task(store.decide, case, "initial evidence load")
        case.status = "running"

    url = f"/triage/{case.case_id}"
    response.headers["Location"] = url
    return TriageAccepted(case_id=case.case_id, status=case.status, status_url=url)


@app.get("/triage/{case_id}", response_model=CaseStatus)
async def poll(case_id: str):
    case = await store.get(case_id)
    if not case:
        raise HTTPException(404, "unknown case")
    return CaseStatus(
        case_id=case.case_id, status=case.status,
        created_at=case.created_at, updated_at=case.updated_at,
        claims=len(case.claims), decision=case.decision,
        revisions=[r.__dict__ for r in case.revisions], error=case.error,
    )


@app.post("/triage/{case_id}/evidence", response_model=CaseStatus)
async def add_evidence(case_id: str, req: EvidenceRequest):
    """Append-only. The decision revises and the revision records its cause."""
    case = await store.get(case_id)
    if not case:
        raise HTTPException(404, "unknown case")
    await store.add_claims(case, req.claims, req.cause)
    return await poll(case_id)


@app.get("/triage/{case_id}/claims")
async def claims(case_id: str, claim_type: str | None = None, limit: int = 200):
    case = await store.get(case_id)
    if not case:
        raise HTTPException(404, "unknown case")
    items = case.claims
    if claim_type:
        items = [c for c in items if c.claim_type == claim_type]
    return {"case_id": case_id, "total": len(case.claims),
            "returned": min(limit, len(items)), "claims": items[:limit]}


@app.post("/feedback")
async def feedback(req: FeedbackRequest):
    case = await store.get(req.case_id)
    if not case:
        raise HTTPException(404, "unknown case")
    # Outcome capture. Trust posteriors are learned from this in a later phase;
    # note that closure labels in real SOCs are noisy and need a noise model.
    return {"recorded": True, "case_id": req.case_id, "outcome": req.outcome}


@app.get("/coverage")
async def coverage(case_id: str | None = None):
    """Sensor registry and measured health — what each sensor covers, what it is
    blind to, and how much traffic it admits to having lost."""
    if case_id:
        case = await store.get(case_id)
        if not case:
            raise HTTPException(404, "unknown case")
        return {"case_id": case_id,
                "sensors": {k: v.model_dump() for k, v in case.health.items()}}
    out = {}
    for cid in await store.list_ids():
        c = await store.get(cid)
        if c and c.health:
            out[cid] = {k: v.model_dump() for k, v in c.health.items()}
    return {"cases": out}


@app.get("/gaps")
async def gaps():
    """Coverage-driven detection engineering.

    Which sensor gaps actually cost decisions, ranked. This is the output that
    turns triage failures into a sensor-investment case.
    """
    ranked = await store.coverage_gaps()
    return {
        "gaps": ranked,
        "summary": [
            f"{g['gap']} — seen in {g['cases']} case(s), "
            f"{g['undecidable_cases']} left undecidable"
            for g in ranked[:10]
        ],
    }


@app.get("/triage/{case_id}/explain")
async def explain(case_id: str, llm: str | None = None, llm_model: str | None = None):
    """Template-generated explanation. An LLM may only adjust phrasing; any
    sentence not traceable to a template sentence is dropped."""
    case = await store.get(case_id)
    if not case or not case.decision:
        raise HTTPException(404, "unknown case or no decision yet")
    ex = render(case.decision)
    if llm and llm != "none":
        client = LLMClient(provider=llm, model=llm_model, cache=ResponseCache())
        ex = polish(ex, client)
    return {"case_id": case_id, "text": ex.text, "sentences": ex.sentences,
            "dropped": ex.dropped, "provider": ex.provider,
            "template_generated": ex.polished is None}


@app.get("/confound")
async def confound():
    """What the corpus scan and capture metadata suppress, and why."""
    rep = cg.load()
    return rep.to_dict()
