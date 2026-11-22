"""Case store.

Async submit-and-poll, because real SOAR platforms do not block on a synchronous
call and because evidence arrives late — EDR uploads lag, network logs roll on an
interval, analysts attach files by hand. A case is an append-only evidence log
with a revisable decision, and every revision records what caused it.
"""
from __future__ import annotations

import asyncio
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Literal

from argus.case import load_case
from argus.models import Claim, Decision, SensorHealth
from argus.reason.engine import Config, reason

Status = Literal["queued", "running", "complete", "failed"]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


@dataclass
class Revision:
    at: str                       # when the decision was made
    disposition: str
    severity: float
    cause: str
    event_time: str | None = None  # the newest event it saw (live cases: argus.live)


@dataclass
class Case:
    case_id: str
    status: Status = "queued"
    claims: list[Claim] = field(default_factory=list)
    health: dict[str, SensorHealth] = field(default_factory=dict)
    protocol_artifacts: set[str] = field(default_factory=set)
    decision: Decision | None = None
    revisions: list[Revision] = field(default_factory=list)
    error: str | None = None
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    def record(self, decision: Decision, cause: str, event_time: str | None = None) -> None:
        changed = (self.decision is None
                   or self.decision.disposition != decision.disposition)
        self.decision = decision
        self.updated_at = _now()
        if changed:
            self.revisions.append(Revision(at=_now(),
                                           disposition=decision.disposition.value,
                                           severity=decision.severity,
                                           cause=cause, event_time=event_time))


class CaseStore:
    """In-memory store. A production deployment swaps this for a versioned
    external store so decisions remain auditable as-of their decision time."""

    def __init__(self, cfg: Config | None = None) -> None:
        self._cases: dict[str, Case] = {}
        self._lock = asyncio.Lock()
        if cfg is None:
            from argus.assurance import confound as _cg
            from argus.assurance import observability as _obs
            cfg = Config(confound=_cg.load(), observability=_obs.load())
        self.cfg = cfg

    # ------------------------------------------------------------ lifecycle

    async def create(self, case_id: str | None = None) -> Case:
        cid = case_id or f"case-{uuid.uuid4().hex[:12]}"
        async with self._lock:
            case = Case(case_id=cid)
            self._cases[cid] = case
            return case

    async def get(self, case_id: str) -> Case | None:
        return self._cases.get(case_id)

    async def list_ids(self) -> list[str]:
        return list(self._cases)

    # -------------------------------------------------------------- ingest

    async def ingest_path(self, case: Case, path: Path) -> None:
        """Load telemetry from a directory. Runs in a thread: parsing a large audit log
        is blocking."""
        case.status = "running"
        try:
            lc = await asyncio.to_thread(load_case, path, case.case_id)
            case.claims = lc.claims
            case.health = lc.health
            case.protocol_artifacts = lc.protocol_artifacts
            await self.decide(case, cause="initial evidence load")
            case.status = "complete"
        except Exception as exc:                     # collector failure is evidence
            case.status = "failed"
            case.error = f"{type(exc).__name__}: {exc}"
            case.updated_at = _now()

    def decide_live(self, case_id: str, folder: Path, cause: str, event_time: str) -> Case:
        """A live case's folder decided again (argus.live): the case is created on its first
        decision, and every change of disposition is a revision with both clocks. Runs in
        the live loop's thread."""
        case = self._cases.get(case_id)
        if case is None:
            case = self._cases[case_id] = Case(case_id=case_id)
        lc = load_case(folder, case_id)
        case.claims, case.health, case.protocol_artifacts = lc.claims, lc.health, lc.protocol_artifacts
        decision = reason(case_id, case.claims, case.health, self.cfg, case.protocol_artifacts)
        case.record(decision, cause, event_time)
        case.status = "complete"
        return case

    async def add_claims(self, case: Case, claims: list[Claim], cause: str) -> None:
        """Append-only. Late evidence revises the decision rather than replacing the case."""
        case.claims.extend(claims)
        await self.decide(case, cause=cause)

    # ------------------------------------------------------------- reasoning

    async def decide(self, case: Case, cause: str) -> Decision:
        decision = await asyncio.to_thread(
            reason, case.case_id, case.claims, case.health, self.cfg,
            case.protocol_artifacts)
        case.record(decision, cause)
        return decision

    # -------------------------------------------------------------- gap feed

    async def coverage_gaps(self) -> list[dict]:
        """C5 — aggregate blind spots across every case seen.

        Turns coverage from an input into an output: which sensor gaps actually
        cost decisions, ranked, as a sensor-investment recommendation.
        """
        counts: dict[str, dict] = {}
        for case in self._cases.values():
            if not case.decision:
                continue
            for gap in case.decision.blind_spots:
                sensor = gap.split(":", 1)[0]
                entry = counts.setdefault(gap, {
                    "gap": gap, "sensor": sensor, "cases": 0,
                    "undecidable_cases": 0, "example_case": case.case_id,
                })
                entry["cases"] += 1
                if case.decision.disposition.value == "undecidable":
                    entry["undecidable_cases"] += 1
        return sorted(counts.values(),
                      key=lambda e: (-e["undecidable_cases"], -e["cases"]))
