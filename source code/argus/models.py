"""Core data model.

Design notes tied to the measured weaknesses in experiments/v1_on_dataset:

W2  Claims carry security-meaningful fields (`facts`), not just a process name.
W3  Per-claim semantics (logon source, source locality) survive all the way to the
    verdict instead of being collapsed into a count.
W7  A decision carries multiple scored hypotheses, not one verdict string.
"""
from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field


# --------------------------------------------------------------------- enums

class Control(str, Enum):
    """How much of this field an adversary can author. Used to discount trust."""
    L0 = "L0"   # kernel-emitted; not attacker-influenceable
    L1 = "L1"   # content chosen by attacker, existence not (e.g. a login user name)
    L2 = "L2"   # existence and content authored (e.g. process command line)
    L3 = "L3"   # attacker can suppress (host they hold admin on)


class DefeaterKind(str, Enum):
    """W5 — typed, hypothesis-relative. Never a global heuristic."""
    REBUT = "rebut"           # attacks the conclusion
    UNDERCUT = "undercut"     # attacks the inference (e.g. sensor was blind)
    UNDERMINE = "undermine"   # attacks premise trust (e.g. stale, attacker-authored)


class Disposition(str, Enum):
    MALICIOUS = "malicious"
    SUSPICIOUS = "suspicious"
    BENIGN = "benign"
    UNDECIDABLE = "undecidable"   # not "benign" — we could not tell


# -------------------------------------------------------------------- claims

class Provenance(BaseModel):
    sensor_id: str
    source: str
    offset: int | None = None
    span: str | None = None
    control: Control = Control.L1


class Claim(BaseModel):
    claim_id: str
    modality: Literal["identity", "endpoint", "network", "cti", "meta"]
    claim_type: str
    entity: str = "-"
    event: str = ""
    time: str | None = None
    confidence: float = 0.8
    reliability: float = 0.0

    # W2/W3: semantics reach the verdict.
    facts: dict[str, Any] = Field(default_factory=dict)
    provenance: list[Provenance] = Field(default_factory=list)

    @property
    def control(self) -> Control:
        """Weakest link: the most attacker-controllable provenance wins."""
        if not self.provenance:
            return Control.L1
        return max((p.control for p in self.provenance), key=lambda c: ["L0", "L1", "L2", "L3"].index(c.value))


# ------------------------------------------------------------- sensor health

class SensorHealth(BaseModel):
    """W6 — Zeek reported 35.294% loss in A04 and v1 had no consumer for it."""
    sensor_id: str
    healthy: bool = True
    loss_pct: float = 0.0
    covers: list[str] = Field(default_factory=list)
    blind_to: list[str] = Field(default_factory=list)
    invalidated_before: str | None = None      # set when the sensor's own log was tampered with
    # intervals in which the sensor could not record (stopped daemon, unloaded rule), each
    # {"start", "end" (None = not resumed), "seconds", "types", "cause"}: blind spots
    gaps: list[dict] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)

    def observability(self) -> float:
        """P(this sensor emits a record | the event occurred)."""
        if not self.healthy:
            return 0.0
        return max(0.0, 1.0 - (self.loss_pct / 100.0))


# --------------------------------------------------------------- hypotheses

class Defeater(BaseModel):
    kind: DefeaterKind
    reason: str
    weight: float = 0.0
    claim_ids: list[str] = Field(default_factory=list)


class HypothesisResult(BaseModel):
    technique: str
    name: str
    rule_id: str = ""               # unique id of a data rule; "" for a Python hypothesis
    tactic: str = ""
    score: float = 0.0
    support: list[str] = Field(default_factory=list)         # claim_ids
    defeaters: list[Defeater] = Field(default_factory=list)
    rationale: list[str] = Field(default_factory=list)
    coverage_gaps: list[str] = Field(default_factory=list)


class Decision(BaseModel):
    case_id: str
    disposition: Disposition
    # W7 — multi-label, every hypothesis scored.
    hypotheses: list[HypothesisResult] = Field(default_factory=list)
    severity: float = 0.0
    priority: float = 0.0
    claims_total: int = 0
    claims_considered: int = 0     # W1 — must equal claims_total
    blind_spots: list[str] = Field(default_factory=list)
    next_actions: list[str] = Field(default_factory=list)
    notes: list[str] = Field(default_factory=list)
    config: dict[str, Any] = Field(default_factory=dict)
    # Techniques reported but excluded from the disposition (capture artifacts).
    suppressed: list[str] = Field(default_factory=list)
    # Weak primitives that fired: reported as context for the analyst and used by the kill
    # chain, never deciding on their own (rule ids).
    context: list[str] = Field(default_factory=list)
    # W-E: process-tree episodes (root + claim ids) — the investigation scope, kept
    # separate from hypothesis evidence.
    episodes: list[dict[str, Any]] = Field(default_factory=list)
    # S3 lifecycle: rules in shadow are scored on every case and reported here, and can
    # never move the disposition, severity, blind spots or anything else above.
    shadow: list[HypothesisResult] = Field(default_factory=list)

    @property
    def top(self) -> HypothesisResult | None:
        """Top DECIDING hypothesis — a suppressed capture artifact is reported
        but must never present as the headline finding."""
        heads = [h for h in self.hypotheses
                 if h.technique not in self.suppressed and (h.rule_id or h.technique) not in self.context]
        for h in heads:
            if h.score > 0:
                return h
        # nothing decides: a context primitive is never the headline
        return heads[0] if heads else None
