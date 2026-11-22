"""W4 — within-capture baseline.

Measured problem: v1 used absolute thresholds. `failed >= 3 and success > 0` fired
on B01, a benign capture holding 20,644 Security events, where 3 failed logons is a
rate of 0.015%. A04 holds 3 Security events in total. Counts are not comparable
across captures whose sizes differ by four orders of magnitude; rates are.

Baselines must be WITHIN-capture. B03 and A04 were recorded seven days apart
(2026-02-23 vs 2026-03-02), so their background activity differs for calendar
reasons rather than behavioural ones — cross-capture baselining is invalid here.
"""
from __future__ import annotations

from collections import Counter
from dataclasses import dataclass, field

from argus.models import Claim, SensorHealth


@dataclass
class CaseContext:
    claims: list[Claim]
    health: dict[str, SensorHealth] = field(default_factory=dict)

    # W-E: process lineage, built on first use from the claims' `_procs` (lab windows).
    # The engine sets `lineage_enabled` from Config.enable_lineage (the ablation switch).
    lineage_enabled: bool = True
    memo: dict = field(default_factory=dict, repr=False)

    # populated in __post_init__
    n_claims: int = 0
    by_type: Counter = field(default_factory=Counter)
    n_logon_success: int = 0
    n_logon_fail: int = 0
    n_remote_logon: int = 0
    invalidated_hosts: dict[str, str] = field(default_factory=dict)
    first_support_time: str | None = None

    def __post_init__(self) -> None:
        self.n_claims = len(self.claims)
        self.by_type = Counter(c.claim_type for c in self.claims)
        for c in self.claims:
            if c.claim_type == "logon_success":
                self.n_logon_success += 1
                if c.facts.get("is_remote"):
                    self.n_remote_logon += 1
            elif c.claim_type == "logon_failure":
                self.n_logon_fail += 1
            elif c.claim_type == "process_create" and c.facts.get("action") in (
                    "remote_share_mount", "remote_service_control", "remote_wmi",
                    "remote_process_create"):
                # Earliest attack-relevant host action; used to decide whether a
                # log clear could plausibly have destroyed corroborating evidence.
                t = c.time or ""
                if t and (self.first_support_time is None or t < self.first_support_time):
                    self.first_support_time = t
            elif c.claim_type == "audit_log_cleared":
                host = str(c.facts.get("host", "-"))
                self.invalidated_hosts[host] = c.time or ""

    # ---------------------------------------------------------------- rates

    @property
    def logon_total(self) -> int:
        return self.n_logon_success + self.n_logon_fail

    def failure_ratio(self) -> float:
        """Failed logons as a share of all logon activity in THIS capture."""
        return self.n_logon_fail / self.logon_total if self.logon_total else 0.0

    def rate(self, claim_type: str) -> float:
        """Share of this capture's claims that are of the given type."""
        return self.by_type.get(claim_type, 0) / self.n_claims if self.n_claims else 0.0

    def anomaly(self, n: int, floor: int = 3, saturate: int = 25) -> float:
        """Volume -> 0..1, saturating. Deliberately NOT a hard threshold: v1's
        `>= 3` cliff is exactly what made three mistyped passwords decisive."""
        if n < floor:
            return 0.0
        return min(1.0, (n - floor + 1) / (saturate - floor + 1))

    @property
    def graph(self):
        """ProcessGraph, or None when disabled or when no claim carries lineage."""
        if not self.lineage_enabled:
            return None
        if "graph" not in self.memo:
            from argus.reason.lineage import ProcessGraph
            self.memo["graph"] = ProcessGraph.from_claims(self.claims)
        return self.memo["graph"]

    def observability(self, sensor_id: str) -> float:
        h = self.health.get(sensor_id)
        return h.observability() if h else 1.0

    def is_blind_to(self, sensor_id: str, target: str) -> bool:
        h = self.health.get(sensor_id)
        if not h:
            return False
        return any(target.startswith(b.rstrip("0/")) or b in target for b in h.blind_to)
