"""The reasoner.

Implements the fixes measured in experiments/v1_on_dataset:

W1  Every hypothesis is evaluated against every claim. `claims_considered` must
    equal `claims_total`; v1 left 75% of claims unreachable.
W5  Defeaters are typed (rebut / undercut / undermine) and attached to a specific
    hypothesis. v1's global `network_missing` rule fired 3/3 on benign captures
    and 0/4 on attacks.
W6  Silence counts against a hypothesis only if a healthy, covering sensor stayed
    silent. Ablatable via `Config.enable_coverage` — turning it off is experiment E1.
W7  Multi-label output; several hypotheses can be true at once.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from argus.models import (
    Claim, Control, Decision, Defeater, DefeaterKind, Disposition,
    HypothesisResult, SensorHealth,
)
from argus.collectors.events import gap_text
from argus.reason.context import CaseContext
from argus.reason.hypotheses import HYPOTHESES, Hypothesis


@dataclass
class Config:
    enable_coverage: bool = True     # W6 — the ablation that decides E1
    enable_baseline: bool = True     # W4
    enable_observability: bool = True  # weight absence by measured emission rate
    enable_lineage: bool = True      # W-E — process-tree linking; off = window-level (S1)
    malicious_threshold: float = 0.50
    suspicious_threshold: float = 0.25
    hypotheses: list[Hypothesis] = field(default_factory=lambda: list(HYPOTHESES))
    # S3 lifecycle: rules being measured before they may act. Scored on every case into
    # Decision.shadow; never read by the disposition.
    shadow: list[Hypothesis] = field(default_factory=list)
    # ConfoundGuard: techniques with no discriminative information in this corpus.
    # Reported to the analyst, excluded from the disposition. None = guard disabled.
    confound: object | None = field(default=None, repr=False)
    # Empirical O(sensor, claim_type). Absence weighs what the data says it weighs.
    observability: object | None = field(default=None, repr=False)

    def artifacts(self) -> set[str]:
        return set(getattr(self.confound, "artifact_techniques", set()) or set())

    def as_dict(self) -> dict:
        return {"enable_coverage": self.enable_coverage,
                "enable_baseline": self.enable_baseline,
                "malicious_threshold": self.malicious_threshold,
                "suspicious_threshold": self.suspicious_threshold,
                "confound_artifacts": sorted(self.artifacts()),
                "observability_model": bool(self.observability),
                "enable_observability": self.enable_observability,
                "enable_lineage": self.enable_lineage,
                **({"shadow_rules": len(self.shadow)} if self.shadow else {})}


# ------------------------------------------------------------------ scoring

def _score_hypothesis(h: Hypothesis, claims: list[Claim], ctx: CaseContext,
                      cfg: Config) -> HypothesisResult:
    res = HypothesisResult(technique=h.technique, name=h.name, tactic=h.tactic,
                           rule_id=h.rule_id)

    total_w = sum(i.weight for i in h.indicators)
    got = 0.0
    required_met = True
    support: list[Claim] = []

    # Trust discount applied to a premise the adversary authored. L2 = they chose
    # both that it exists and what it says; L3 = they could also suppress it.
    CONTROL_DISCOUNT = {Control.L0: 1.0, Control.L1: 0.95,
                        Control.L2: 0.85, Control.L3: 0.70}
    undermined: list[tuple[str, Control, list[str]]] = []

    for ind in h.indicators:
        hits, strength = ind.match(claims, ctx)
        if ind.required and strength <= 0.0:
            required_met = False
        if strength > 0.0:
            factor = 1.0
            if hits:
                worst = max((c.control for c in hits),
                            key=lambda c: ["L0", "L1", "L2", "L3"].index(c.value))
                factor = CONTROL_DISCOUNT[worst]
                if factor < 1.0:
                    undermined.append((ind.name, worst,
                                       [c.claim_id for c in hits][:6]))
            got += ind.weight * strength * factor
            support.extend(hits)
            res.rationale.append(
                f"{ind.name}: {len(hits)} claim(s), strength {strength:.2f}"
                + (f" (premise trust x{factor:.2f}, {worst.value})" if factor < 1.0 else ""))

    if not required_met:
        res.score = 0.0
        return res

    raw = got / total_w if total_w else 0.0
    res.support = [c.claim_id for c in support][:40]

    # ---- W5: undermine — one per premise whose trust was discounted ----
    for name, ctrl, ids in undermined:
        res.defeaters.append(Defeater(
            kind=DefeaterKind.UNDERMINE,
            reason=(f"premise '{name}' is adversary-authored ({ctrl.value}) — "
                    f"trust discounted, conclusion not attacked"),
            weight=round(1.0 - CONTROL_DISCOUNT[ctrl], 3),
            claim_ids=ids,
        ))

    # ---- W5 + W6: expected observables that did not appear ----
    present_types = {c.claim_type for c in claims}
    for exp in h.expected:
        if exp.claim_type in present_types:
            continue

        # A sensor with no health record is not in this capture: it could not have spoken,
        # so its silence is not evidence. (Before 2026-11-16 it was read as a working sensor.)
        health = ctx.health.get(exp.sensor_id)
        absent = health is None
        obs = health.observability() if health else 0.0
        blind = bool(health and exp.target_hint and
                     any(exp.target_hint.startswith(b.split("/")[0].rstrip("0."))
                         for b in health.blind_to))
        # A sensor can also be blind to a whole claim type (a window with no connect
        # events). Zeek blind_to entries are address ranges, never claim types, so this
        # cannot fire for them.
        blind_type = bool(health and exp.claim_type in health.blind_to)

        # A cleared log invalidates what came BEFORE the clear. Evidence that would
        # have been written afterwards survives it.
        invalidated = False
        if health and health.invalidated_before and ctx.first_support_time:
            invalidated = str(ctx.first_support_time) < str(health.invalidated_before)

        if cfg.enable_coverage and (obs < 0.9 or blind or blind_type or invalidated):
            why = []
            if absent:
                why.append(f"no {exp.sensor_id} sensor in this capture")
            elif not health.healthy:
                why.append("; ".join(health.notes) or f"{exp.sensor_id} was not working")
            elif obs < 0.9:
                why.append(f"{(1-obs)*100:.1f}% measured loss")
            if blind:
                why.append(f"sensor does not cover {exp.target_hint}")
            if blind_type:
                why.append(f"{exp.sensor_id} recorded no {exp.claim_type} events in this capture")
            if invalidated:
                why.append("log was cleared before the activity")
            res.defeaters.append(Defeater(
                kind=DefeaterKind.UNDERCUT,
                reason=f"absence of {exp.description} is uninformative ({'; '.join(why)})",
                weight=0.0,
            ))
            res.coverage_gaps.append(f"{exp.sensor_id}: {exp.description} — {'; '.join(why)}")
        else:
            # The sensor was able to speak and did not. How much that counts against
            # the hypothesis is the rate at which this sensor actually emits this
            # evidence — measured across the corpus, not asserted.
            rate = 1.0
            if cfg.observability is not None and cfg.enable_observability:
                rate = cfg.observability.rate(exp.sensor_id, exp.claim_type, 1.0)
            penalty = 0.12 * rate
            qual = "" if rate >= 0.9 else f"; emitted in only {rate:.0%} of captures"
            res.defeaters.append(Defeater(
                kind=DefeaterKind.REBUT,
                reason=f"expected {exp.description} from {exp.sensor_id}, none observed{qual}",
                weight=round(penalty, 3),
            ))
            raw -= penalty
            if rate < 0.9:
                res.coverage_gaps.append(
                    f"{exp.sensor_id}: {exp.description} — emitted in only {rate:.0%} of captures")

    res.score = max(0.0, min(1.0, raw))
    return res


# ------------------------------------------------------------------- public

def reason(case_id: str, claims: list[Claim],
           health: dict[str, SensorHealth] | None = None,
           cfg: Config | None = None,
           protocol_artifacts: set[str] | None = None) -> Decision:
    cfg = cfg or Config()
    ctx = CaseContext(claims=claims, health=health or {})
    ctx.lineage_enabled = cfg.enable_lineage

    results = [_score_hypothesis(h, claims, ctx, cfg) for h in cfg.hypotheses]
    # keyed by unique rule id: several data rules may share a technique (S3 §6)
    sev = {h.uid: h.severity for h in cfg.hypotheses}

    artifacts = cfg.artifacts() | set(protocol_artifacts or set())
    scored = sorted((r for r in results if r.score > 0.0),
                    key=lambda r: -(r.score * sev.get(r.rule_id or r.technique, 0.9)))
    # Artifact techniques stay in the output but cannot drive the disposition, and neither
    # can a weak primitive on its own (Hypothesis.decides; lab plan F2 and amendment A2).
    weak = {h.uid for h in cfg.hypotheses if not h.decides}
    context = [r.rule_id or r.technique for r in scored if (r.rule_id or r.technique) in weak]
    deciding = [r for r in scored if r.technique not in artifacts and (r.rule_id or r.technique) not in weak]

    # ---- disposition (W7: keep every hypothesis, pick a disposition) ----
    disposition = Disposition.BENIGN
    top_weighted = 0.0
    if deciding:
        top = deciding[0]
        top_weighted = top.score * sev.get(top.rule_id or top.technique, 0.9)
        if top_weighted >= cfg.malicious_threshold:
            disposition = Disposition.MALICIOUS
        elif top_weighted >= cfg.suspicious_threshold:
            disposition = Disposition.SUSPICIOUS

    # ---- abstention: partial support blocked by a coverage gap is NOT benign ----
    gaps = [g for r in results for g in r.coverage_gaps]
    if disposition == Disposition.BENIGN:
        blocked = [r for r in results
                   if r.coverage_gaps and (r.score > 0.0 or r.support)]
        if blocked:
            disposition = Disposition.UNDECIDABLE

    blind_spots = sorted(set(gaps))
    next_actions: list[str] = []
    for r in results:
        for g in r.coverage_gaps:
            next_actions.append(f"[{r.technique}] recover: {g.split(' — ')[0]}")
    for sid, h in (health or {}).items():
        if h.invalidated_before:
            next_actions.append(
                f"[{sid}] audit log cleared at {h.invalidated_before}; confirm whether authorised")
        # W6 at sensor level: a claim type the sensor is contracted to record but recorded
        # nowhere in this capture is a blind spot whatever the verdict, so a benign verdict
        # never hides it. Address-range entries (Zeek) are hypothesis-relative and are
        # handled per hypothesis above.
        for t in h.blind_to:
            if "/" in t or t[:1].isdigit():
                continue
            blind_spots.append(f"{sid}: recorded no {t} events in this capture")
            next_actions.append(f"[{sid}] confirm {t} collection; its absence here is not evidence")
        # the same for an interval the sensor could not record (stopped daemon, unloaded
        # rule): reported whatever the verdict; what happened inside it is unknown
        for g in h.gaps:
            blind_spots.append(f"{sid}: {gap_text(g)}")
            next_actions.append(f"[{sid}] {g.get('cause', 'sensor gap')} at "
                                f"{str(g['start'])[:19].replace('T', ' ')}; confirm whether authorised")
    blind_spots = sorted(set(blind_spots))

    notes: list[str] = []
    for r in scored:
        if r.technique in artifacts:
            why = ("capture protocol declares log clearing"
                   if r.technique in set(protocol_artifacts or set())
                   else "no discriminative information in this corpus")
            notes.append(f"{r.technique} reported but excluded from disposition "
                         f"(ConfoundGuard: {why})")
    if context:
        notes.append(f"{', '.join(context)} reported as context: a weak primitive never decides "
                     "on its own; it counts as a kill-chain stage")
    if not cfg.enable_coverage:
        notes.append("ABLATION: coverage model disabled — sensor silence treated as counter-evidence")
    if not cfg.enable_lineage:
        notes.append("ABLATION: process lineage disabled — kill chain fused window-wide")

    # W-E: the episode (root process + every claim its subtree performed) is the scope an
    # analyst investigates. It is reported beside the evidence, never merged into it, and
    # only when the case is not benign.
    episodes = []
    ep = ctx.memo.get("episode")
    if ep is not None and disposition in (Disposition.MALICIOUS, Disposition.SUSPICIOUS):
        episodes.append(ep.to_dict())
        notes.append(f"episode: {len(ep.claims)} claim(s) descend from {ep.root_image} "
                     f"({ep.root}), linking {', '.join(ep.stages)}")

    # Shadow rules run last, on the same context, and write nothing the decision reads;
    # the episode memo is restored so a shadow chain cannot change the reported episode.
    shadow = []
    if cfg.shadow:
        kept = ctx.memo.get("episode")
        shadow = [r for r in (_score_hypothesis(h, claims, ctx, cfg) for h in cfg.shadow)
                  if r.score > 0.0]
        shadow.sort(key=lambda r: -r.score)
        ctx.memo["episode"] = kept

    return Decision(
        case_id=case_id,
        disposition=disposition,
        hypotheses=scored or results[:1],
        severity=round(top_weighted, 3),
        priority=round(top_weighted * (1.0 - 0.2 * bool(blind_spots)), 3),
        claims_total=len(claims),
        claims_considered=len(claims),          # W1 — every claim is reachable
        blind_spots=blind_spots,
        next_actions=sorted(set(next_actions))[:8],
        notes=notes,
        config=cfg.as_dict(),
        suppressed=sorted(artifacts),
        context=context,
        episodes=episodes,
        shadow=shadow,
    )
