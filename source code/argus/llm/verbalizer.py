"""Analyst-facing explanation — template-first.

Fix for shortcoming S6: if faithfulness is checked by an NLI model, the check is
itself an unverified model, and you have circular trust in exactly the component
whose trustworthiness is the point.

So the explanation is generated from the decision graph by deterministic templates
and is therefore correct by construction. An LLM may be used to improve register
and flow, but it is given ONLY the template sentences, and any sentence it returns
that is not traceable to a template sentence is discarded. Content never originates
with the model.
"""
from __future__ import annotations

import json
from dataclasses import dataclass, field
from difflib import SequenceMatcher

from argus.llm.client import LLMClient
from argus.models import Decision, DefeaterKind

DISPOSITION_SENTENCE = {
    "malicious": "Assessed malicious: {name} ({technique}), confidence {score:.2f}.",
    "suspicious": "Assessed suspicious: {name} ({technique}), confidence {score:.2f}.",
    "undecidable": "Could not be decided from the available evidence.",
    "benign": "No supported attack hypothesis. Assessed benign.",
}

DEFEATER_SENTENCE = {
    DefeaterKind.UNDERCUT: "Absence of evidence here is uninformative: {reason}",
    DefeaterKind.REBUT: "Counter-evidence: {reason}",
    DefeaterKind.UNDERMINE: "Premise trust reduced: {reason}",
}


@dataclass
class Explanation:
    sentences: list[str] = field(default_factory=list)
    polished: str | None = None
    dropped: list[str] = field(default_factory=list)
    provider: str | None = None

    @property
    def text(self) -> str:
        return self.polished or "\n".join(self.sentences)


def render(decision: Decision) -> Explanation:
    """Deterministic. Every sentence is generated from a node of the decision."""
    ex = Explanation()
    top = decision.top if (decision.top and decision.top.score > 0) else None

    d = decision.disposition.value
    if top and d in ("malicious", "suspicious"):
        ex.sentences.append(DISPOSITION_SENTENCE[d].format(
            name=top.name, technique=top.technique, score=top.score))
    else:
        ex.sentences.append(DISPOSITION_SENTENCE[d])

    if top:
        for r in top.rationale:
            ex.sentences.append(f"Supporting: {r}.")
        for df in top.defeaters:
            ex.sentences.append(DEFEATER_SENTENCE[df.kind].format(reason=df.reason))

    others = [h for h in decision.hypotheses if h.score > 0 and h is not top]
    for h in others:
        ex.sentences.append(
            f"Also present: {h.name} ({h.technique}) at confidence {h.score:.2f}.")

    if decision.blind_spots:
        ex.sentences.append(
            f"The following evidence was unavailable rather than absent "
            f"({len(decision.blind_spots)} item(s)):")
        for b in decision.blind_spots:
            ex.sentences.append(f"  - {b}")

    for a in decision.next_actions:
        ex.sentences.append(f"Next action: {a}")
    for n in decision.notes:
        ex.sentences.append(f"Note: {n}")

    ex.sentences.append(
        f"Considered {decision.claims_considered} of {decision.claims_total} claims.")
    return ex


POLISH_PROMPT = """Rewrite these analyst notes so they read as fluent prose.

HARD CONSTRAINTS:
- Do NOT add any fact, number, hostname, technique or judgement not present below.
- Do NOT remove any sentence's meaning.
- Do NOT change any number or identifier.
- You may reorder, join and adjust wording only.

NOTES:
{sentences}

Return JSON: {{"sentences": ["...", "..."]}} with one entry per input sentence."""


def polish(ex: Explanation, client: LLMClient, threshold: float = 0.55) -> Explanation:
    """Optional. Every returned sentence must trace to a template sentence.

    Traceability is measured by string similarity against the source sentences —
    a deterministic check, not another model. Sentences that do not trace are
    dropped, so the model can improve phrasing but cannot introduce content.
    """
    if not ex.sentences:
        return ex
    resp = client.complete(POLISH_PROMPT.format(sentences="\n".join(ex.sentences)))
    try:
        got = json.loads(resp.text).get("sentences") or []
    except json.JSONDecodeError:
        ex.provider = client.provider
        return ex

    kept: list[str] = []
    for s in got:
        s = str(s).strip()
        if not s:
            continue
        best = max((SequenceMatcher(None, s.lower(), o.lower()).ratio()
                    for o in ex.sentences), default=0.0)
        (kept if best >= threshold else ex.dropped).append(s)

    ex.polished = "\n".join(kept) if kept else None
    ex.provider = client.provider
    return ex
