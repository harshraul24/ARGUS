"""Analyst feedback and rule memory (S3 §4 levels 1–2, build step 5).

The checks are label-free, and they can only promote what an independent non-LLM source
confirms (S3 §12). A correct rule for behaviour no hand-written rule watches therefore
waits in shadow (S3 §13). An analyst's verdicts are the second kind of independent
evidence, used the way detection teams use them:

  verdicts      an analyst reviews one alert (rule, capture) and says malicious or benign;
                each rule's precision is estimated from its verdicts (Beta(1, 1) prior)
  what to ask   analyst time is the budget, so ARGUS asks about the alert whose answer is
                worth most: the one most likely to complete a promote/retire decision, on
                the rule whose promotion would change the most decisions (it fires on
                captures ARGUS currently calls benign). Random choice is the baseline
  lifecycle     shadow -> active when the evidence says the rule is right
                (mean >= promote_mean and a lower bound >= promote_lower, >= min_n verdicts);
                shadow or active -> retired when it says the rule is wrong. Every
                transition records the verdict counts behind it
  memory        what the library has learned — rules confirmed, rules rejected and why,
                rules analysts retired — rendered for the next prompt (§4 level 1), so the
                model does not repeat a known mistake

Verdicts are the only labels this module sees, and in evaluation they come from a
simulated analyst on the DESIGN period only (tools/rules_step5.py).
"""
from __future__ import annotations

import math
import random
from collections import Counter
from dataclasses import asdict, dataclass, field


@dataclass
class Verdict:
    rule_id: str
    capture: str
    verdict: str                     # "malicious" | "benign"
    events: int = 0
    note: str = ""


def _wilson_lower(k: int, n: int, z: float = 1.96) -> float:
    if not n:
        return 0.0
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return max(0.0, c - h)


@dataclass
class FeedbackStore:
    verdicts: list[Verdict] = field(default_factory=list)

    def add(self, v: Verdict) -> None:
        self.verdicts.append(v)

    def asked(self) -> set[tuple[str, str]]:
        return {(v.rule_id, v.capture) for v in self.verdicts}

    def counts(self, rule_id: str) -> tuple[int, int]:
        tp = sum(1 for v in self.verdicts if v.rule_id == rule_id and v.verdict == "malicious")
        fp = sum(1 for v in self.verdicts if v.rule_id == rule_id and v.verdict == "benign")
        return tp, fp

    def precision(self, rule_id: str) -> dict:
        """Posterior mean under Beta(1, 1), its variance, and a Wilson lower bound."""
        tp, fp = self.counts(rule_id)
        a, b = tp + 1, fp + 1
        mean = a / (a + b)
        var = a * b / ((a + b) ** 2 * (a + b + 1))
        return {"tp": tp, "fp": fp, "n": tp + fp, "mean": round(mean, 4),
                "var": var, "lower": round(_wilson_lower(tp, tp + fp), 4)}

    def to_dict(self) -> dict:
        return {"verdicts": [asdict(v) for v in self.verdicts]}


# ============================================================ what to ask

def _decided(tp: int, fp: int, policy: "Policy", can_promote: bool, total: int | None = None) -> bool:
    n = tp + fp
    # approval mode (S3 §5): every alert the rule raised in the period reviewed and confirmed
    if can_promote and total is not None and n == total and n >= 1 and fp == 0:
        return True
    if n < policy.min_n:
        return False
    mean = (tp + 1) / (n + 2)
    if mean <= policy.retire_mean:
        return True
    return can_promote and mean >= policy.promote_mean and _wilson_lower(tp, n) >= policy.promote_lower


def move_rate(tp: int, fp: int, policy: "Policy", can_promote: bool = True,
              total: int | None = None) -> float:
    """Expected lifecycle moves per verdict on this rule: the predictive probability (Beta
    posterior) that the next k verdicts promote or retire it, divided by k, where k is the
    fewest verdicts that could. 0 for a rule already decided. Pure uncertainty sampling
    spreads a budget one verdict per rule and decides nothing (S3 §14); this concentrates
    verdicts where they complete a decision."""
    if _decided(tp, fp, policy, can_promote, total):
        return 0.0
    k = max(1, policy.min_n - (tp + fp))
    if total is not None:
        k = max(1, min(k, total - (tp + fp)))
    hit = 0.0

    def walk(t, f, depth, p):
        nonlocal hit
        if total is not None and t + f > total:
            return
        if _decided(t, f, policy, can_promote, total):
            hit += p
            return
        if depth == k:
            return
        m = (t + 1) / (t + f + 2)
        walk(t + 1, f, depth + 1, p * m)
        walk(t, f + 1, depth + 1, p * (1 - m))

    walk(tp, fp, 0, 1.0)
    return hit / k


def next_query(alerts: dict[str, dict[str, set]], store: FeedbackStore,
               benign_now: set[str], strategy: str = "value", rng: random.Random | None = None,
               active: set[str] | None = None, policy: "Policy | None" = None):
    """The (rule, capture) alert to show the analyst next, or None.

    `alerts`: rule -> capture -> events the rule fires on. `benign_now`: captures ARGUS
    currently decides benign. `active`: rules already active (only retirement moves them).
    value   argmax of move_rate(rule) × impact(rule) × local(capture). impact = 1 + the
            benign-now captures the rule fires on (the decisions its promotion would
            change); local = 1.0 for a benign-now capture, 0.5 otherwise. Ties by id
    random  uniformly among the alerts not yet asked about (the baseline)"""
    asked = store.asked()
    pool = [(r, c) for r, caps in sorted(alerts.items()) for c in sorted(caps) if (r, c) not in asked]
    if not pool:
        return None
    if strategy == "random":
        return (rng or random.Random(7)).choice(pool)
    policy, active = policy or Policy(), active or set()
    rate = {r: move_rate(*store.counts(r), policy, r not in active, len(alerts[r])) for r in alerts}
    impact = {r: 1 + len(set(caps) & benign_now) for r, caps in alerts.items()}
    best = max(pool, key=lambda rc: (rate[rc[0]] * impact[rc[0]] * (1.0 if rc[1] in benign_now else 0.5),
                                     rc[0], rc[1]))
    return best if rate[best[0]] > 0 else None


# ============================================================ lifecycle

@dataclass
class Policy:
    promote_mean: float = 0.75
    promote_lower: float = 0.34      # Wilson lower bound; 2/2 malicious gives 0.34
    retire_mean: float = 0.40
    min_n: int = 2


def apply(library, store: FeedbackStore, policy: Policy | None = None,
          totals: dict[str, int] | None = None) -> list[tuple[str, str, str]]:
    """Promote or retire LLM rules on their verdicts. `totals`: alerts each rule raised in
    the review period (for approval on complete review). Returns (uid, to, reason)."""
    policy, totals = policy or Policy(), totals or {}
    moves = []
    for e in sorted(library.by_status("shadow", "active"), key=lambda e: e.uid):
        p = store.precision(e.uid)
        total = totals.get(e.uid)
        complete = total is not None and p["n"] == total and p["n"] >= 1
        if p["n"] < policy.min_n and not complete:
            continue
        why = (f"analyst verdicts {p['tp']} malicious / {p['fp']} benign (mean {p['mean']:.2f}, "
               f"lower {p['lower']:.2f}" + (f"; all {total} alert(s) reviewed)" if complete else ")"))
        if p["n"] >= policy.min_n and p["mean"] <= policy.retire_mean:
            library.transition(e.uid, "retired", "analyst: " + why)
            moves.append((e.uid, "retired", why))
        elif e.status == "shadow" and (
                (complete and p["fp"] == 0) or
                (p["n"] >= policy.min_n and p["mean"] >= policy.promote_mean and p["lower"] >= policy.promote_lower)):
            library.confirm_by_analyst(e.uid, "analyst-approved: " + why)     # a C5 pass
            moves.append((e.uid, "active", why))
        elif complete and p["tp"] == 0:
            library.transition(e.uid, "retired", "analyst: " + why)
            moves.append((e.uid, "retired", why))
    return moves


# ============================================================ memory for the next prompt

def _behaviour(rule: dict) -> str:
    import json
    return " · ".join(json.dumps(i.get("select"), ensure_ascii=False)[:160]
                      for i in rule.get("indicators") or [])


def memory(library, store: FeedbackStore | None = None, max_each: int = 6) -> str:
    """What earlier rules on this host taught, for the next prompt. Only outcomes the
    system observed (checks, promotions, analyst verdicts) — never ground truth."""
    confirmed, retired, reasons = [], [], Counter()
    examples: dict[str, str] = {}
    for e in sorted(library.entries.values(), key=lambda e: e.uid):
        last = e.history[-1]["reason"]
        if e.status == "active":
            confirmed.append(f"- {e.rule.get('name')}: {_behaviour(e.rule)}")
        elif e.status == "retired" and last.startswith("analyst"):
            retired.append(f"- {e.rule.get('name')} ({last.split(': ', 1)[-1]})")
        elif (e.status == "rejected" and not last.startswith("repaired")) or \
                (e.status == "retired" and last.startswith("C3")):
            key = last.split(":")[0]
            if key in ("C4_quiet", "C4_rare_history"):          # the name before A3, same check
                key = "C4: fired on too many of this host's captures (routine activity or too-short tokens)"
            elif key.startswith("C3_robust"):
                key = "C3: keyed on a name the attacker chose (" + last.split("when ")[-1][:70] + ")"
            elif key == "C2_own_evidence":
                key = "C2: did not fire on its own episode"
            reasons[key] += 1
            examples.setdefault(key, e.rule.get("name", ""))
        elif e.status == "shadow" and "only LLM rules agree" in last:
            reasons["confirmed only by other LLM rules (not promoted)"] += 1
            examples.setdefault("confirmed only by other LLM rules (not promoted)", e.rule.get("name", ""))
    parts = []
    if confirmed:
        parts.append("Rules confirmed on this host (do not rewrite these; describe other behaviour):\n"
                     + "\n".join(confirmed[:max_each]))
    if retired:
        parts.append("Rules an analyst retired as routine activity (avoid similar rules):\n"
                     + "\n".join(retired[:max_each]))
    if reasons:
        parts.append("Most common reasons earlier rules failed:\n" + "\n".join(
            f"- {k}: {n} rule(s), e.g. \"{examples[k]}\"" for k, n in reasons.most_common(max_each)))
    return "\n\n".join(parts)
