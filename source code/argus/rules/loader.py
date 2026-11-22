"""Load JSON rules as ordinary ARGUS hypotheses.

A rule becomes a `Hypothesis` whose indicators' matchers run the rule interpreter, so the
engine scores it exactly like a hand-written hypothesis: same weights, required gating,
control discount, defeaters, coverage and episodes. Rules are validated before they load,
and a rule that fails validation never reaches the engine.
"""
from __future__ import annotations

import json
from pathlib import Path

from argus.reason.hypotheses import Expected, Hypothesis, Indicator
from argus.rules.dsl import eval_indicator, validate



class RuleError(ValueError):
    pass


def _read(src) -> list[dict]:
    if isinstance(src, dict):
        return src.get("rules", [src])
    if isinstance(src, (str, Path)):
        return _read(json.loads(Path(src).read_text()))
    return list(src)


def load_rules(*sources) -> list[dict]:
    """Rules from files, dicts or lists, validated as one set (chains may reference any
    rule in the set). Raises RuleError naming every invalid rule."""
    rules: list[dict] = []
    for s in sources:
        rules += _read(s)
    by_id: dict[str, dict] = {}
    errors = []
    for r in rules:
        rid = r.get("id")
        if rid in by_id:
            errors.append(f"duplicate rule id {rid!r}")
        by_id[rid] = r
    for r in rules:
        errors += [f"{r.get('id')}: {e}" for e in validate(r, by_id)]
    if errors:
        raise RuleError("; ".join(errors))
    return rules


def _matcher(ind: dict, stage_fns):
    def match(claims, ctx):
        return eval_indicator(ind, claims, ctx, stage_fns)
    return match


def to_hypotheses(rules: list[dict]) -> list[Hypothesis]:
    by_id = {r["id"]: r for r in rules}
    cache: dict[tuple, object] = {}

    def fn(rid: str, i: int):
        key = (rid, i)
        if key not in cache:
            ind = by_id[rid]["indicators"][i]
            cache[key] = _matcher(ind, _stages(ind))
        return cache[key]

    def _stages(ind: dict):
        ch = ind.get("chain")
        if not ch:
            return None
        return [(s["name"], fn(s["rule"], int(s.get("indicator", 0)))) for s in ch["stages"]]

    out = []
    for r in rules:
        inds = [Indicator(ind["name"], float(ind.get("weight", 1.0)), fn(r["id"], i),
                          required=bool(ind.get("required")))
                for i, ind in enumerate(r["indicators"])]
        exp = [Expected(e["sensor_id"], e["claim_type"], e["description"], e.get("target_hint", ""))
               for e in r.get("expected") or []]
        out.append(Hypothesis(technique=r["technique"], name=r["name"], tactic=r.get("tactic", ""),
                              indicators=inds, expected=exp, severity=float(r.get("severity", 0.9)),
                              rule_id=r["id"]))
    return out
