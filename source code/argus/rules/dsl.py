"""ARGUS rules as data — interpreter and validator (S3 step 1, S3_DESIGN.md §6).

A rule is JSON: indicators made of a `select` clause, optional `exclude`/`versus`
clauses, groupings, aggregates and a saturating score. Nothing is `eval`'d; every
operator comes from a fixed table below, and `validate()` rejects anything outside it.
Hand-written, LLM-written and imported rules all use this one format and load as
ordinary ARGUS `Hypothesis` objects (`argus.rules.loader`), so the engine — defeaters,
coverage, lineage, explanations — treats them identically.

Adapted from Odin's rule language (`odin/dsl.py`) to run on ARGUS `Claim`s. Additions:

  contains_any       substring tokens on the lower-cased text
  truthy             bool(value)
  categories         named clauses; `distinct_categories` counts how many matched
  affine scorer      min(1, intercept + slope·(v − offset)), 0 below `floor`
  sum `default`      a missing or zero count counts as `default` (`count or 1`)
  multi-valued field provenance.sensor_id matches if any provenance matches
  baseline fields    baseline.image_seen / baseline.lineage_seen: counts in the host's
                     benign baseline (P3); None when there is no baseline
  chain              an indicator made of other rules' indicators, scored as a kill
                     chain; scope `episode` requires one process-tree root (S2)
  behaviour.tactics  ATT&CK tactics the Sigma community associates with the performing
                     Linux program (argus.normalize.behaviour); None without a vocabulary
  lineage fields     lineage.user_writable / parent_user_writable / ancestor_user_writable:
                     whether the performing process, its parent, or any ancestor runs
                     from a folder a user can write (S3 step 3). They read where a
                     program runs, never its name, so they survive renaming
"""
from __future__ import annotations

import re
from functools import lru_cache
from datetime import datetime
from typing import Any, Callable

# ============================================================ field access

TOP_FIELDS = {"claim_type", "modality", "entity", "event", "time", "claim_id"}
LINEAGE_FIELDS = {"lineage.user_writable", "lineage.parent_user_writable",
                  "lineage.ancestor_user_writable"}
BEHAVIOUR_FIELDS = {"behaviour.tactics"}
SPECIAL_FIELDS = {"provenance.sensor_id", "baseline.image_seen",
                  "baseline.lineage_seen"} | LINEAGE_FIELDS | BEHAVIOUR_FIELDS


class Multi(tuple):
    """A multi-valued field: a predicate holds if it holds for any value."""


def _baseline() -> dict:
    from argus.reason import hypotheses as H          # the same cache P3 and the tools use
    return H._baseline()


def _lineage(claim, path: str, ctx) -> Any:
    """Process-tree facts about the process that performed `claim` (S3 step 3). They read
    the folder an executable runs from, never its name, so renaming an implant does not
    change them. None without a process graph (no lineage, or lineage switched off)."""
    g = getattr(ctx, "graph", None) if getattr(ctx, "lineage_enabled", False) else None
    chains = claim.facts.get("_procs") or []
    if g is None or not chains or not chains[0]:
        return None
    anc = g.ancestry(chains[0][0])
    if path == "lineage.user_writable":
        return g.writable(anc[0])
    if path == "lineage.parent_user_writable":
        return g.writable(anc[1]) if len(anc) > 1 else None
    return any(g.writable(a) for a in anc[1:])       # lineage.ancestor_user_writable


def get(claim, path: str, ctx=None) -> Any:
    if path in LINEAGE_FIELDS:
        return _lineage(claim, path, ctx)
    if path in BEHAVIOUR_FIELDS:
        from argus.normalize.behaviour import tactics
        t = tactics(claim)
        return None if t is None else Multi(t)
    if path in TOP_FIELDS:
        return getattr(claim, path)
    if path.startswith("facts."):
        return claim.facts.get(path[6:])
    if path == "provenance.sensor_id":
        return Multi(str(p.sensor_id) for p in claim.provenance)
    if path in ("baseline.image_seen", "baseline.lineage_seen"):
        b = _baseline()
        images = b.get("images", {})
        if not images:
            return None                               # no baseline: nothing is novel
        img = str(claim.facts.get("image") or "").lower()
        if path == "baseline.image_seen":
            return images.get(img, 0)
        par = str(claim.facts.get("parent") or "").lower()
        return b.get("pairs", {}).get(f"{par}>{img}", 0)
    raise KeyError(f"unknown field path {path!r}")


def valid_path(path: str) -> bool:
    return path in TOP_FIELDS or path in SPECIAL_FIELDS or (
        isinstance(path, str) and path.startswith("facts.") and len(path) > 6)


# ============================================================ predicates

def _num(x) -> float:
    try:
        return float(x)
    except (TypeError, ValueError):
        return float("nan")


def _contains_any(v, arg, ctx) -> bool:
    tokens = tuple(str(t).lower() for t in (arg if isinstance(arg, list) else [arg]))
    text = str(v or "").lower()
    return any(t in text for t in tokens)


@lru_cache(maxsize=None)
def _rx(pattern: str):
    """Compiled once per pattern: imported rule sets (Sigma) hold thousands of patterns,
    beyond `re`'s own 512-entry cache. Matching is unchanged."""
    return re.compile(pattern)


def _in(v, arg):
    return v in arg if isinstance(arg, list) else v == arg


PREDICATES: dict[str, Callable] = {
    "eq": lambda v, a: v == a,
    "ne": lambda v, a: v != a,
    "in": _in,
    "not_in": lambda v, a: not _in(v, a),
    "gt": lambda v, a: v is not None and _num(v) > _num(a),
    "gte": lambda v, a: v is not None and _num(v) >= _num(a),
    "lt": lambda v, a: v is not None and _num(v) < _num(a),
    "lte": lambda v, a: v is not None and _num(v) <= _num(a),
    "exists": lambda v, a: (v is not None) == bool(a),
    "truthy": lambda v, a: bool(v) == bool(a),
    "prefix": lambda v, a: isinstance(v, str) and v.startswith(tuple(a) if isinstance(a, list) else a),
    "suffix": lambda v, a: isinstance(v, str) and v.endswith(tuple(a) if isinstance(a, list) else a),
    "regex": lambda v, a: isinstance(v, str) and _rx(a).search(v) is not None,
    "contains_any": None,           # needs the case context; handled in _test
}

COMBINATORS = ("any_of", "all_of", "none_of")
# An LLM writing JSON reaches for and/or/not unprompted; they map onto the same closed
# combinators (Odin's first live run lost 3 of 3 rules to this).
COMB_ALIASES = {"and": "all_of", "or": "any_of", "not": "none_of",
                "allOf": "all_of", "anyOf": "any_of", "noneOf": "none_of"}


def _combinator(key: str) -> str | None:
    return key if key in COMBINATORS else COMB_ALIASES.get(key)


def _as_predicate(spec: dict) -> dict | None:
    if "op" in spec:
        return {"op": spec["op"], "value": spec.get("value")}
    if len(spec) == 1:
        (k, v), = spec.items()
        if k in PREDICATES:
            return {"op": k, "value": v}
    return None


def _test(v, spec, ctx) -> bool:
    if isinstance(v, Multi):
        return any(_test(x, spec, ctx) for x in v)
    if isinstance(spec, dict):
        for key in spec:
            comb = _combinator(key)
            if comb:
                subs = [_test(v, s, ctx) for s in spec[key]]
                return (all(subs) if comb == "all_of" else
                        any(subs) if comb == "any_of" else not any(subs))
        p = _as_predicate(spec)
        if p is None or p["op"] not in PREDICATES:
            return False
        if p["op"] == "contains_any":
            return _contains_any(v, p["value"], ctx)
        return bool(PREDICATES[p["op"]](v, p["value"]))
    if isinstance(spec, list):
        return v in spec
    return v == spec


def match(claim, clause: dict, ctx=None) -> bool:
    """A clause is {field_path: spec}, ANDed; combinator keys hold lists of clauses."""
    for path, spec in (clause or {}).items():
        comb = _combinator(path)
        if comb:
            subs = [match(claim, c, ctx) for c in spec]
            ok = (all(subs) if comb == "all_of" else
                  any(subs) if comb == "any_of" else not any(subs))
            if not ok:
                return False
            continue
        try:
            v = get(claim, path, ctx)
        except KeyError:
            return False
        if not _test(v, spec, ctx):
            return False
    return True


# ============================================================ aggregates

def _epoch(t) -> float | None:
    try:
        return datetime.fromisoformat(str(t)).timestamp()
    except (TypeError, ValueError):
        return None


def _a_sum(rows, a, ctx):
    d = a.get("default")
    tot = 0.0
    for c in rows:
        v = get(c, a["field"], ctx)
        if d is not None and not v:
            v = d
        if _num(v) == _num(v):                        # skip NaN
            tot += _num(v)
    return tot


def _vals(rows, a, ctx=None):
    return [x for x in (_num(get(c, a["field"], ctx)) for c in rows) if x == x]


AGGREGATES: dict[str, Callable] = {
    "count": lambda rows, a, ctx: float(len(rows)),
    "distinct": lambda rows, a, ctx: float(len({v for v in (get(c, a["field"], ctx) for c in rows)
                                                if v is not None})),
    "sum": _a_sum,
    "max": lambda rows, a, ctx: max(_vals(rows, a, ctx), default=0.0),
    "min": lambda rows, a, ctx: min(_vals(rows, a, ctx), default=0.0),
    "timespan": lambda rows, a, ctx: (lambda ts: max(ts) - min(ts) if len(ts) > 1 else 0.0)(
        [t for t in (_epoch(c.time) for c in rows) if t is not None]),
    "distinct_categories": None,                     # computed from categories in eval
}
NEEDS_FIELD = {"distinct", "sum", "max", "min"}


# ============================================================ scorers

def _s_saturate(v, s):
    floor, ceil = float(s.get("floor", 3)), float(s.get("ceiling", 25))
    if v < floor:
        return 0.0
    if ceil <= floor:
        return 1.0
    return min(1.0, (v - floor + 1.0) / (ceil - floor + 1.0))


def _s_linear(v, s):
    if v < float(s.get("floor", 0)):
        return 0.0
    return max(0.0, min(1.0, v / (float(s.get("over", 1)) or 1.0)))


def _s_affine(v, s):
    if v < float(s.get("floor", 1)):
        return 0.0
    return max(0.0, min(1.0, float(s.get("intercept", 0)) +
                        float(s.get("slope", 0)) * (v - float(s.get("offset", 0)))))


SCORERS: dict[str, Callable] = {
    "saturate": _s_saturate, "linear": _s_linear, "affine": _s_affine,
    "threshold": lambda v, s: 1.0 if v >= float(s.get("at", 1)) else 0.0,
    "ratio": lambda v, s: max(0.0, min(1.0, v)),
    "absent": lambda v, s: 1.0 if v <= float(s.get("at", 0)) else 0.0,
}


def _case_metric(name: str, ctx) -> float:
    if name == "case.failure_ratio":
        return ctx.failure_ratio()
    if name == "case.total_claims":
        return float(ctx.n_claims)
    if name.startswith("case.rate."):
        return ctx.rate(name[len("case.rate."):])
    raise KeyError(f"unknown case metric {name!r}")


# ============================================================ evaluation

def _group_key(c, keys, ctx=None) -> tuple:
    out = []
    for k in keys:
        if isinstance(k, dict):
            v = get(c, k["field"], ctx)
            out.append(str(v or "").lower() if k.get("lower") else v)
        else:
            out.append(get(c, k, ctx))
    return tuple(out)


def eval_indicator(ind: dict, claims: list, ctx, stage_fns=None) -> tuple[list, float]:
    """(hits, strength) — the ARGUS matcher contract."""
    if "chain" in ind:
        return _eval_chain(ind["chain"], claims, ctx, stage_fns or [])
    rows = [c for c in claims if match(c, ind.get("select", {}), ctx)
            and not (ind.get("exclude") and match(c, ind["exclude"], ctx))]
    cats = ind.get("categories")
    cat_of: dict[str, list[str]] = {}
    if cats:
        kept = []
        for c in rows:
            names = [n for n, cl in cats.items() if match(c, cl, ctx)]
            if names:
                kept.append(c)
                cat_of[c.claim_id] = names
        rows = kept
    versus = [c for c in claims if match(c, ind["versus"], ctx)] if "versus" in ind else None

    keys = ind.get("group_by") or []
    groups: dict[tuple, list] = {}
    if keys:
        for c in rows:
            groups.setdefault(_group_key(c, keys, ctx), []).append(c)
    else:
        groups[()] = rows

    spec = ind.get("score") or {"op": "threshold", "value": "n", "at": 1}
    best, best_hits = 0.0, []
    for key, grp in groups.items():
        if not grp and keys:
            continue
        aggs: dict[str, float] = {}
        for a in ind.get("aggregate") or [{"as": "n", "op": "count"}]:
            src = grp
            if a.get("from") == "versus":
                src = [c for c in (versus or []) if not keys or _group_key(c, keys, ctx) == key]
            if a["op"] == "distinct_categories":
                aggs[a["as"]] = float(len({n for c in src for n in cat_of.get(c.claim_id, ())}))
            else:
                aggs[a["as"]] = AGGREGATES[a["op"]](src, a, ctx)
        aggs.setdefault("n", float(len(grp)))

        def value(name):
            return _case_metric(name, ctx) if str(name).startswith("case.") else aggs[name]

        strength = SCORERS[spec.get("op", "threshold")](value(spec.get("value", "n")), spec)
        for mod in spec.get("modulate") or []:
            m = value(mod["value"])
            if mod.get("op"):
                m = SCORERS[mod["op"]](m, mod)
            w = float(mod.get("weight", 1.0))
            strength *= (1.0 - w) + w * max(0.0, min(1.0, m))
        strength = max(0.0, min(1.0, strength))
        if strength > best:
            best, best_hits = strength, grp
    return list(best_hits), best


def _eval_chain(ch: dict, claims: list, ctx, stage_fns) -> tuple[list, float]:
    """Kill-chain composition of other rules' indicators (P2 + S2 lineage)."""
    stages = list(stage_fns)
    scope = claims
    if ch.get("scope", "episode") == "episode" and getattr(ctx, "graph", None) is not None:
        from argus.reason.lineage import find_episode
        key = ("episode", id(claims), tuple(n for n, _ in stages))
        if key not in ctx.memo:
            ctx.memo[key] = find_episode(stages, claims, ctx)
        ep = ctx.memo[key]
        if ep is None:
            return [], 0.0
        ctx.memo["episode"] = ep
        scope = ep.claims
    fired: dict[str, str | None] = {}
    all_hits = []
    for name, fn in stages:
        hits, s = fn(scope, ctx)
        if s > 0.0 and hits:
            fired[name] = min((c.time for c in hits if c.time), default=None)
            all_hits.extend(hits)
    n = len(fired)
    if n < int(ch.get("min_stages", 2)):
        return [], 0.0
    sc = ch.get("score") or {}
    base = min(1.0, (n - float(sc.get("offset", 1))) / float(sc.get("over", 3.0)))
    ob = ch.get("order_bonus") or {}
    early = [fired[k] for k in ob.get("early", []) if fired.get(k)]
    obj = [fired[k] for k in ob.get("objective", []) if fired.get(k)]
    if early and obj and min(early) <= min(obj):
        base = min(1.0, base + float(ob.get("bonus", 0.0)))
    seen, dedup = set(), []
    for c in all_hits:
        if c.claim_id not in seen:
            seen.add(c.claim_id)
            dedup.append(c)
    return dedup, base


# ============================================================ validation

def validate(rule: dict, known_rules: dict | None = None) -> list[str]:
    """Everything the interpreter cannot run safely. Errors name the valid alternatives,
    because an LLM repairs a rule from these messages (Odin §19: one unexplained error
    hid every error beneath it and the repair round could not converge)."""
    errs: list[str] = []
    for k in ("id", "technique", "name", "indicators"):
        if not rule.get(k):
            errs.append(f"missing required key {k!r}")
    if not isinstance(rule.get("indicators"), list) or not rule.get("indicators"):
        return errs + ["indicators must be a non-empty list"]
    if not any(i.get("required") for i in rule["indicators"] if isinstance(i, dict)):
        errs.append("no indicator is marked \"required\": true")
    sev = rule.get("severity", 0.9)
    if not isinstance(sev, (int, float)) or not 0 <= sev <= 1:
        errs.append("severity must be a number in [0, 1]")

    def spec_(spec, where):
        if isinstance(spec, dict):
            for key in spec:
                if _combinator(key):
                    if not isinstance(spec[key], list):
                        errs.append(f"{where}.{key}: must be a list")
                        return
                    for s in spec[key]:
                        spec_(s, f"{where}.{key}")
                    return
            p = _as_predicate(spec)
            if p is None or p["op"] not in PREDICATES:
                errs.append(f"{where}: {sorted(spec)!r} is not a predicate — use "
                            f'{{"<op>": value}} with op in {sorted(PREDICATES)}')
            elif p["op"] == "regex":
                try:
                    re.compile(p["value"])
                except (re.error, TypeError) as exc:
                    errs.append(f"{where}: invalid regex {p['value']!r}: {exc}")

    def clause_(clause, where):
        if not isinstance(clause, dict):
            errs.append(f"{where}: a clause must be an object keyed by field path")
            return
        for path, spec in clause.items():
            if _combinator(path):
                if not isinstance(spec, list):
                    errs.append(f"{where}.{path}: must be a list of clauses")
                    continue
                for j, sub in enumerate(spec):
                    clause_(sub, f"{where}.{path}[{j}]")
                continue
            if not valid_path(path):
                errs.append(f"{where}: unknown field path {path!r} — use {sorted(TOP_FIELDS)}, "
                            f"{sorted(SPECIAL_FIELDS)} or \"facts.<name>\"; combine clauses "
                            f"with {list(COMBINATORS)}")
            spec_(spec, f"{where}.{path}")

    for i, ind in enumerate(rule["indicators"]):
        w = f"indicator[{i}]"
        if not isinstance(ind, dict):
            errs.append(f"{w}: must be an object")
            continue
        if not ind.get("name"):
            errs.append(f"{w}: no name")
        if not isinstance(ind.get("weight", 1.0), (int, float)) or ind.get("weight", 1.0) <= 0:
            errs.append(f"{w}: weight must be a positive number")
        if "chain" in ind:
            ch = ind["chain"]
            stages = ch.get("stages") or []
            if len(stages) < 2:
                errs.append(f"{w}.chain: needs at least two stages")
            for s in stages:
                ref = s.get("rule")
                if known_rules is not None and ref not in known_rules:
                    errs.append(f"{w}.chain: stage {s.get('name')!r} references unknown rule {ref!r}")
                elif known_rules is not None:
                    n_ind = len(known_rules[ref].get("indicators", []))
                    if not 0 <= int(s.get("indicator", 0)) < n_ind:
                        errs.append(f"{w}.chain: stage {s.get('name')!r} indicator out of range")
            if ch.get("scope", "episode") not in ("episode", "window"):
                errs.append(f"{w}.chain: scope must be episode|window")
            continue
        if not ind.get("select"):
            errs.append(f"{w}: no select clause")
        clause_(ind.get("select", {}), f"{w}.select")
        if "exclude" in ind:
            clause_(ind["exclude"], f"{w}.exclude")
        if "versus" in ind:
            clause_(ind["versus"], f"{w}.versus")
        cats = ind.get("categories")
        if cats is not None:
            if not isinstance(cats, dict) or not cats:
                errs.append(f"{w}.categories: must be a non-empty object of named clauses")
            else:
                for n, cl in cats.items():
                    clause_(cl, f"{w}.categories.{n}")
        for k in ind.get("group_by") or []:
            f = k.get("field") if isinstance(k, dict) else k
            if not valid_path(f):
                errs.append(f"{w}.group_by: unknown field path {f!r}")
        names = {"n"}
        for a in ind.get("aggregate") or []:
            op = a.get("op")
            if op not in AGGREGATES:
                errs.append(f"{w}.aggregate: unknown op {op!r} — valid: {sorted(AGGREGATES)}")
            if not a.get("as"):
                errs.append(f"{w}.aggregate: entry has no 'as' name")
            if op in NEEDS_FIELD and not valid_path(a.get("field", "")):
                errs.append(f"{w}.aggregate[{a.get('as')}]: op {op!r} needs a valid 'field'")
            if op == "distinct_categories" and not cats:
                errs.append(f"{w}.aggregate: distinct_categories needs categories")
            if a.get("from") not in (None, "select", "versus"):
                errs.append(f"{w}.aggregate: 'from' must be select|versus")
            names.add(a.get("as"))
        spec = ind.get("score") or {}
        if spec:
            if spec.get("op") not in SCORERS:
                errs.append(f"{w}.score: unknown op {spec.get('op')!r} — valid: {sorted(SCORERS)}")
            for ref in [spec.get("value", "n")] + [m.get("value") for m in spec.get("modulate") or []]:
                if ref is None or (not str(ref).startswith("case.") and ref not in names):
                    errs.append(f"{w}.score: references undefined value {ref!r}")
    for e in rule.get("expected") or []:
        if not (isinstance(e, dict) and e.get("sensor_id") and e.get("claim_type") and e.get("description")):
            errs.append("expected: each entry needs sensor_id, claim_type and description")
    return errs


def grammar() -> dict:
    """The rule language described from the interpreter's own tables (for prompts)."""
    return {"field_paths": sorted(TOP_FIELDS) + sorted(SPECIAL_FIELDS) + ["facts.<name>"],
            "predicates": sorted(PREDICATES), "combinators": list(COMBINATORS),
            "combinator_aliases": COMB_ALIASES, "aggregates": sorted(AGGREGATES),
            "scorers": sorted(SCORERS),
            "case_metrics": ["case.failure_ratio", "case.total_claims", "case.rate.<claim_type>"]}
