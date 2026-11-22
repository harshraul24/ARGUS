"""The five label-free checks a written rule must pass (S3_DESIGN.md §3; LAB_EVAL_PLAN.md A3).

`CHECKS` below is the one definition: the code, the library's records, the workbench and the
documents all use its keys, names and questions.

  C1 valid           ARGUS can run the rule as written (dsl.validate)
  C2 own evidence    every literal occurs in the episode it was written from, a required
                     indicator selects something there, and the rule FIRES there (a rule
                     that selects the right events but never scores is dead)
  C3 robust          it still fires on label-free transformed copies of its own evidence:
                     user-writable programs renamed, programs run by full path, created
                     files renamed. The static rename analysis is a risk flag, not a gate
  C4 quiet           it fires on at most `max_rate` of its host's other windows. The history
                     is not assumed benign, only mostly benign
  C5 confirmed       a source that may decide on its own flags the same events: a deciding
                     hand-written rule or a Sigma rule rated medium or higher, either one
                     itself quiet by C4's bar on that host, or the analyst. Agreement with
                     other written rules is recorded, and never confirms

How they fit together:
- **Order.** C1–C3 run on the episode while the rule is written, and their findings are sent
  back to the writer; C4 and C5 run on the host's history afterwards, on survivors only.
- **Reached.** A check that cannot run is not reached and is not recorded: C2 and C3 when
  C1 fails, C3 when the rule never fires, C4 when C1–C3 failed, C5 when C4 failed.
- **Status follows the record.** A rule becomes shadow only with C1–C4 passed and active only
  with C5 passed (library.RuleLibrary.transition enforces it). An analyst's approval is a C5
  pass and is recorded as one (`c5_by_analyst`).

No check reads labels. Literal verification and rename analysis are Odin's `trust.py`
(ARGUS's own verifier idea applied to rules), adapted to ARGUS claims and field names.
"""
from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Any, Iterator

from argus.reason.lineage import ProcessGraph, user_writable
from argus.rules.dsl import PREDICATES, _as_predicate, _combinator, get, match, validate

# ============================================================ attacker control per field

L0, L1, L2, UNCLASSIFIED = "L0", "L1", "L2", "unclassified"
_RANK = {L0: 0, L1: 1, UNCLASSIFIED: 1, L2: 2}
TOP_CONTROL = {"claim_type": L0, "modality": L0, "entity": L1, "event": L2, "time": L0,
               "claim_id": L0, "provenance.sensor_id": L0,
               "baseline.image_seen": L2, "baseline.lineage_seen": L2,
               # the process tree is recorded by the kernel; the folder an executable runs
               # from is the attacker's choice only within what their rights allow
               "lineage.user_writable": L1, "lineage.parent_user_writable": L1,
               "lineage.ancestor_user_writable": L1,
               # looked up by program NAME, which is the attacker's choice for anything they
               # run from a user-writable folder (C3's rename transform exercises this)
               "behaviour.tactics": L2}
# Claim facts (collectors/events.py, linux.py, zeek.py). L0 = sensor-measured; L1 = chosen
# by the attacker from a closed set; L2 = written freely by the attacker (renameable).
FACT_CONTROL = {
    "host": L0, "direction": L0, "audit_key": L0, "syscall": L0, "success": L0, "exit": L0,
    "is_remote": L0, "source_locality": L0, "logon_type": L0,
    "user": L1, "principal": L1, "target_user": L1, "dst_ip": L1, "dst_port": L1,
    "src_ip": L1, "src_port": L1, "protocol": L1,
    "image": L2, "image_path": L2, "parent": L2, "command": L2, "cwd": L2, "file_path": L2,
    "old_path": L2,
}


def control_of(path: str) -> str:
    if path in TOP_CONTROL:
        return TOP_CONTROL[path]
    if path.startswith("facts."):
        return FACT_CONTROL.get(path[6:], UNCLASSIFIED)
    return UNCLASSIFIED


# ============================================================ literal walk

_LITERAL_OPS = {"eq", "in", "prefix", "suffix", "regex", "contains_any"}
_NEGATIVE_OPS = {"ne", "not_in"}


@dataclass
class Literal:
    indicator: str
    clause: str
    path: str
    op: str
    value: Any
    positive: bool
    necessary: bool
    group: int

    def show(self) -> str:
        return f"{self.path} {self.op} {self.value!r}"


def _spec_literals(path, spec, positive, necessary, groups) -> Iterator[tuple]:
    if isinstance(spec, dict):
        for key in spec:
            comb = _combinator(key)
            if comb:
                subs = spec[key] or []
                if comb == "none_of":
                    for s in subs:
                        yield from _spec_literals(path, s, not positive, False, groups)
                elif comb == "any_of" and len(subs) > 1:
                    g = next(groups)
                    for s in subs:
                        for leaf in _spec_literals(path, s, positive, False, groups):
                            yield leaf[:5] + (g if leaf[5] is None else leaf[5],)
                else:
                    for s in subs:
                        yield from _spec_literals(path, s, positive, necessary, groups)
                return
        p = _as_predicate(spec)
        if not p:
            return
        vals = p["value"] if isinstance(p["value"], list) else [p["value"]]
        if p["op"] in _NEGATIVE_OPS:
            for v in vals:
                yield (path, "eq", v, not positive, False, None)
        elif p["op"] in ("in", "prefix", "suffix", "contains_any"):
            g = next(groups) if len(vals) > 1 else None
            op = "eq" if p["op"] == "in" else p["op"]
            for v in vals:
                yield (path, op, v, positive, necessary and g is None, g)
        elif p["op"] in _LITERAL_OPS:
            yield (path, p["op"], p["value"], positive, necessary, None)
        return
    if isinstance(spec, list):
        g = next(groups) if len(spec) > 1 else None
        for v in spec:
            yield (path, "eq", v, positive, necessary and g is None, g)
        return
    yield (path, "eq", spec, positive, necessary, None)


def _clause_literals(clause, positive, necessary, groups) -> Iterator[tuple]:
    for key, spec in (clause or {}).items():
        comb = _combinator(key)
        if comb:
            subs = spec or []
            if comb == "none_of":
                for c in subs:
                    yield from _clause_literals(c, not positive, False, groups)
            elif comb == "any_of" and len(subs) > 1:
                g = next(groups)
                for c in subs:
                    for leaf in _clause_literals(c, positive, False, groups):
                        yield leaf[:5] + (g if leaf[5] is None else leaf[5],)
            else:
                for c in subs:
                    yield from _clause_literals(c, positive, necessary, groups)
            continue
        yield from _spec_literals(key, spec, positive, necessary, groups)


def literals(rule: dict) -> list[Literal]:
    out: list[Literal] = []
    counter = iter(range(1, 1_000_000))
    for ind in rule.get("indicators") or []:
        if "chain" in ind:
            continue                                  # made of other rules' indicators
        name = ind.get("name", "?")
        clauses = [("select", ind.get("select"), True, True),
                   ("exclude", ind.get("exclude"), False, True),
                   ("versus", ind.get("versus"), True, True)]
        if ind.get("categories"):                     # categories are alternatives
            g = next(counter)
            for cname, cl in ind["categories"].items():
                for path, op, value, pos, nec, gg in _clause_literals(cl, True, False, counter):
                    if not (isinstance(value, bool) or value is None):
                        out.append(Literal(name, f"category:{cname}", path, op, value, pos, False, gg or g))
        for cname, cl, pos, nec in clauses:
            for path, op, value, p2, n2, g in _clause_literals(cl, pos, nec, counter):
                if isinstance(value, bool) or value is None:
                    continue
                out.append(Literal(name, cname, path, op, value, p2, n2, g or 0))
    return out


# ============================================================ C3 static: rename analysis

def _spec_breaks(spec) -> bool:
    if isinstance(spec, dict):
        for key in spec:
            comb = _combinator(key)
            if comb:
                subs = spec[key] or []
                if comb == "all_of":
                    return any(_spec_breaks(x) for x in subs)
                if comb == "any_of":
                    return bool(subs) and all(_spec_breaks(x) for x in subs)
                return False
        p = _as_predicate(spec)
        return bool(p) and p["op"] in _LITERAL_OPS
    return True


def _clause_breaks(clause) -> bool:
    for key, spec in (clause or {}).items():
        comb = _combinator(key)
        if comb:
            subs = spec or []
            if comb == "all_of" and any(_clause_breaks(c) for c in subs):
                return True
            if comb == "any_of" and subs and all(_clause_breaks(c) for c in subs):
                return True
            continue
        if control_of(key) == L2 and _spec_breaks(spec):
            return True
    return False


def rename_survival(rule: dict) -> tuple[float, dict[str, list[str]]]:
    """(share of score left after the attacker renames every L2 string, breaking literals).
    A broken required indicator zeroes the rule, as the interpreter does."""
    lits = literals(rule)
    total = got = 0.0
    breaking: dict[str, list[str]] = {}
    required_broken = False
    for ind in rule.get("indicators") or []:
        w = float(ind.get("weight", 1.0))
        total += w
        name = ind.get("name", "?")
        broken = False
        if "chain" not in ind:
            broken = _clause_breaks(ind.get("select"))
            cats = ind.get("categories")
            if cats and not broken:
                broken = all(_clause_breaks(c) for c in cats.values())
        if broken:
            breaking[name] = sorted({l.show() for l in lits if l.indicator == name and l.positive
                                     and control_of(l.path) == L2})
            required_broken = required_broken or bool(ind.get("required"))
        else:
            got += w
    return (0.0 if required_broken or not total else got / total), breaking


# ============================================================ C2: literal grounding

_ASCII_PUNCT = str.maketrans({"‐": "-", "‑": "-", "‒": "-", "–": "-",
                              "—": "-", "−": "-", "‘": "'", "’": "'",
                              "“": '"', "”": '"', " ": " ", " ": " "})


def _search(pattern, value, flags=0) -> bool:
    try:
        return re.search(pattern, value, flags) is not None
    except (re.error, TypeError):
        return False


class _Index:
    """Observed values per field path in the origin capture."""

    def __init__(self, claims):
        self.values: dict[str, set] = {}
        for c in claims:
            for top in ("claim_type", "modality"):
                self.values.setdefault(top, set()).add(getattr(c, top))
            for k, v in c.facts.items():
                if not k.startswith("_") and isinstance(v, (str, int, float)) and not isinstance(v, bool):
                    self.values.setdefault(f"facts.{k}", set()).add(v)

    def satisfied(self, path, op, value) -> bool:
        vals = self.values.get(path, ())
        if op == "contains_any":
            t = str(value).lower()
            return any(isinstance(v, str) and t in v.lower() for v in vals)
        if op == "eq" and isinstance(value, (int, float)) and not isinstance(value, bool):
            return any((isinstance(v, (int, float)) and float(v) == float(value)) or
                       (isinstance(v, str) and v == str(value)) for v in vals)
        fn = PREDICATES.get(op)
        try:
            return bool(fn) and any(fn(v, value) for v in vals)
        except Exception:
            return False

    def _any(self, path, fn) -> bool:
        return any(isinstance(v, str) and fn(v) for v in self.values.get(path, ()))

    def diagnose(self, lit: Literal) -> str:
        """Why no claim satisfies a literal — the repair prompt's next step, and the
        per-model error profile."""
        if not isinstance(lit.value, str):
            return "not_observed"
        val, op = lit.value, lit.op
        if op == "regex":
            if self._any(lit.path, lambda v: _search(val, v, re.I)):
                return "case"
            if "\\\\" in val and self._any(lit.path, lambda v: _search(val.replace("\\\\", "\\"), v)):
                return "over_escaped"
        elif op in ("eq", "prefix", "suffix"):
            low = val.lower()
            ci = {"eq": lambda v: v.lower() == low, "prefix": lambda v: v.lower().startswith(low),
                  "suffix": lambda v: v.lower().endswith(low)}[op]
            if self._any(lit.path, ci):
                return "case"
        ascii_val = val.translate(_ASCII_PUNCT)
        if ascii_val != val and self.satisfied(lit.path, op, ascii_val):
            return "non_ascii"
        for p in self.values:
            if p != lit.path and p.startswith("facts.") and self.satisfied(p, op, val):
                return "wrong_field"
        if op == "eq" and self._any(lit.path, lambda v: val.lower() in v.lower()):
            return "partial"
        return "not_observed"


# ============================================================ the five checks, one definition

# (key, name, the question it answers). The order is the order a rule meets them.
CHECKS = (
    ("C1_valid", "valid", "Can ARGUS run the rule as written?"),
    ("C2_own_evidence", "own evidence",
     "Does it fire on the episode it was written from, using values that really occur there?"),
    ("C3_robust", "robust",
     "Does it still fire when programs are renamed, run by full path, or create renamed files?"),
    ("C4_quiet", "quiet", "Is it silent on at least three quarters of its host's other windows?"),
    ("C5_confirmed", "confirmed",
     "Does a source that may decide on its own flag the same events: a deciding hand-written "
     "rule or a medium-or-higher Sigma rule (each quiet on that host), or the analyst?"),
)
KEYS = tuple(k for k, _, _ in CHECKS)
SHADOW_NEEDS = KEYS[:4]                 # C1–C4: measured on every case, never decides
ACTIVE_NEEDS = KEYS                     # C1–C5: decides
# keys of earlier records (before A3), read as today's
ALIASES = {"C4_rare_history": "C4_quiet", "C5_agreement": "C5_confirmed"}


@dataclass
class Check:
    name: str
    passed: bool | None               # None = not applicable
    detail: str = ""
    data: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"check": self.name, "passed": self.passed, "detail": self.detail, **self.data}


def passed_all(checks: dict, keys) -> bool:
    """Every check in `keys` was reached and passed (records as Check objects or dicts)."""
    def ok(c):
        return bool(c.passed if hasattr(c, "passed") else (c or {}).get("passed"))
    return all(k in checks and ok(checks[k]) for k in keys)


def normalise(checks: dict, status: str, history: list) -> dict:
    """An entry's check record in today's form (A3), its status untouched:
    - earlier keys renamed (`ALIASES`);
    - agreement with other written rules folded into C5 as a note (it never confirmed);
    - checks recorded although not reached removed (C3 after a rule never fired, C5 after
      C4 failed);
    - an analyst's approval recorded as the C5 pass it was."""
    out: dict = {}
    for k, v in checks.items():
        if k == "C5_any_source":
            continue
        d = dict(v)
        k = ALIASES.get(k, k)
        d["check"] = k
        if "agreed_with" in d:
            d["confirmed_by"] = d.pop("agreed_with")
        out[k] = d
    any_src = checks.get("C5_any_source") or {}
    if "C5_confirmed" in out:
        llm = [a for a in any_src.get("agreed_with", []) if a.startswith("llm:")]
        out["C5_confirmed"].setdefault("llm_agreement", llm)
        if out["C5_confirmed"].get("passed"):
            out["C5_confirmed"].setdefault("source", _source(out["C5_confirmed"].get("confirmed_by", [])))
    if (out.get("C3_robust") or {}).get("not_applicable"):
        del out["C3_robust"]
    if "C5_confirmed" in out and not (out.get("C4_quiet") or {}).get("passed"):
        del out["C5_confirmed"]
    activated = next((h for h in reversed(history) if h.get("to") == "active"), None)
    if activated and str(activated.get("reason", "")).startswith("analyst") \
            and not (out.get("C5_confirmed") or {}).get("passed"):
        note = (out.get("C5_confirmed") or {}).get("llm_agreement", [])
        out["C5_confirmed"] = c5_by_analyst(activated["reason"]).to_dict() | {"llm_agreement": note}
    return {k: out[k] for k in KEYS if k in out} | {k: v for k, v in out.items() if k not in KEYS}


def _source(confirmed_by: list[str]) -> str:
    kinds = sorted({a.split(":", 1)[0] for a in confirmed_by})
    return {"hand": "hand-written rule", "sigma": "Sigma rule", "analyst": "analyst"}.get(
        kinds[0], kinds[0]) if len(kinds) == 1 else " + ".join(kinds)


def rule_score(hyp, claims, ctx) -> tuple[float, list, list[tuple[str, float, int]]]:
    """(score, hit claims, per-indicator (name, strength, hits)) — the engine's weighted
    mean with required gating, before defeaters. Hits only when the rule fires."""
    total = got = 0.0
    required_ok = True
    hits, per = {}, []
    for ind in hyp.indicators:
        h, s = ind.match(claims, ctx)
        total += ind.weight
        got += ind.weight * s
        if ind.required and s <= 0:
            required_ok = False
        if s > 0:
            hits.update({c.claim_id: c for c in h})
        per.append((ind.name, s, len(h)))
    score = got / total if total and required_ok else 0.0
    return score, (list(hits.values()) if score > 0 else []), per


def c1_valid(rule: dict, known: dict | None = None) -> Check:
    errs = validate(rule, known)
    return Check("C1_valid", not errs, "; ".join(errs[:3]), {"errors": errs})


def c2_own_evidence(rule: dict, hyp, origin_claims, ctx) -> Check:
    idx = _Index(origin_claims)
    hard, soft, causes = [], [], Counter()
    lits = [l for l in literals(rule) if l.clause != "versus"]
    groups: dict[int, list[Literal]] = {}
    missing_in_group: dict[int, list[Literal]] = {}
    for l in lits:
        if l.positive and not l.necessary and l.group:
            groups.setdefault(l.group, []).append(l)
        if idx.satisfied(l.path, l.op, l.value):
            continue
        if not l.positive:
            soft.append(f"excludes {l.show()}, never seen in the origin capture")
        elif l.necessary:
            cause = idx.diagnose(l)
            causes[cause] += 1
            hard.append(f"[{l.indicator}] requires {l.show()}: no claim of the origin capture "
                        f"satisfies it ({cause})")
        elif l.group:
            missing_in_group.setdefault(l.group, []).append(l)
    for g, members in groups.items():
        miss = missing_in_group.get(g, [])
        if miss and len(miss) == len(members):
            causes[idx.diagnose(members[0])] += 1
            hard.append(f"[{members[0].indicator}] none of {', '.join(m.show() for m in members[:4])} "
                        f"occurs in the origin capture")
    score, _, per = rule_score(hyp, origin_claims, ctx)
    dead = []
    if not hard:
        for (name, s, n), ind in zip(per, rule.get("indicators") or []):
            if ind.get("required") and s <= 0:
                sel = sum(1 for c in origin_claims if match(c, ind.get("select", {}), ctx)
                          and not (ind.get("exclude") and match(c, ind["exclude"], ctx))) \
                    if "chain" not in ind else None
                sc = ind.get("score") or {}
                need = {k: sc[k] for k in ("floor", "at", "over", "ceiling") if k in sc}
                if sel == 0:
                    causes["jointly_unsatisfied"] += 1
                    hard.append(f"[{name}] is required but selects no claim of the origin capture")
                else:
                    causes["dead_score"] += 1
                    hard.append(f"[{name}] selects {sel} claim(s) of its origin capture but scores 0 "
                                f"(score {sc.get('op')} {need}; groups by {ind.get('group_by') or 'nothing'})")
    ok = not hard and score > 0
    return Check("C2_own_evidence", ok, "; ".join(hard[:2]),
                 {"hard": hard, "soft": soft, "causes": dict(causes), "origin_score": round(score, 4)})


def c3_robust(rule: dict, hyp, origin_claims, ctx_for, fired_on_origin: bool,
              transforms=None) -> Check:
    """Dynamic robustness on the rule's own evidence, under label-free transforms
    (`C3_TRANSFORMS`, defined below): does it still fire when every user-writable
    executable is renamed, when programs are invoked by full path, and when created files
    are renamed?"""
    survival, breaking = rename_survival(rule)
    lost = []
    if fired_on_origin:
        for kind in (transforms or C3_TRANSFORMS):
            t = transform(origin_claims, kind)
            if rule_score(hyp, t, ctx_for(t))[0] <= 0:
                lost.append(kind)
    return c3_verdict(survival, breaking, lost)


def c3_verdict(survival: float, breaking: dict, lost: list[str]) -> Check:
    """Pass unless the rule stops firing on a transformed copy of its own evidence."""
    return Check("C3_robust", not lost,
                 f"stops firing on its own evidence when {', '.join(lost)}" if lost else "",
                 {"lost_under": lost, "static_rename_survival": round(survival, 4),
                  "static_brittle": survival == 0.0, "breaking_literals": breaking})


def history_rate(fires_on, host_windows: list[str], exclude: str | None = None) -> float:
    """The share of a host's windows on which a rule fires: C4's measure. A written rule
    is measured on its host's history less its origin window (`exclude`), which it was
    built to fire on; a confirmer was built from nothing here, so on the whole history."""
    ref = [w for w in host_windows if w != exclude]
    return sum(1 for w in ref if w in fires_on) / len(ref) if ref else 0.0


def c4_quiet(fired_windows: list[str], reference: list[str], max_rate: float) -> Check:
    rate = len(fired_windows) / len(reference) if reference else 0.0
    ok = rate <= max_rate
    return Check("C4_quiet", ok,
                 "" if ok else f"fires on {rate:.0%} of the host's other captures (max {max_rate:.0%})",
                 {"history_rate": round(rate, 4), "fired_on": fired_windows[:10]})


def quiet_hits(hits: dict[str, set], host_of: dict[str, str], by_host: dict[str, list[str]],
               max_rate: float) -> dict[str, set]:
    """A confirmer's hits, kept only on hosts where it is itself quiet by C4's bar: it fires
    on at most `max_rate` of that host's windows (`history_rate` on the whole history). A
    source that fires through a host's routine activity confirms nothing there."""
    return {w: ev for w, ev in hits.items()
            if history_rate(hits, by_host[host_of[w]]) <= max_rate}


def c5_confirmed(my_hits: dict[str, set], my_recordings: set[str],
                 sources: list[tuple[str, set[str], dict[str, set]]],
                 llm_sources: list[tuple[str, set[str], dict[str, set]]] = ()) -> Check:
    """Pass if a confirming source (label, recordings it was written from, hits per window)
    flags at least one of the same events. Callers pass only sources that may decide on
    their own, with hits already restricted by `quiet_hits`. Independence is by recording,
    never by window: adjacent windows of one recording are one continuous observation (S2).
    `llm_sources` (other written rules) are recorded as a note and never confirm."""
    def agreeing(srcs):
        out = []
        for label, recs, hits in srcs:
            if recs & my_recordings:
                continue
            shared = [w for w, ev in my_hits.items() if ev & hits.get(w, set())]
            if shared:
                out.append(f"{label}@{shared[0]}")
        return out[:6]
    agree, llm = agreeing(sources), agreeing(llm_sources)
    return Check("C5_confirmed", bool(agree),
                 "" if agree else "no independent source flags the same events",
                 {"confirmed_by": agree, "source": _source(agree) if agree else None, "llm_agreement": llm})


def c5_by_analyst(reason: str) -> Check:
    """The analyst's approval, recorded as the C5 pass it is."""
    return Check("C5_confirmed", True, "", {"confirmed_by": ["analyst"], "source": "analyst",
                                             "why": reason[:300], "llm_agreement": []})


# ============================================================ C3 dynamic transforms (label-free)

def renameable_images(claims) -> set[str]:
    """Image names seen running from a user-writable location in these claims. An
    executable there has a NAME its owner chose, so a rule keyed on it is keyed on a
    choice the attacker makes (`lineage.user_writable`: decided from `image_path`)."""
    out = set()
    for c in claims:
        img = c.facts.get("image")
        # an absolute path only: the kernel's "System" has none and is not renameable
        if img and user_writable(c.facts.get("image_path")):
            out.add(str(img).lower())
    return out


def _rename_patterns(names: set[str]):
    import hashlib
    pats = []
    for n in sorted(names, key=len, reverse=True):
        new = "r" + hashlib.sha1(n.encode()).hexdigest()[:8]
        pats.append((re.compile(r"(?<![\w.-])" + re.escape(n) + r"(?![\w-])", re.I), new))
    return pats


def respell(cmd: str, image: str | None = None, image_path: str | None = None) -> str:
    """An equivalent spelling of a command: the program invoked by its full path, as the
    sensor recorded it (`id -u` -> `/usr/bin/id -u`). What Linux executes is unchanged."""
    if not (image and image_path and image_path.startswith("/")):
        return cmd
    head, _, rest = cmd.partition(" ")
    if head != image:
        return cmd
    return image_path + (" " + rest if rest else "")


# shell function definitions: `name() {` or `function name {`
_FUNC_DEF = re.compile(r"(?:\bfunction\s+([A-Za-z_][\w-]{3,})|\b([A-Za-z_][\w-]{3,})\s*\(\)\s*\{)")
_CREATES = ("file_create", "file_write", "file_rename")


def created_artifacts(claims) -> set[str]:
    """Names the authors of these claims chose: the files created by processes that run
    from, or descend from, a user-writable folder (by base name, and by stem when it is
    distinctive), and script functions defined in their command lines. Label-free: decided
    from lineage and paths. A rule keyed on one (`ad.7z`, `trustdmp`) is keyed on a choice
    the next operator makes differently (S3 §13)."""
    g = ProcessGraph.from_claims(claims)
    if g is None:
        return set()
    out: set[str] = set()
    for c in claims:
        actors = g.actors(c)
        if not any(g.writable(a) or any(g.writable(x) for x in g.ancestry(a)[1:]) for a in actors):
            continue
        if c.claim_type in _CREATES and c.facts.get("file_path"):
            base = re.split(r"[\\/]", str(c.facts["file_path"]))[-1].lower()
            stem = base.rsplit(".", 1)[0]
            if len(base) >= 4:
                out.add(base)
            if len(stem) >= 5 and stem != base:
                out.add(stem)
        elif c.claim_type == "process_create" and c.facts.get("command"):
            out.update((m.group(1) or m.group(2)).lower() for m in _FUNC_DEF.finditer(str(c.facts["command"])))
    return out


def transform(claims, kind: str):
    """Deep copies of `claims` under a label-free transform:
       rename_user_writable      every executable seen running from a user-writable folder
                                 is renamed (consistently, in every string fact)
       respell_commands          programs invoked by their full path (equivalent spelling)
       rename_created_artifacts  files created by user-writable process trees, and script
                                 functions their commands define, renamed everywhere"""
    out = [c.model_copy(deep=True) for c in claims]
    if kind == "rename_created_artifacts":
        import hashlib
        pats = []
        for n in sorted(created_artifacts(claims), key=len, reverse=True):
            ext = "." + n.rsplit(".", 1)[1] if "." in n else ""
            pats.append((re.compile(r"(?<![\w-])" + re.escape(n) + r"(?![\w-])", re.I),
                         "a" + hashlib.sha1(n.encode()).hexdigest()[:8] + ext))
        for c in out:
            for k, v in list(c.facts.items()):
                if isinstance(v, str) and not k.startswith("_"):
                    for p, new in pats:
                        v = p.sub(new, v)
                    c.facts[k] = v
        return out
    if kind == "rename_user_writable":
        pats = _rename_patterns(renameable_images(claims))
        for c in out:
            for k, v in list(c.facts.items()):
                if isinstance(v, str) and not k.startswith("_"):
                    for p, new in pats:
                        v = p.sub(new, v)
                    c.facts[k] = v
    elif kind == "respell_commands":
        for c in out:
            if c.claim_type == "process_create" and c.facts.get("command"):
                c.facts["command"] = respell(str(c.facts["command"]), c.facts.get("image"),
                                             c.facts.get("image_path"))
    else:
        raise ValueError(f"unknown transform {kind!r}")
    return out


C3_TRANSFORMS = ("rename_user_writable", "respell_commands", "rename_created_artifacts")
