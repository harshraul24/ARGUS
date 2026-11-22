"""Import Linux Sigma rules (SigmaHQ community detection rules) into the ARGUS rule format.

Sigma is the independent, non-LLM source C5 lacked (S3 §12–§14): a rule of a different
kind that can confirm, or fail to confirm, what an LLM-written rule flags. It comes from a
dated snapshot (tools/intel_snapshot.py), never live, so no rule published after a capture
can score it.

The import is exact or refused, and it may NARROW a rule but never BROADEN it:
  - a field ARGUS's telemetry does not carry (OriginalFileName, Hashes, Description, ...)
    offered as one alternative of an OR is dropped, and the rule is marked `narrowed`
    (it can only fire less often than the original);
  - the same field anywhere else (required, or inside an exclusion, where dropping it would
    make the rule fire MORE often) refuses the rule, with the reason;
  - keyword (full-text) searches, aggregations, base64 and CIDR modifiers, field
    references and logsources with no ARGUS claim type are refused.

Sigma matches case-insensitively with `*`/`?` wildcards; every value becomes a
case-insensitive anchored regex, so the semantics are kept exactly.
"""
from __future__ import annotations

import re
from pathlib import Path

# Sigma logsource category -> ARGUS claim types (collectors/events.py)
CATEGORY = {
    "process_creation": ["process_create"],
    "file_event": ["file_create"],
    "file_delete": ["file_delete"],
    "network_connection": ["host_network_connection"],
}
PRODUCTS = {"linux"}

# Sigma field -> (ARGUS fact path, how values compare)
#   path     the full path, as recorded
#   base     ARGUS records only the base name: a Sigma `endswith '/x'` / equality on a
#            path compares its base name; anything needing the folders is refused
#   text     free text;  num  number
FIELDS = {
    "process_create": {"Image": ("facts.image_path", "path"), "CommandLine": ("facts.command", "text"),
                       "ParentImage": ("facts.parent", "base"), "User": ("facts.user", "text"),
                       "CurrentDirectory": ("facts.cwd", "path")},
    "file": {"TargetFilename": ("facts.file_path", "path"), "Image": ("facts.image_path", "path")},
    "host_network_connection": {"DestinationPort": ("facts.dst_port", "num"),
                                "DestinationIp": ("facts.dst_ip", "text"),
                                "Image": ("facts.image_path", "path")},
}
LEVEL = {"informational": 0.2, "low": 0.4, "medium": 0.6, "high": 0.8, "critical": 0.9}


class Refused(ValueError):
    pass


def _family(claim_types: list[str]) -> str:
    t = claim_types[0]
    return "file" if t.startswith("file_") else t


# ============================================================ values -> regex

def _wild(v: str) -> str:
    """Sigma wildcards (`*`, `?`, backslash-escapable) to a regex body."""
    out, i = [], 0
    while i < len(v):
        c = v[i]
        if c == "\\" and i + 1 < len(v) and v[i + 1] in "*?\\":
            out.append(re.escape(v[i + 1]))
            i += 2
            continue
        out.append(".*" if c == "*" else "." if c == "?" else re.escape(c))
        i += 1
    return "".join(out)


def _value_regex(v, mods: list[str], kind: str) -> str:
    if v is None:
        raise Refused("null-valued match")       # handled by the caller as `exists`
    s = str(v)
    if kind == "base":
        # a path compared on its base name: only the part after the last separator
        tail = re.split(r"[\\/]", s)[-1]
        if ("endswith" in mods and s.startswith(("\\", "/")) and "\\" not in s[1:] and "/" not in s[1:]) \
                or (not mods and s == tail):
            return f"(?i)^{_wild(tail)}$"
        if "contains" in mods and not re.search(r"[\\/]", s):
            return f"(?i){_wild(s)}"
        raise Refused(f"needs the folder of a process ARGUS records by name only ({s!r})")
    if "re" in mods:
        return ("(?i)" if "i" in mods else "") + s
    body = _wild(s)
    if "contains" in mods:
        return f"(?i){body}"
    if "startswith" in mods:
        return f"(?i)^{body}"
    if "endswith" in mods:
        return f"(?i){body}$"
    return f"(?i)^{body}$"


def _field(name: str, values, family: str) -> tuple[dict, bool]:
    """(clause for one `Field|mods: values` entry, narrowed?)."""
    field, *mods = name.split("|")
    table = FIELDS.get(family, {})
    if field not in table:
        raise Refused(f"field {field!r} is not in ARGUS's {family} telemetry")
    path, kind = table[field]
    bad = set(mods) - {"contains", "startswith", "endswith", "all", "re", "i"}
    if bad:
        raise Refused(f"modifier(s) {sorted(bad)} on {field}")
    vals = values if isinstance(values, list) else [values]
    if any(v is None for v in vals):
        if len(vals) == 1:
            return {path: {"exists": False}}, False
        raise Refused(f"null mixed with values on {field}")
    if kind == "num":
        if mods:
            raise Refused(f"modifiers on numeric field {field}")
        nums = []
        for v in vals:
            nums += [int(v), str(v)] if str(v).isdigit() else [v]
        return {path: {"in": nums}}, False
    rx = [_value_regex(v, [m for m in mods if m != "all"], kind) for v in vals]
    specs = [{"regex": r} for r in rx]
    if "all" in mods:
        return {path: {"all_of": specs}}, False
    return ({path: specs[0]} if len(specs) == 1 else {path: {"any_of": specs}}), False


def _selection(sel, family: str, negated: bool) -> tuple[dict, bool]:
    """A Sigma selection: a map is AND of fields; a list of maps is OR of them."""
    if isinstance(sel, dict):
        parts = []
        for k, v in sel.items():
            parts.append(_field(k, v, family)[0])
        return ({"all_of": parts} if len(parts) > 1 else parts[0]), False
    if isinstance(sel, list) and sel and all(isinstance(x, dict) for x in sel):
        kept, narrowed, errors = [], False, []
        for alt in sel:
            try:
                kept.append(_selection(alt, family, negated)[0])
            except Refused as exc:
                errors.append(str(exc))
                narrowed = True
        if not kept or (narrowed and negated):
            # dropping an alternative of an exclusion would make the rule fire MORE often
            raise Refused("; ".join(errors[:2]) + (" (inside an exclusion)" if negated else ""))
        return ({"any_of": kept} if len(kept) > 1 else kept[0]), narrowed
    raise Refused("keyword (full-text) selection")


# ============================================================ condition grammar

_TOK = re.compile(r"\s*(\(|\)|\bnot\b|\band\b|\bor\b|\b1 of\b|\ball of\b|[\w*]+)", re.I)


def _tokens(cond: str) -> list[str]:
    out, pos = [], 0
    cond = cond.strip()
    while pos < len(cond):
        m = _TOK.match(cond, pos)
        if not m:
            raise Refused(f"unparsed condition {cond!r}")
        out.append(m.group(1).lower() if m.group(1).lower() in ("not", "and", "or", "1 of", "all of")
                   else m.group(1))
        pos = m.end()
    return out


def _condition(cond: str, sels: dict, family: str) -> tuple[dict, bool]:
    if "|" in cond:
        raise Refused("aggregation condition")
    toks = _tokens(cond)
    narrowed = [False]

    def sel(name: str, neg: bool) -> dict:
        if name not in sels:
            raise Refused(f"condition names unknown selection {name!r}")
        c, n = _selection(sels[name], family, neg)
        narrowed[0] |= n
        return c

    def names(pat: str) -> list[str]:
        if pat == "them":
            return [k for k in sels]
        rx = re.compile("^" + re.escape(pat).replace(r"\*", ".*") + "$")
        got = [k for k in sels if rx.match(k)]
        if not got:
            raise Refused(f"no selection matches {pat!r}")
        return got

    def expr(i, neg):
        left, i = term(i, neg)
        parts = [left]
        while i < len(toks) and toks[i] == "or":
            right, i = term(i + 1, neg)
            parts.append(right)
        return ({"any_of": parts} if len(parts) > 1 else parts[0]), i

    def term(i, neg):
        left, i = factor(i, neg)
        parts = [left]
        while i < len(toks) and toks[i] == "and":
            right, i = factor(i + 1, neg)
            parts.append(right)
        return ({"all_of": parts} if len(parts) > 1 else parts[0]), i

    def factor(i, neg):
        t = toks[i]
        if t == "not":
            inner, i = factor(i + 1, not neg)
            return {"none_of": [inner]}, i
        if t == "(":
            inner, i = expr(i + 1, neg)
            if i >= len(toks) or toks[i] != ")":
                raise Refused("unbalanced parentheses")
            return inner, i + 1
        if t in ("1 of", "all of"):
            group = [sel(n, neg) for n in names(toks[i + 1])]
            node = group[0] if len(group) == 1 else {("any_of" if t == "1 of" else "all_of"): group}
            return node, i + 2
        return sel(t, neg), i + 1

    tree, i = expr(0, False)
    if i != len(toks):
        raise Refused(f"trailing tokens in condition {cond!r}")
    return tree, narrowed[0]


# ============================================================ rule

def _technique(tags) -> str:
    for t in tags or []:
        m = re.fullmatch(r"attack\.(t\d{4}(?:\.\d{3})?)", str(t).lower())
        if m:
            return m.group(1).upper()
    return "SIGMA"


def _tactic(tags) -> str:
    for t in tags or []:
        t = str(t).lower()
        if t.startswith("attack.") and not re.fullmatch(r"attack\.[tgs]\d{4}.*", t):
            return t[7:].replace("_", " ").replace("-", " ")
    return ""


def from_sigma(doc: dict, path: str = "", snapshot: str = "") -> dict:
    """An ARGUS rule from one Sigma rule. Raises Refused with the reason."""
    ls = doc.get("logsource") or {}
    if ls.get("product") not in PRODUCTS:
        raise Refused(f"product {ls.get('product')!r}")
    cat = ls.get("category")
    if cat not in CATEGORY:
        raise Refused(f"logsource {cat or ls.get('service')!r} has no ARGUS claim type")
    ctypes = CATEGORY[cat]
    det = dict(doc.get("detection") or {})
    cond = det.pop("condition", None)
    det.pop("timeframe", None)
    if isinstance(cond, list):
        if len(cond) != 1:
            raise Refused("several conditions")
        cond = cond[0]
    if not isinstance(cond, str):
        raise Refused("no condition")
    tree, narrowed = _condition(cond, det, _family(ctypes))
    ctype = ctypes[0] if len(ctypes) == 1 else {"in": ctypes}
    sid = str(doc.get("id") or Path(path).stem)
    return {
        "id": f"sigma:{sid}", "technique": _technique(doc.get("tags")), "name": str(doc.get("title", sid)),
        "tactic": _tactic(doc.get("tags")), "severity": LEVEL.get(str(doc.get("level")), 0.6),
        "indicators": [{"name": "sigma detection", "weight": 1.0, "required": True,
                        "select": {"claim_type": ctype, "all_of": [tree]}}],
        "expected": [],
        "provenance": {"authored_by": "SigmaHQ community", "sigma_id": sid, "sigma_path": path,
                       "status": doc.get("status"), "level": doc.get("level"),
                       "date": str(doc.get("date", "")), "modified": str(doc.get("modified", "")),
                       "licence": "Detection Rule License (DRL) 1.1", "snapshot": snapshot,
                       "narrowed": narrowed, "logsource": {"product": ls.get("product"), "category": cat}},
    }


def load_snapshot(snapshot_dir: Path) -> tuple[list[dict], list[tuple[str, str]]]:
    """(converted rules, [(path, reason)] refused) for every Sigma rule in a snapshot."""
    import yaml
    snapshot_dir = Path(snapshot_dir)
    rules, refused = [], []
    for f in sorted((snapshot_dir / "sigma" / "rules").rglob("*.yml")):
        rel = str(f.relative_to(snapshot_dir / "sigma"))
        try:
            docs = [d for d in yaml.safe_load_all(f.read_text(errors="ignore")) if isinstance(d, dict)]
        except yaml.YAMLError as exc:
            refused.append((rel, f"YAML: {str(exc)[:80]}"))
            continue
        for d in docs:
            if "detection" not in d:
                continue
            try:
                rules.append(from_sigma(d, rel, snapshot_dir.name))
            except Refused as exc:
                refused.append((rel, str(exc)))
    return rules, refused
