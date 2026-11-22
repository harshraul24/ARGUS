"""Shared by the lab tools: the corpus and its design/test split, the freeze check, scoring
one window, and Wilson intervals. Nothing here tunes ARGUS; labels are read only to grade.

The split lives in lab_split.json (ARGUS root): operations in capture order, the first
`design_count` of them design, every later one test (LAB_EVAL_PLAN.md §3).
"""
from __future__ import annotations

import hashlib
import json
import math
import sys
from contextlib import contextmanager
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "source code"))

from argus.case import load_case                                   # noqa: E402
from argus.reason import hypotheses as H                           # noqa: E402
from argus.reason.context import CaseContext                       # noqa: E402
from argus.reason.engine import Config, reason                     # noqa: E402

LAB = ROOT / "cases_lab"
SPLIT = ROOT / "lab_split.json"
FLAGGED = ("malicious", "suspicious")


# ============================================================ corpus

def split() -> dict[str, list[str]]:
    s = json.loads(SPLIT.read_text())
    ops, n = s["operations"], s.get("design_count", 3)
    return {"design": ops[:n], "test": ops[n:], "excluded": sorted(s.get("excluded", {}))}


def meta(window: Path) -> dict:
    return json.loads((window / "meta.json").read_text())


def operation(window: Path) -> str:
    return meta(window).get("campaign", "?")


def host(window: Path) -> str:
    return meta(window).get("host", "?")


def labels(window: Path) -> dict:
    return json.loads((window / "labels.json").read_text())


def windows(operations=None, root: Path = LAB) -> list[Path]:
    """Windows of the given operations (all if None), in name order."""
    ws = sorted(w for w in root.iterdir() if (w / "events.jsonl").exists())
    return [w for w in ws if operations is None or operation(w) in set(operations)]


# ============================================================ freeze

def _hashes() -> dict[str, str]:
    base = ROOT / "source code"
    return {str(p.relative_to(base)): hashlib.sha256(p.read_bytes()).hexdigest()
            for p in sorted((base / "argus").rglob("*"))
            if p.is_file() and "__pycache__" not in p.parts and p.name != ".DS_Store"}


def freeze_status() -> dict:
    manifests = sorted(ROOT.glob("ARGUS_FREEZE_*.json"),
                       key=lambda m: json.loads(m.read_text()).get("frozen_at", ""))
    cur = _hashes()
    agg = hashlib.sha256(json.dumps(cur, sort_keys=True).encode()).hexdigest()
    if not manifests:
        return {"manifest": None, "matches": False, "aggregate_sha256": agg,
                "changed": ["no freeze manifest found"]}
    man = json.loads(manifests[-1].read_text())
    changed = sorted(k for k in set(man["files"]) | set(cur) if man["files"].get(k) != cur.get(k))
    return {"manifest": manifests[-1].name, "matches": not changed,
            "aggregate_sha256": agg, "changed": changed}


# ============================================================ scoring

@contextmanager
def novelty_baseline(b: dict | None):
    """Point NOVELTY at `b` for the duration (None = the shipped file, if any). Detection
    code is unchanged; only the module's baseline cache is set."""
    old = H._baseline_cache
    H._baseline_cache = b
    try:
        yield
    finally:
        H._baseline_cache = old


def score_window(case_dir: Path, cfg: Config) -> dict:
    """ARGUS's decision for one window, plus every event each alerting hypothesis selects."""
    lc = load_case(case_dir)
    dec = reason(lc.case_id, lc.claims, lc.health, cfg, lc.protocol_artifacts)
    ctx = CaseContext(claims=lc.claims, health=lc.health)
    ctx.lineage_enabled = cfg.enable_lineage
    by = {h.uid: h for h in cfg.hypotheses}
    alerts = {}
    for r in dec.hypotheses:
        key = r.rule_id or r.technique
        if r.score <= 0 or r.technique in dec.suppressed or key in dec.context or key not in by:
            continue
        weighted = r.score * by[key].severity
        if weighted < cfg.suspicious_threshold:
            continue
        sel: set[str] = set()
        for ind in by[key].indicators:
            hits, strength = ind.match(lc.claims, ctx)
            if strength > 0:
                sel |= {c.facts["_event_id"] for c in hits if c.facts.get("_event_id")}
        alerts[key] = {"score": round(r.score, 4), "weighted": round(weighted, 4), "events": sel}
    eid = {c.claim_id: c.facts.get("_event_id") for c in lc.claims}
    episodes = [{"root": e["root"], "root_image": e["root_image"], "stages": e["stages"],
                 "events": {eid[x] for x in e["claim_ids"] if eid.get(x)}}
                for e in dec.episodes]
    return {"disposition": dec.disposition.value, "alerts": alerts, "episodes": episodes,
            "context": list(dec.context), "blind_spots": list(dec.blind_spots)}


def wilson(k: int, n: int, z: float = 1.96) -> tuple[float, float] | None:
    if not n:
        return None
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * math.sqrt(p * (1 - p) / n + z * z / (4 * n * n)) / d
    return round(max(0.0, c - h), 3), round(min(1.0, c + h), 3)
