"""The rule library: every rule with its checks, its lifecycle state and its history (S3 §4–5).

  candidate ─► shadow ─► active ─► retired
      │           │
      └─► rejected ◄┘

  candidate  written, not yet judged
  shadow     passed C1–C4: runs on every case (Config.shadow), is reported in
             Decision.shadow and measured, and can never move a verdict
  active     passed C1–C5: scored by the engine exactly like a hand-written hypothesis
  retired    was active or shadow, taken out (superseded, duplicate, analyst decision)
  rejected   failed a check; kept with its reason, never loaded

Every transition is recorded with its reason. A rule's body cannot change once it has
left `candidate` — a fix is a new rule — so what was judged is what runs. The status
follows the check record (checks.py): `transition` refuses shadow without C1–C4 passed and
active without C5 passed, and an analyst's approval is recorded as a C5 pass
(`confirm_by_analyst`). Libraries written before A3 are read in today's form (`load`).

This is the system's memory (S3 §4 level 1): what was written, what failed and why.
"""
from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

from argus.rules.loader import to_hypotheses

STATES = ("candidate", "shadow", "active", "retired", "rejected")
ALLOWED = {"candidate": {"shadow", "rejected"},
           "shadow": {"active", "retired", "rejected"},
           "active": {"retired"},
           "retired": set(), "rejected": set()}


class LifecycleError(ValueError):
    pass


@dataclass
class Entry:
    uid: str
    rule: dict
    status: str = "candidate"
    origin: dict = field(default_factory=dict)       # capture, recording, episode root
    checks: dict = field(default_factory=dict)       # check name -> Check.to_dict()
    history: list = field(default_factory=list)      # [{at, from, to, reason}]


class RuleLibrary:
    def __init__(self, entries: list[Entry] | None = None) -> None:
        self.entries: dict[str, Entry] = {e.uid: e for e in entries or []}

    # ---------------------------------------------------------------- writes

    def add(self, rule: dict, origin: dict | None = None, reason: str = "written") -> Entry:
        uid = rule["id"]
        if uid in self.entries:
            raise LifecycleError(f"rule {uid!r} already in the library")
        e = Entry(uid=uid, rule=json.loads(json.dumps(rule)), origin=dict(origin or {}))
        e.history.append({"at": _now(), "from": None, "to": "candidate", "reason": reason})
        self.entries[uid] = e
        return e

    def record(self, uid: str, checks: dict) -> None:
        """Attach check results (Check objects or their dicts)."""
        e = self.entries[uid]
        for name, c in checks.items():
            e.checks[name] = c.to_dict() if hasattr(c, "to_dict") else dict(c)

    def transition(self, uid: str, to: str, reason: str) -> Entry:
        from argus.rules import checks as C
        e = self.entries[uid]
        if to not in ALLOWED.get(e.status, set()):
            raise LifecycleError(f"{uid}: {e.status} -> {to} is not allowed")
        need = {"shadow": C.SHADOW_NEEDS, "active": C.ACTIVE_NEEDS}.get(to, ())
        if not C.passed_all(e.checks, need):
            missing = [k for k in need if not C.passed_all(e.checks, (k,))]
            raise LifecycleError(f"{uid}: {to} needs {', '.join(need)} passed; not passed: {', '.join(missing)}")
        e.history.append({"at": _now(), "from": e.status, "to": to, "reason": reason})
        e.status = to
        return e

    def confirm_by_analyst(self, uid: str, reason: str) -> Entry:
        """The analyst approves a shadow rule: recorded as its C5 pass, then made active."""
        from argus.rules import checks as C
        e = self.entries[uid]
        if e.status != "shadow":
            raise LifecycleError(f"{uid}: only a shadow rule can be approved (it is {e.status})")
        note = (e.checks.get("C5_confirmed") or {}).get("llm_agreement", [])
        self.record(uid, {"C5_confirmed": C.c5_by_analyst(reason).to_dict() | {"llm_agreement": note}})
        return self.transition(uid, "active", reason)

    def edit(self, uid: str, rule: dict) -> None:
        e = self.entries[uid]
        if e.status != "candidate":
            raise LifecycleError(f"{uid} is {e.status}: a judged rule cannot change; add a new rule")
        e.rule = json.loads(json.dumps({**rule, "id": uid}))

    def merge_duplicates(self, hits: dict[str, dict[str, set]]) -> list[tuple[str, str]]:
        """Retire each active or shadow rule that fires on exactly the same events, in every
        capture, as another one. Label-free, and nothing the library detects on these
        captures is lost. The kept copy is an active rule if there is one (an analyst's or
        the checks' decision stands), then the most general: the one whose score best
        survives renaming (checks.rename_survival), then the one with fewer literals, then
        the lower id. `hits`: rule id -> capture -> event ids. Returns [(retired, kept)]."""
        from argus.rules import checks as C
        groups: dict[frozenset, list[str]] = {}
        for e in self.by_status("active", "shadow"):
            key = frozenset((cap, ev) for cap, evs in (hits.get(e.uid) or {}).items() for ev in evs)
            if key:                                    # a rule that fires nowhere has nothing to compare
                groups.setdefault(key, []).append(e.uid)

        def rank(uid: str):
            rule = self.entries[uid].rule
            return (self.entries[uid].status != "active", -C.rename_survival(rule)[0], len(C.literals(rule)), uid)

        merged = []
        for uids in groups.values():
            keep, *rest = sorted(uids, key=rank)
            for u in rest:
                self.transition(u, "retired", f"duplicate of {keep}: fires on exactly the same events "
                                              "in every design capture")
                merged.append((u, keep))
        return merged

    # ---------------------------------------------------------------- reads

    def by_status(self, *status: str) -> list[Entry]:
        return [e for e in self.entries.values() if e.status in status]

    def hypotheses(self, *status: str):
        return to_hypotheses([e.rule for e in self.by_status(*status)])

    def counts(self) -> dict[str, int]:
        out = {s: 0 for s in STATES}
        for e in self.entries.values():
            out[e.status] += 1
        return out

    # ---------------------------------------------------------------- persistence

    def to_dict(self) -> dict:
        return {"format": "argus.rules.library/1", "counts": self.counts(),
                "entries": [asdict(e) for e in sorted(self.entries.values(), key=lambda e: e.uid)]}

    def save(self, path) -> None:
        Path(path).write_text(json.dumps(self.to_dict(), indent=1, default=str))

    @classmethod
    def load(cls, path) -> "RuleLibrary":
        """A saved library, its check records in today's form (checks.normalise); statuses
        and histories exactly as saved."""
        from argus.rules import checks as C
        d = json.loads(Path(path).read_text())
        entries = []
        for e in d["entries"]:
            e = dict(e)
            e["checks"] = C.normalise(e.get("checks") or {}, e.get("status", ""), e.get("history") or [])
            entries.append(Entry(**e))
        return cls(entries)


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")
