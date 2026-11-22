"""Record passed checks on a library entry, so a test can move it the way the pipeline does:
the library refuses shadow without C1–C4 passed and active without C5 passed (checks.py)."""
from __future__ import annotations

from argus.rules import checks as C


def passed(lib, uid: str, through: str = "C4_quiet", source: str = "hand-written rule") -> None:
    keys = C.KEYS[: C.KEYS.index(through) + 1]
    lib.record(uid, {k: C.Check(k, True, "", {"source": source} if k == "C5_confirmed" else {}) for k in keys})
