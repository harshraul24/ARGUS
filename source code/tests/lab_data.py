"""Real Linux lab captures for the tests (cases_lab/, converted from the run1 and smoke
CALDERA operations by tools/apt_capture/auditd_to_windows.py). Nothing here is synthetic:
a test that needs these is skipped when they are absent.
"""
from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import pytest

from argus.case import load_case

ROOT = Path(__file__).resolve().parents[2]
LAB = ROOT / "cases_lab"
LINUX = ROOT / "cases_linux"

# run1 on web01: the agent starts at 12:52 (12:30 window); discovery steps at 13:45 (13:30)
AGENT_WINDOW = "run1_web01_1230"
STEPS_WINDOW = "run1_web01_1330"
HOST_WINDOWS = ("run1_web01_1200", "run1_web01_1230", "run1_web01_1300", "run1_web01_1330",
                "run1_web01_1400")

needs_lab = pytest.mark.skipif(not (LAB / AGENT_WINDOW / "events.jsonl").exists(),
                               reason="needs the converted run1 lab capture (cases_lab)")
needs_linux = pytest.mark.skipif(not LINUX.is_dir(), reason="needs cases_linux")


@lru_cache(maxsize=None)
def case(name: str):
    return load_case(LAB / name)


def claims(name: str) -> list:
    return [c.model_copy(deep=True) for c in case(name).claims]


def history():
    """web01's run1 windows: the host's own history."""
    from argus.rules.episodes import History
    return History.build({n: case(n).claims for n in HOST_WINDOWS})


def agent_episode():
    """The episode rooted at the CALDERA agent (splunkd, run from the user's home)."""
    from argus.rules.episodes import find_episodes
    eps = find_episodes(case(AGENT_WINDOW).claims, AGENT_WINDOW, history())
    return next(e for e in eps if e.root_image == "splunkd")
