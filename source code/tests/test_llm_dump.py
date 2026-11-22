"""The dump-to-LLM baseline (tools/llm_dump_lab.py) on the REAL run1 lab windows. No model is
called: the answers are fixed, to check what the model is shown and how it is graded.

Run: .venv/bin/python -m pytest tests/ -q   (from `source code/`)
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

_ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(_ROOT / "tools"))

import lab_common as E                                           # noqa: E402
import llm_dump_lab as D                                         # noqa: E402
from argus.normalize.redact import assert_clean                  # noqa: E402

from lab_data import AGENT_WINDOW, needs_lab                     # noqa: E402


class _Answer:
    def __init__(self, text):
        self.text, self.cached = text, True


class _Fixed:
    def __init__(self, answer: dict):
        self.text = json.dumps(answer)

    def complete(self, prompt):
        return _Answer(self.text)


@needs_lab
def test_the_model_sees_every_event_of_the_window_and_no_secret():
    w = E.LAB / AGENT_WINDOW
    blob, ids, cut = D.render(w)
    events = (w / "events.jsonl").read_text().splitlines()
    assert not cut and len(ids) == len(events) == len(blob.splitlines())
    assert set(ids.values()) == {json.loads(x)["event_id"] for x in events}
    assert_clean(D.PROMPT + blob)
    assert "malicious" not in blob and "labels" not in blob          # nothing from the labels


@needs_lab
def test_it_is_graded_like_argus_and_fabricated_ids_are_counted():
    w = E.LAB / AGENT_WINDOW
    _, ids, _ = D.render(w)
    inv = {v: k for k, v in ids.items()}
    mal = E.labels(w)["malicious_event_ids"]
    rows, steps, _ = D.run([w], _Fixed({"disposition": "malicious",
                                        "malicious_events": [inv[m] for m in mal] + ["e999999"]}))
    m = D.metrics(rows, steps)
    assert m["attack_windows_flagged"] == "1/1" and m["event_precision"] == 1.0
    assert m["fabricated_ids"] == 1 and all(s["detected"] for s in steps)
    # a benign answer selects nothing, whatever it lists
    rows, steps, _ = D.run([w], _Fixed({"disposition": "benign", "malicious_events": [inv[mal[0]]]}))
    assert D.metrics(rows, steps)["events_cited"] == 0 and not any(s["detected"] for s in steps)
