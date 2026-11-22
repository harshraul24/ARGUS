"""Behaviour vocabulary (lab plan fix F3): which ATT&CK tactics the detection community
associates with a Linux program.

Built by tools/behaviour_vocab.py from a dated intelligence snapshot's Linux Sigma rules
(detection metadata only): `id`, `uname`, `netstat`, `ss` -> discovery. A rule can then say
"a discovery program" instead of naming each one.

Rule field (argus.rules.dsl):  behaviour.tactics — multi-valued, the tactics of the program
that performed the claim (its image).

ARGUS loads the vocabulary shipped beside this module (`behaviour_vocab.json`, installed by
`tools/behaviour_vocab.py --install`; its hash is part of every freeze). `use(path)` swaps in
another for a block, and `use(None)` runs without one: the field is then None.
"""
from __future__ import annotations

import json
from contextlib import contextmanager
from functools import lru_cache
from pathlib import Path

DEFAULT_PATH = Path(__file__).with_name("behaviour_vocab.json")
_UNSET = object()
_VOCAB = _UNSET


def set_vocabulary(vocab: dict | None) -> None:
    global _VOCAB
    _VOCAB = vocab
    _lookup.cache_clear()


def vocabulary() -> dict | None:
    """The vocabulary in force: the default one unless another was set."""
    if _VOCAB is _UNSET:
        try:
            set_vocabulary(json.loads(DEFAULT_PATH.read_text()))
        except (OSError, ValueError):
            set_vocabulary(None)
    return _VOCAB


@contextmanager
def use(path_or_vocab):
    old = _VOCAB
    v = path_or_vocab
    set_vocabulary(json.loads(Path(v).read_text()) if isinstance(v, (str, Path)) else v)
    try:
        yield _VOCAB
    finally:
        if old is _UNSET:
            _reset()
        else:
            set_vocabulary(old)


def _reset() -> None:
    global _VOCAB
    _VOCAB = _UNSET
    _lookup.cache_clear()


def program(image) -> str:
    """`/usr/bin/whoami` -> `whoami`."""
    return str(image or "").rsplit("/", 1)[-1].lower()


@lru_cache(maxsize=8192)
def _lookup(name: str) -> tuple | None:
    v = vocabulary()
    if v is None:
        return None
    e = v["binaries"].get(name)
    return tuple(e["tactics"]) if e else ()


def tactics(claim):
    """The `behaviour.tactics` value for a claim, or None without a vocabulary."""
    if vocabulary() is None:
        return None
    return _lookup(program(claim.facts.get("image_path") or claim.facts.get("image")))
