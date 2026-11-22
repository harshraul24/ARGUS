"""Response cache and run manifest — reproducibility.

An LLM in the loop makes research irreproducible, which is fatal for a thesis.
Every call is keyed by sha256(provider, model, prompt, params), so:

  * a re-run replays byte-identically from cache, with no API key and no spend
  * the cache ships as a research artifact — reviewers reproduce without credentials
  * "did my pipeline change, or did the vendor's model drift?" becomes answerable,
    because you can re-run against the frozen cache and compare

This is P0.8 in the plan and it exists before any LLM result is generated, not after.
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

DEFAULT_DIR = Path(os.environ.get("ARGUS_LLM_CACHE", ".argus_cache/llm"))


def key_for(provider: str, model: str, prompt: str, params: dict[str, Any]) -> str:
    blob = json.dumps(
        {"provider": provider, "model": model, "prompt": prompt,
         "params": {k: params[k] for k in sorted(params)}},
        sort_keys=True, ensure_ascii=False,
    )
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


@dataclass
class CacheEntry:
    key: str
    provider: str
    model: str
    prompt_sha: str
    response: str
    latency_s: float
    created_at: float
    params: dict[str, Any] = field(default_factory=dict)


class ResponseCache:
    def __init__(self, directory: Path | str = DEFAULT_DIR, read_only: bool = False) -> None:
        self.dir = Path(directory)
        self.read_only = read_only
        self.hits = 0
        self.misses = 0
        self.dir.mkdir(parents=True, exist_ok=True)

    def _path(self, key: str) -> Path:
        return self.dir / f"{key[:2]}" / f"{key}.json"

    def get(self, key: str) -> CacheEntry | None:
        p = self._path(key)
        if not p.exists():
            self.misses += 1
            return None
        self.hits += 1
        return CacheEntry(**json.loads(p.read_text()))

    def put(self, entry: CacheEntry) -> None:
        if self.read_only:
            return
        p = self._path(entry.key)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(asdict(entry), indent=2))

    def stats(self) -> dict:
        total = self.hits + self.misses
        return {"hits": self.hits, "misses": self.misses,
                "hit_rate": round(self.hits / total, 3) if total else None,
                "entries": sum(1 for _ in self.dir.rglob("*.json"))}


@dataclass
class RunManifest:
    """Everything needed to reproduce a run."""
    provider: str
    model: str
    params: dict[str, Any]
    cache_dir: str
    started_at: float = field(default_factory=time.time)
    calls: int = 0
    cache_hits: int = 0
    live_calls: int = 0
    prompt_shas: list[str] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["cache_fingerprint"] = hashlib.sha256(
            "".join(sorted(self.prompt_shas)).encode()).hexdigest()[:16]
        return d

    def save(self, path: Path) -> None:
        Path(path).parent.mkdir(parents=True, exist_ok=True)
        Path(path).write_text(json.dumps(self.to_dict(), indent=2))
