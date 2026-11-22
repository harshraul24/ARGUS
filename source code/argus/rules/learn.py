"""Rule learning (S3 on Linux) as one call, shared by the workbench and tools/rules_induce.py.

  1. episodes   per window, the process trees whose launches are new to that host's history
                (the host's other windows), label-free (argus.rules.episodes)
  2. write      the model writes up to 3 rules per episode; C1–C3 run on the episode and
                failing rules go back with the checks' findings (argus.rules.induce)
  3. C4         a surviving rule may fire on at most `max_rate` of its host's other windows
  4. C5         on C4 survivors: a source that may decide on its own flags the same events —
                a deciding hand-written rule, or a Sigma rule rated medium or higher — and is
                itself quiet by C4's bar on that host (checks.quiet_hits). Agreement between
                written rules is noted, never confirms. `approve` (optional) is the analyst's
                C5 path: a decision on each shadow rule, recorded as a C5 pass
  5. lifecycle  rejected / shadow (C1–C4) / active (C1–C5); duplicates of an active rule (the
                same behaviour id, or the same events in every window) are retired

The checks and their order are defined once, in checks.py.

`combine` adds a new run's rules to an existing library without undoing any decision in it.

No labels are read here. The API key, if any, lives in the client the caller passes in.
"""
from __future__ import annotations

import threading
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from argus.case import load_case
from argus.reason import hypotheses as H
from argus.reason.context import CaseContext
from argus.rules import checks as C
from argus.rules import induce as I
from argus.rules import to_hypotheses
from argus.rules.episodes import History, Redactor, find_episodes, render
from argus.rules.library import RuleLibrary

# C5's hand-written confirmers: exactly the hypotheses that may decide a case on their own.
# Context-only primitives (discovery, staging, exfiltration, beacon, novelty) never decide
# alone (amendment A2), so they never confirm a rule into deciding either (A3)
HAND_SOURCES = tuple(h.technique for h in H.HYPOTHESES if h.decides)
SIGMA_LEVELS = ("medium", "high", "critical")


class KeyRefused(RuntimeError):
    """The model endpoint refused the credentials: nothing is learned or written."""


@dataclass
class Window:
    name: str
    path: Path
    host: str
    operation: str


@dataclass
class Learned:
    library: RuleLibrary
    windows: list[str]
    fired: dict[str, dict[str, set]]              # survivor -> window -> events
    hand_hits: dict[str, dict[str, set]]
    sigma_hits: dict[str, dict[str, set]]
    quiet_sigma: set[str]
    episodes: list = field(default_factory=list)  # [{"ep", "text", "renameable"}]
    inductions: dict = field(default_factory=dict)
    approvals: list = field(default_factory=list)
    merged: list = field(default_factory=list)
    meter: dict = field(default_factory=dict)
    sigma_rules: int = 0


class Meter:
    """Model calls, cache hits, latency and characters, across worker threads."""

    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.calls = self.live = self.cached = self.failed = 0
        self.latency = 0.0
        self.prompt_chars = self.response_chars = 0

    def wrap(self, client):
        def complete(prompt: str) -> str:
            try:
                r = client.complete(prompt)
            except Exception:
                with self.lock:
                    self.failed += 1
                raise
            with self.lock:
                self.calls += 1
                self.cached += r.cached
                self.live += not r.cached
                self.latency += r.latency_s
                self.prompt_chars += len(prompt)
                self.response_chars += len(r.text)
            return r.text
        return complete

    def to_dict(self) -> dict:
        return {"calls": self.calls, "failed_calls": self.failed, "live_calls": self.live,
                "cache_hits": self.cached, "model_seconds": round(self.latency, 1),
                "prompt_chars": self.prompt_chars, "response_chars": self.response_chars,
                "approx_tokens_in": self.prompt_chars // 4, "approx_tokens_out": self.response_chars // 4}


def _eid(claims) -> set:
    return {c.facts.get("_event_id") for c in claims if c.facts.get("_event_id")}


def quiet_sigma_sources(sigma: list[dict]) -> list[dict]:
    """Sigma rules eligible to confirm: rated at least medium (lab plan F8)."""
    return [r for r in sigma if (r.get("provenance") or {}).get("level") in SIGMA_LEVELS]


def episodes(windows: list[Window], max_rate: float = 0.25):
    """(cases, history per host, jobs): the novel episodes of every window, label-free."""
    cases = {w.name: load_case(w.path) for w in windows}
    by_host: dict[str, list[str]] = defaultdict(list)
    for w in windows:
        by_host[w.host].append(w.name)
    history = {h: History.build({n: cases[n].claims for n in ns}) for h, ns in by_host.items()}
    host_of = {w.name: w.host for w in windows}
    jobs = []
    for w in windows:
        cl = cases[w.name].claims
        hist = history[host_of[w.name]]
        red = Redactor(cl)
        for ep in find_episodes(cl, w.name, hist, max_rate=max_rate):
            text, _ = render(ep, hist, red, max_rate=max_rate)
            jobs.append({"ep": ep, "text": text, "renameable": C.renameable_images(ep.claims)})
    return cases, by_host, jobs


def learn(windows: list[Window], client_factory: Callable[[], object], model: str,
          sigma: list[dict] | None = None, memory: str = "", max_rate: float = 0.25,
          max_repairs: int = 2, workers: int = 4,
          approve: Callable[[RuleLibrary, dict], list] | None = None,
          progress: Callable[[str, int, int], None] | None = None) -> Learned:
    """Learn a rule library from `windows`. `client_factory()` returns an argus LLMClient
    (one per worker thread). `approve(library, fired)` may promote or retire shadow rules
    and returns its moves. `progress(stage, done, total)` reports along the way."""
    say = progress or (lambda *_: None)
    say("episodes", 0, len(windows))
    cases, by_host, jobs = episodes(windows, max_rate)
    host_of = {w.name: w.host for w in windows}
    rec = {w.name: w.operation for w in windows}
    names = [w.name for w in windows]
    say("episodes", len(windows), len(windows))

    # ---- write + C1–C3 + repair (model calls)
    meter = Meter()
    local = threading.local()
    abort = threading.Event()

    def client():
        if not hasattr(local, "c"):
            local.c = client_factory()
        return local.c

    def run(j):
        ep = j["ep"]
        ind = I.Induction(origin=ep.eid)
        if abort.is_set():
            ind.errors.append("skipped: the endpoint refused the credentials")
            return ind
        try:
            return I.induce_episode(meter.wrap(client()), j["text"], ep.claims, cases[ep.capture].health,
                                    ep.eid, model, j["renameable"], max_repairs, memory)
        except Exception as exc:                           # one episode never sinks the run...
            ind.errors.append(f"{type(exc).__name__}: {str(exc)[:300]}")
            # ...but a refused key sinks every episode: stop instead of failing on each
            if getattr(getattr(exc, "response", None), "status_code", None) in (401, 403):
                abort.set()
            return ind

    inductions: dict[str, I.Induction] = {}
    say("writing", 0, len(jobs))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(run, j) for j in jobs]
        for f in as_completed(futs):
            ind = f.result()
            inductions[ind.origin] = ind
            say("writing", len(inductions), len(jobs))
    if abort.is_set() or (meter.calls == 0 and any(i.errors for i in inductions.values())):
        first = next(e for i in inductions.values() for e in i.errors)
        raise KeyRefused(first[:200])

    # ---- library: every attempt, with its fate
    lib = RuleLibrary()
    ep_of = {j["ep"].eid: j["ep"] for j in jobs}
    survivors: dict[str, dict] = {}
    for eid in sorted(inductions):
        ep = ep_of[eid]
        for a in inductions[eid].attempts:
            e = lib.add(a.rule, {"capture": ep.capture, "recording": rec[ep.capture], "host": host_of[ep.capture],
                                 "episode": eid, "episode_root_image": ep.root_image, "round": a.round})
            lib.record(e.uid, a.checks)
            if a.superseded_by is not None:
                lib.transition(e.uid, "rejected", f"repaired: superseded by {a.superseded_by}")
            elif not I.passed(a.checks):
                first = next(k for k in C.KEYS[:3] if not C.passed_all(a.checks, (k,)))
                lib.transition(e.uid, "rejected", f"{first}: {a.checks[first].detail[:200]}")
            else:
                survivors[e.uid] = a.rule

    # ---- C4 + firing on every window (no labels)
    say("checking", 0, len(names))
    hyps = dict(zip(survivors, to_hypotheses(list(survivors.values()))))
    hand = {h.technique: h for h in H.HYPOTHESES if h.technique in HAND_SOURCES}
    sig = quiet_sigma_sources(sigma or [])
    sig_h = dict(zip([r["id"] for r in sig], to_hypotheses(sig)))
    sig_name = {r["id"]: r["name"] for r in sig}
    fired: dict[str, dict[str, set]] = {u: {} for u in hyps}
    hand_hits: dict[str, dict[str, set]] = {t: {} for t in hand}
    sigma_hits: dict[str, dict[str, set]] = {u: {} for u in sig_h}
    for i, n in enumerate(names):
        lc = cases[n]
        ctx = CaseContext(claims=lc.claims, health=lc.health)
        for hs, dest in ((hyps, fired), (hand, hand_hits), (sig_h, sigma_hits)):
            for u, h in hs.items():
                s, hits, _ = C.rule_score(h, lc.claims, ctx)
                if s > 0:
                    dest[u][n] = _eid(hits)
        say("checking", i + 1, len(names))

    # C5's confirmers, each held to C4's bar on the host where it agrees (checks.quiet_hits)
    quiet_hand = {t: C.quiet_hits(hh, host_of, by_host, max_rate) for t, hh in hand_hits.items()}
    quiet_sig = {u: C.quiet_hits(f, host_of, by_host, max_rate) for u, f in sigma_hits.items()}
    quiet = {u for u, f in quiet_sig.items() if f}
    confirmers = ([(f"hand:{t}", {"human"}, hh) for t, hh in quiet_hand.items()]
                  + [(f"sigma:{sig_name[u]}", {"sigma"}, quiet_sig[u]) for u in sorted(quiet)])
    c4 = {}
    for u in hyps:
        origin = lib.entries[u].origin
        ref = [n for n in by_host[origin["host"]] if n != origin["capture"]]
        c4[u] = C.c4_quiet([n for n in ref if n in fired[u]], ref, max_rate)
        lib.record(u, {"C4_quiet": c4[u]})
    passed_c4 = [u for u in hyps if c4[u].passed]
    for u in hyps:
        if not c4[u].passed:                        # C5 is not reached
            lib.transition(u, "rejected", f"C4_quiet: {c4[u].detail}")
            continue
        e = lib.entries[u]
        my_rec = {e.origin["recording"]}
        written = [(f"llm:{o}", {lib.entries[o].origin["recording"]}, fired[o]) for o in passed_c4 if o != u]
        c5 = C.c5_confirmed(fired[u], my_rec, confirmers, written)
        lib.record(u, {"C5_confirmed": c5})
        llm_only = c5.data["llm_agreement"] and not c5.passed
        lib.transition(u, "shadow", "passed C1–C4" + (
            f"; only LLM rules agree ({', '.join(c5.data['llm_agreement'][:2])}): a non-LLM "
            "source is required to promote" if llm_only else ""))
        if c5.passed:
            lib.transition(u, "active", f"passed C5: agrees with {', '.join(c5.data['confirmed_by'][:3])}")

    approvals = approve(lib, fired) if approve else []

    # one active copy of each behaviour, and of each set of events
    seen: dict[str, str] = {}
    for e in sorted(lib.by_status("active"), key=lambda e: e.uid):
        sem = e.rule["provenance"]["semantic_id"]
        if sem in seen:
            lib.transition(e.uid, "retired", f"duplicate of {seen[sem]}")
        else:
            seen[sem] = e.uid
    merged = lib.merge_duplicates(fired)
    say("done", 1, 1)
    return Learned(library=lib, windows=names, fired=fired, hand_hits=hand_hits, sigma_hits=sigma_hits,
                   quiet_sigma=quiet, episodes=jobs, inductions=inductions, approvals=approvals,
                   merged=merged, meter=meter.to_dict(), sigma_rules=len(sig))


def hits_on(windows: list[Window], library: RuleLibrary) -> dict[str, dict[str, set]]:
    """Active and shadow rule id -> window -> event ids it fires on."""
    entries = library.by_status("active", "shadow")
    hyps = dict(zip([e.uid for e in entries], to_hypotheses([e.rule for e in entries])))
    hits: dict[str, dict[str, set]] = {u: {} for u in hyps}
    for w in windows:
        lc = load_case(w.path)
        ctx = CaseContext(claims=lc.claims, health=lc.health)
        for u, h in hyps.items():
            s, sel, _ = C.rule_score(h, lc.claims, ctx)
            if s > 0:
                hits[u][w.name] = _eid(sel)
    return hits


def combine(old: RuleLibrary | None, new: RuleLibrary, windows: list[Window]) -> tuple[RuleLibrary, list]:
    """The old library with the new run's rules added. Every rule already in the old library
    keeps its status (an analyst's approval or retirement stands); a new rule that fires on
    exactly the same events as an existing one is retired as its duplicate."""
    if old is None:
        return new, []
    lib = RuleLibrary(list(old.entries.values()) + [e for u, e in new.entries.items() if u not in old.entries])
    return lib, lib.merge_duplicates(hits_on(windows, lib))
