"""W1 — an open hypothesis space, Linux only.

Every hypothesis declares its own indicators over ANY claim type, and the engine
evaluates all of them. Adding a technique is data, not a code change to the decision
function.

Hand-written here is only what is platform-neutral reasoning, not a command signature:

  identity / network   T1110 brute force (auth.log), T1046 port scan and T1210 exploited
                       service (Zeek) — network shapes the LLM cannot learn from process trees
  tactic primitives    discovery burst, local staging, exfiltration, C2 beacon — keyed on
                       the behaviour vocabulary (ATT&CK tactics the Sigma community assigns
                       to each Linux program, argus.normalize.behaviour) and on what the
                       sensors measured, never on a hand-written list of commands
  fusion               the kill chain (linked by process lineage) and novelty

Technique-level command rules are written by the S3 loop (argus.rules) from Linux
design episodes and must pass its label-free checks.
"""
from __future__ import annotations

import json
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from argus.models import Claim
from argus.normalize import behaviour
from argus.reason.context import CaseContext

Matcher = Callable[[list[Claim], CaseContext], tuple[list[Claim], float]]


@dataclass
class Indicator:
    name: str
    weight: float
    match: Matcher
    required: bool = False


@dataclass
class Expected:
    """What a sensor SHOULD show if this hypothesis is true (W6 input)."""
    sensor_id: str
    claim_type: str
    description: str
    target_hint: str = ""


@dataclass
class Hypothesis:
    technique: str
    name: str
    tactic: str
    indicators: list[Indicator]
    expected: list[Expected] = field(default_factory=list)
    # Technique impact, used for severity and for disposition.
    severity: float = 0.9
    # Unique id of a data rule (argus/rules). Several rules may share a technique, so the
    # engine keys results by `uid`; a Python hypothesis is keyed by its technique.
    rule_id: str = ""
    # A weak primitive (False) is reported as context and feeds the kill chain, but never
    # sets the disposition on its own (lab plan F2, generalised by amendment A2).
    decides: bool = True

    @property
    def uid(self) -> str:
        return self.rule_id or self.technique


# --------------------------------------------------------------- identity / network

def _logon_weight(claims: list[Claim]) -> float:
    return 0.5 * len(claims)


def m_remote_logon_success(claims, ctx):
    hits = [c for c in claims if c.claim_type == "logon_success" and c.facts.get("is_remote")]
    return hits, min(1.0, _logon_weight(hits) / 2.0) if hits else 0.0


def m_logon_failure_burst(claims, ctx):
    """W4 — rate-relative and grouped by source.

    v1 fired on `failed >= 3` regardless of who, from where, or against what
    background. Three mistyped passwords in a 20,644-event capture was enough.
    """
    fails = [c for c in claims if c.claim_type == "logon_failure"]
    if not fails:
        return [], 0.0

    by_src: dict[str, list[Claim]] = defaultdict(list)
    for c in fails:
        by_src[str(c.facts.get("src_ip", "-"))].append(c)

    best_hits: list[Claim] = []
    best = 0.0
    for src, group in by_src.items():
        if src in ("-", "", "127.0.0.1", "::1"):
            continue                                    # local noise, not a burst
        volume = ctx.anomaly(len(group), floor=3, saturate=20)
        ratio = ctx.failure_ratio()                     # rate within this capture
        targets = {c.facts.get("principal") for c in group}
        spread = min(1.0, len(targets) / 3.0)           # many usernames = spraying
        score = volume * (0.55 + 0.45 * ratio) * (0.6 + 0.4 * spread)
        if score > best:
            best, best_hits = score, group
    return best_hits, min(1.0, best)


def m_port_sweep(claims, ctx):
    """Many distinct ports probed between one source and one target (Zeek)."""
    pairs: dict[tuple[str, str], set[str]] = defaultdict(set)
    owner: dict[tuple[str, str], list[Claim]] = defaultdict(list)
    for c in claims:
        if c.claim_type not in ("network_connection", "remote_access_session"):
            continue
        s, d, p = c.facts.get("src_ip"), c.facts.get("dst_ip"), str(c.facts.get("dst_port", ""))
        if not (s and d and p.isdigit()):
            continue
        pairs[(s, d)].add(p)
        owner[(s, d)].append(c)

    best, hits = 0.0, []
    for key, ports in pairs.items():
        if len(ports) < 15:
            continue
        score = min(1.0, len(ports) / 100.0)
        if score > best:
            best, hits = score, owner[key][:60]
    return hits, best


# Reverse/bind-shell and handler ports: the callback signature of a LANDED exploit.
# 4444/4445 = Metasploit default handler; 6200 = vsftpd 2.3.4 backdoor bind shell (opened
# only when the backdoor fires); the rest are common reverse/bind-shell ports. Deliberately
# excludes standing services (e.g. 1524 ingreslock) that a benign scan probes without
# exploiting anything.
PAYLOAD_PORTS = ("4444", "4445", "5555", "6666", "1234", "12345", "31337",
                 "6200", "9999", "4443", "8443")


def m_post_exploit_activity(claims, ctx):
    """T1210 — a remote service was actually EXPLOITED (not merely used): a payload or
    shell callback on the wire. Session or sudo activity is not the signal: benign admin and
    cron sessions have it in equal measure. A backdoor that bypasses authentication leaves
    its expected `logon_success` ABSENT, which the coverage model reports, not scores."""
    payload = [c for c in claims
               if c.claim_type in ("network_connection", "remote_access_session")
               and (str(c.facts.get("dst_port")) in PAYLOAD_PORTS
                    or str(c.facts.get("src_port")) in PAYLOAD_PORTS)]
    if not payload:
        return [], 0.0
    return payload, min(1.0, 0.7 + 0.15 * (len(payload) - 1))


def m_service_probe(claims, ctx):
    """Recon against network services, from the network layer (supports T1210)."""
    hits = [c for c in claims
            if c.claim_type in ("remote_access_session", "network_connection")
            and str(c.facts.get("dst_port")) in ("21", "22", "23", "25", "80",
                                                  "445", "3306", "5432", "6667")]
    return hits, min(1.0, len(hits) / 3.0) if hits else 0.0


# ============================================================================
# Tactic primitives. They score the SHAPE of intrusion activity rather than one named
# technique. What a program is for comes from the behaviour vocabulary (Sigma's ATT&CK
# tags for Linux programs), so no command list is written by hand here; network facts
# are what the sensor measured.
# ============================================================================

def _procs(claims):
    return (c for c in claims if c.claim_type == "process_create")


def _has(c: Claim, tactic: str) -> bool:
    return tactic in (behaviour.tactics(c) or ())


def _remote(ip) -> bool:
    ip = str(ip or "")
    return bool(ip) and not ip.startswith("127.") and ip not in ("::1", "0.0.0.0", "::")


def m_discovery_burst(claims, ctx):
    """Many DISTINCT discovery programs in the window = reconnaissance. One `id` is
    benign; four or more different discovery programs is a survey of the host."""
    progs: dict[str, list[Claim]] = {}
    for c in _procs(claims):
        if _has(c, "discovery"):
            progs.setdefault(behaviour.program(c.facts.get("image_path") or c.facts.get("image")), []).append(c)
    n = len(progs)
    if n < 4:
        return [], 0.0
    return [c for lst in progs.values() for c in lst], ctx.anomaly(n, floor=4, saturate=8)


_STAGING_EXT = (".txt", ".zip", ".dat", ".log", ".csv", ".tar", ".gz", ".tgz", ".xml", ".json")


def m_local_staging(claims, ctx):
    """Command output redirected into files, or collection programs — staging."""
    hits = []
    for c in _procs(claims):
        cmd = str(c.facts.get("command") or "").lower()
        redirect = (">>" in cmd) or (" > " in cmd and any(e in cmd for e in _STAGING_EXT))
        if redirect or _has(c, "collection"):
            hits.append(c)
    if len(hits) < 3:
        return [], 0.0
    return hits, ctx.anomaly(len(hits), floor=3, saturate=12)


def m_exfil_c2(claims, ctx):
    """A program the community associates with exfiltration that connected to a
    non-loopback address. Needs the host's connect events (auditd `net` rule)."""
    hits = [c for c in claims if c.claim_type == "host_network_connection"
            and _session(c) and _has(c, "exfiltration")]
    if not hits:
        return [], 0.0
    return hits, min(1.0, 0.65 + 0.15 * (len(hits) - 1))


_BROWSER = ("chrome", "chromium", "firefox")


def _session(c: Claim) -> bool:
    """A connection that leaves the host: not loopback, not the unspecified address, and not
    a port-0 `connect()` (a UDP socket's route lookup, which opens no session)."""
    port = str(c.facts.get("dst_port") or "")
    return _remote(c.facts.get("dst_ip")) and port not in ("", "0", "None")


def m_c2_beacon(claims, ctx):
    """A non-browser process repeatedly reaching one host = beaconing. Only sessions that
    leave the host count: a beacon is traffic to a controller somewhere else."""
    tally: Counter = Counter()
    groups: dict[tuple, list] = {}
    for c in claims:
        if c.claim_type != "host_network_connection":
            continue
        if str(c.facts.get("direction")) not in ("outbound", "None", "none", ""):
            continue
        img = str(c.facts.get("image") or "").lower()
        dst = c.facts.get("dst_ip")
        if not _session(c) or any(b in img for b in _BROWSER):
            continue
        tally[(img, dst)] += 1
        groups.setdefault((img, dst), []).append(c)
    best_hits, best = [], 0.0
    for k, n in tally.items():
        if n >= 5:
            s = min(1.0, 0.5 + 0.08 * (n - 5))
            if s > best:
                best, best_hits = s, groups[k]
    return best_hits, best


# ============================================================================
# Novelty / rarity vs. a learned benign baseline. Detects "this host has never done
# this" without a signature. Fed as gated EVIDENCE (low severity), so rare-but-benign
# activity is at most suspicious and can be rebutted — never a standalone malicious
# verdict. Without a baseline (`_BASELINE_PATH` absent) it is disabled.
# ============================================================================

_BASELINE_PATH = Path(__file__).resolve().parents[1] / "assurance" / "behavior_baseline.json"
_baseline_cache: dict | None = None


def _baseline() -> dict:
    global _baseline_cache
    if _baseline_cache is None:
        try:
            _baseline_cache = json.loads(_BASELINE_PATH.read_text())
        except Exception:
            _baseline_cache = {"images": {}, "pairs": {}}
    return _baseline_cache


def m_rare_execution(claims, ctx):
    """Process lineages never seen in the benign baseline = behavioural novelty.
    Requires several (>=3) novel processes to fire, so a single new benign tool does
    not alarm; scored on the count of novel lineages, saturating."""
    b = _baseline()
    imgs, pairs = b.get("images", {}), b.get("pairs", {})
    if not imgs:                                       # no baseline -> disabled
        return [], 0.0
    novel = []
    for c in _procs(claims):
        # A baseline is population-specific: only judge the endpoint sensor's processes.
        if not any(str(p.sensor_id).startswith("auditd") for p in c.provenance):
            continue
        img = str(c.facts.get("image") or "").lower()
        par = str(c.facts.get("parent") or "").lower()
        if not img:
            continue
        # novel = this parent->child lineage never occurred in benign AND the image
        # itself is essentially unseen (count <= 1) in benign.
        if pairs.get(f"{par}>{img}", 0) == 0 and imgs.get(img, 0) <= 1:
            novel.append(c)
    if len(novel) < 3:
        return [], 0.0
    return novel, ctx.anomaly(len(novel), floor=3, saturate=15)


# ============================================================================
# Kill-chain correlation. Each primitive above is individually only suspicious; a real
# intrusion co-occurs several distinct tactics, in kill-chain order when timestamped.
# ============================================================================

_CHAIN_STAGES = (
    ("discovery", m_discovery_burst),
    ("staging",   m_local_staging),
    ("exfil",     m_exfil_c2),
    ("beacon",    m_c2_beacon),
)


def m_killchain(claims, ctx):
    """>=2 distinct behavioural tactics co-occurring = multi-stage intrusion. Score
    scales with how many distinct tactics are present, with a bonus when an early
    stage (discovery/staging) precedes an objective stage (exfil/beacon).

    W-E: when the claims carry process lineage, the stages must also be LINKED — they
    must fire on the subtree of one non-hub process, the episode root
    (`reason.lineage.find_episode`). Two unrelated processes each doing one suspicious
    thing in the same window are not a kill chain. Without lineage (auth.log, Zeek) the
    window-level rule applies. The episode is kept on `ctx.memo` for the engine."""
    scope = claims
    g = ctx.graph
    if g is not None:
        from argus.reason.lineage import find_episode
        key = ("episode", id(claims))
        if key not in ctx.memo:
            ctx.memo[key] = find_episode(_CHAIN_STAGES, claims, ctx)
        ep = ctx.memo[key]
        if ep is None:
            return [], 0.0
        ctx.memo["episode"] = ep
        scope = ep.claims
    fired: dict[str, str | None] = {}
    all_hits = []
    for name, fn in _CHAIN_STAGES:
        hits, s = fn(scope, ctx)
        if s > 0.0 and hits:
            fired[name] = min((c.time for c in hits if c.time), default=None)
            all_hits.extend(hits)
    n = len(fired)
    if n < 2:
        return [], 0.0
    base = min(1.0, (n - 1) / 3.0)                 # 2→0.33, 3→0.67, 4→1.0
    early = [fired[k] for k in ("discovery", "staging") if fired.get(k)]
    obj = [fired[k] for k in ("exfil", "beacon") if fired.get(k)]
    if early and obj and min(early) <= min(obj):   # kill-chain ordering bonus
        base = min(1.0, base + 0.1)
    seen, dedup = set(), []
    for c in all_hits:
        if c.claim_id not in seen:
            seen.add(c.claim_id)
            dedup.append(c)
    return dedup, base


HYPOTHESES: list[Hypothesis] = [
    Hypothesis(
        technique="T1110",
        name="Brute force",
        tactic="Credential Access",
        indicators=[
            Indicator("logon failure burst from a single source", 3.0, m_logon_failure_burst, required=True),
            Indicator("remote logon success (possible success)", 1.0, m_remote_logon_success),
        ],
        expected=[Expected("authlog", "logon_failure", "failed SSH logins in auth.log")],
        severity=0.7,
    ),
    Hypothesis(
        technique="T1046",
        name="Network service scanning",
        tactic="Discovery",
        indicators=[
            Indicator("many distinct ports probed on one target", 3.0, m_port_sweep, required=True),
        ],
        expected=[Expected("zeek", "network_connection", "connection records for the sweep")],
        severity=0.6,
    ),
    Hypothesis(
        technique="T1210",
        name="Exploitation of a remote service",
        tactic="Lateral Movement",
        indicators=[
            Indicator("payload or shell callback on the network", 3.0, m_post_exploit_activity, required=True),
            Indicator("prior service probing", 1.0, m_service_probe),
        ],
        # A legitimate session authenticates; a backdoor exploit does not, so absence here is
        # the coverage signal the reasoner should weigh, not rebut.
        expected=[Expected("authlog", "logon_success", "service authentication for the session")],
        severity=0.85,
    ),
    Hypothesis(
        technique="TA0007",
        name="Discovery activity (reconnaissance burst)",
        tactic="Discovery",
        indicators=[
            Indicator("many distinct discovery programs", 3.0, m_discovery_burst, required=True),
        ],
        severity=0.5,
        decides=False,
    ),
    Hypothesis(
        technique="TA0009",
        name="Local data staging / collection",
        tactic="Collection",
        indicators=[
            Indicator("output redirected to files, or collection programs", 3.0, m_local_staging, required=True),
        ],
        severity=0.55,
        decides=False,
    ),
    Hypothesis(
        technique="TA0010",
        name="Exfiltration",
        tactic="Exfiltration",
        indicators=[
            Indicator("exfiltration program reached a remote host", 3.0, m_exfil_c2, required=True),
            Indicator("non-browser beacon to one host", 1.0, m_c2_beacon),
        ],
        severity=0.85,
        decides=False,
    ),
    Hypothesis(
        technique="TA0011",
        name="Command-and-control beacon",
        tactic="Command and Control",
        indicators=[
            Indicator("non-browser process beaconing to one host", 3.0, m_c2_beacon, required=True),
        ],
        severity=0.7,
        decides=False,
    ),
    Hypothesis(
        technique="KILLCHAIN",
        name="Multi-stage intrusion (kill chain)",
        tactic="Multiple",
        indicators=[
            Indicator("co-occurring attack tactics in kill-chain order", 3.0, m_killchain, required=True),
        ],
        severity=0.9,
    ),
    Hypothesis(
        technique="NOVELTY",
        name="Anomalous / novel execution vs. baseline",
        tactic="Discovery",
        indicators=[
            Indicator("process lineages unseen in the benign baseline", 3.0, m_rare_execution, required=True),
        ],
        severity=0.35,     # gated: novelty alone is at most suspicious
        decides=False,
    ),
]
