"""Where the rule-writing model looks: novel process-tree episodes (S3 §5, step 3).

Odin showed the model the rarest EVENTS of a capture, and most of what it wrote was
background: rare is not malicious, and an isolated event carries no story. ARGUS shows
it EPISODES instead — a process and everything its descendants did — chosen by novelty
against the host's own history:

  1. every claim gets a behaviour signature (who launched what; who touched which
     watched path; who connected where), with volatile parts (digits, GUIDs, home
     directory names) normalised;
  2. a process launch is NOVEL when its (parent > image) pair occurs in at most
     `max_rate` of the host's other captures;
  3. each novel launch climbs to its highest ancestor that is not a session hub
     (lineage.HUB_CHILD_IMAGES) and did something in the capture: the episode root. Launches sharing a root are one
     episode; a hub and its descendants are never part of another root's episode;
  4. episodes are ranked by novel launches, and one with fewer than `min_novel` is not
     an episode but a lone event (Odin's failure mode) and is skipped.

Everything here is label-free: the only reference is the host's other captures, which
are assumed mostly benign (the same assumption as C4), never ground truth.

`render` turns an episode into prompt text. Attacker-written strings (commands, paths)
are fenced as «untrusted data», and this capture's identity (addresses, user names) is
redacted so a rule cannot key on it.
"""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from dataclasses import dataclass, field

from argus.reason.lineage import HUB_CHILD_IMAGES, ProcessGraph, user_writable

# ============================================================ behaviour signatures

_GUID = re.compile(r"\{?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\}?")
_HEX = re.compile(r"\b[0-9a-f]{12,}\b")
_DIGITS = re.compile(r"\d+")
_PROFILE = re.compile(r"(/home/)[^/]+")


def _norm(v) -> str:
    s = str(v or "").lower()
    s = _GUID.sub("{g}", s)
    s = _HEX.sub("{h}", s)
    s = _PROFILE.sub(r"\1*", s)
    return _DIGITS.sub("0", s)


def _f(c, k) -> str:
    return str(c.facts.get(k) or "").lower()


_PRIVATE = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|f[cd][0-9a-f]{2}:|fe80:)", re.I)


def locality(ip) -> str:
    """loopback / internal / external, from the destination address alone."""
    ip = str(ip or "").lower()
    if not ip:
        return ""
    if ip.startswith("127.") or ip in ("::1", "0.0.0.0", "::"):
        return "loopback"
    return "internal" if _PRIVATE.match(ip) else "external"


def signature(c) -> str | None:
    t = c.claim_type
    if t == "process_create":
        return f"launch|{_f(c, 'parent')}>{_f(c, 'image')}"
    if t.startswith("file_"):
        return f"{t}|{_f(c, 'image')}|{_norm(c.facts.get('file_path'))}"
    if t == "host_network_connection":
        return (f"net|{_f(c, 'image')}|{c.facts.get('dst_port')}|{locality(c.facts.get('dst_ip'))}"
                f"|{_f(c, 'direction')}")
    return None


class History:
    """Which behaviour signatures each of the host's captures contains."""

    def __init__(self, sigs: dict[str, set[str]]) -> None:
        self.sigs = sigs

    @classmethod
    def build(cls, captures: dict[str, list]) -> "History":
        return cls({name: {s for s in map(signature, claims) if s}
                    for name, claims in captures.items()})

    def rate(self, sig: str | None, exclude: str) -> float:
        """Share of the OTHER captures in which `sig` occurs (1.0 if unknown)."""
        if sig is None:
            return 1.0
        ref = [n for n in self.sigs if n != exclude]
        return sum(sig in self.sigs[n] for n in ref) / len(ref) if ref else 0.0


# ============================================================ episodes

@dataclass
class Episode:
    capture: str
    root: str
    root_image: str
    novel_launches: list[str]                 # claim ids of the novel process launches
    processes: set[str]                       # the root's subtree, hubs pruned
    claims: list = field(default_factory=list)

    @property
    def eid(self) -> str:
        return f"{self.capture}#{self.root}"

    def to_dict(self) -> dict:
        return {"eid": self.eid, "capture": self.capture, "root": self.root,
                "root_image": self.root_image, "novel_launches": len(self.novel_launches),
                "processes": len(self.processes), "claims": len(self.claims)}


def _pruned_subtree(g: ProcessGraph, root: str, hub_threshold: int) -> set[str]:
    out, todo = set(), [root]
    while todo:
        k = todo.pop()
        if k in out:
            continue
        if k != root and g.is_hub(k, hub_threshold):
            continue                              # a hub's activity is not this episode's
        out.add(k)
        todo.extend(g.children.get(k, ()))
    return out


def find_episodes(claims, capture: str, history: History, max_rate: float = 0.25,
                  min_novel: int = 2, top: int = 3,
                  hub_threshold: int = HUB_CHILD_IMAGES) -> list[Episode]:
    g = ProcessGraph.from_claims(claims)
    if g is None:
        return []
    novel_by_root: dict[str, list] = defaultdict(list)
    for c in claims:
        if c.claim_type != "process_create":
            continue
        if history.rate(signature(c), capture) > max_rate:
            continue
        actors = g.actors(c)
        if not actors:
            continue
        root = actors[0]
        for a in g.ancestry(actors[0])[1:]:
            # a hub is never a root; an ancestor that did nothing in this capture adds
            # nothing to the episode but a name the capture never recorded
            if g.is_hub(a, hub_threshold) or not g.claims_of.get(a):
                break
            root = a
        novel_by_root[root].append(c)
    ranked = sorted(novel_by_root.items(), key=lambda kv: (-len(kv[1]), kv[0]))
    out = []
    for root, launches in ranked:
        if len(launches) < min_novel or len(out) >= top:
            continue
        procs = _pruned_subtree(g, root, hub_threshold)
        scoped = list({c.claim_id: c for k in sorted(procs) for c in g.claims_of.get(k, ())}.values())
        out.append(Episode(capture=capture, root=root, root_image=g.image.get(root, "?"),
                           novel_launches=[c.claim_id for c in launches], processes=procs,
                           claims=scoped))
    return out


# ============================================================ redaction and fencing

_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
# system accounts every Linux host has: not this capture's identity
_SYSTEM_USERS = {"root", "daemon", "nobody", "man", "_apt", "messagebus", "systemd-network",
                 "systemd-resolve", "systemd-timesync", "sshd", "syslog", "polkitd"}


class Redactor:
    """This capture's identity — IP addresses and account names — replaced by placeholders,
    so the model describes behaviour rather than this host."""

    def __init__(self, claims) -> None:
        names: set[str] = set()
        for c in claims:
            for k in ("user", "principal"):
                v = str(c.facts.get(k) or "")
                for part in re.split(r"[\\@]", v):
                    if len(part) >= 3 and part.lower() not in _SYSTEM_USERS and not part.isdigit():
                        names.add(part)
        self.names = sorted(names, key=lambda n: (-len(n), n))   # stable: prompts are cache keys
        self._pat = (re.compile("|".join(re.escape(n) for n in self.names), re.I)
                     if self.names else None)

    def __call__(self, v) -> str:
        s = _IPV4.sub("<ip>", str(v))
        return self._pat.sub("<name>", s) if self._pat else s


def fence(v, redact, limit: int = 320) -> str:
    s = redact(v).replace("«", "<").replace("»", ">").replace("\n", " ")
    return "«" + (s[:limit] + "…" if len(s) > limit else s) + "»"


# ============================================================ rendering

_ITEM = {"file_": ("file_path", "audit_key"),
         "host_network_connection": ("dst_port", "locality", "direction")}


def _item(c, redact) -> str:
    for prefix, keys in _ITEM.items():
        if c.claim_type.startswith(prefix):
            parts = []
            for k in keys:
                v = locality(c.facts.get("dst_ip")) if k == "locality" else c.facts.get(k)
                if v is None or v == "":
                    continue
                parts.append(f"{k}={fence(v, redact, 160)}" if k == "file_path" else f"{k}={v}")
            return " ".join(parts)
    return ""


def _ranked(counts: Counter) -> list[tuple[str, int]]:
    """Most common first, ties by name: prompts are cache keys, so no set order may leak."""
    return sorted(counts.items(), key=lambda kv: (-kv[1], kv[0]))


def _folder(path) -> str:
    w = user_writable(path)
    return ("USER-WRITABLE folder" if w else "system folder" if w is False else "folder unknown")


def render(ep: Episode, history: History, redact, max_procs: int = 30, max_items: int = 4,
           max_rate: float = 0.25) -> tuple[str, dict]:
    """(prompt text, process label map). Process keys are replaced by p1..pn labels.

    Per process: its launch and command line, activity counts by claim type, and up to
    `max_items` claims whose signature is new to the host's history — one per claim type
    first, rarest first. A claim several processes performed is listed once."""
    g = ProcessGraph.from_claims(ep.claims)
    novel = set(ep.novel_launches)
    creation: dict[str, object] = {}
    for c in ep.claims:
        if c.claim_type == "process_create":
            a = g.actors(c)
            if a:
                creation.setdefault(a[0], c)

    def rare_items(k):
        out = defaultdict(list)
        for c in g.claims_of.get(k, ()):
            if c.claim_type == "process_create":
                continue
            r = history.rate(signature(c), ep.capture)
            if r <= max_rate:
                out[c.claim_type].append((r, c))
        return out

    rare = {k: rare_items(k) for k in ep.processes}
    # which processes to show: novel launches, then processes with novel activity, then the
    # rest; every shown process brings its ancestors up to the root, so the tree is whole
    order = sorted(ep.processes, key=lambda k: (creation.get(k) is None or creation[k].claim_id not in novel,
                                                -sum(len(v) for v in rare[k].values()), k))
    shown: set[str] = set()
    for k in order:
        chain = [a for a in g.ancestry(k) if a in ep.processes]
        if len(shown | set(chain)) > max_procs and shown:
            continue
        shown.update(chain)
    labels = {k: f"p{i + 1}" for i, k in enumerate(sorted(shown, key=lambda k: (g.depth(k), k)))}

    lines = []
    listed: set[str] = set()

    def pick(k):
        by_type = {t: sorted(v, key=lambda rc: (rc[0], rc[1].claim_id)) for t, v in rare[k].items()}
        by_type = {t: [c for _, c in v if c.claim_id not in listed] for t, v in by_type.items()}
        out, i = [], 0
        while len(out) < max_items and any(len(v) > i for v in by_type.values()):
            for t in sorted(by_type):
                if len(by_type[t]) > i and len(out) < max_items:
                    out.append(by_type[t][i])
            i += 1
        more = sum(len(v) for v in by_type.values()) - len(out)
        return out, more

    def emit(k, depth):
        pad = "  " * depth
        cr = creation.get(k)
        img = g.image.get(k, "?")
        head = f"{pad}{labels[k]} {img} — {_folder(g.path.get(k))}"
        if cr is None:
            head += " — started before this capture (no launch recorded)"
        else:
            head += (" — launch NEW to this host's history" if cr.claim_id in novel
                     else " — launch seen before on this host")
            head += f" [claim {cr.claim_id}]"
        lines.append(head)
        if cr is not None and cr.facts.get("command"):
            lines.append(f"{pad}   command {fence(cr.facts['command'], redact, 260)}")
        counts = Counter(c.claim_type for c in g.claims_of.get(k, ()) if c.claim_type != "process_create")
        if counts:
            lines.append(f"{pad}   activity: " + ", ".join(f"{t} {n}" for t, n in _ranked(counts)))
        items, more = pick(k)
        for c in items:
            listed.add(c.claim_id)
            lines.append(f"{pad}   new {c.claim_type} [claim {c.claim_id}] {_item(c, redact)}")
        if more:
            lines.append(f"{pad}   (+{more} more claims new to this host)")
        for ch in sorted(g.children.get(k, ()), key=lambda x: (x not in labels, x)):
            if ch in labels:
                emit(ch, depth + 1)

    if ep.root not in labels:
        return "", labels
    emit(ep.root, 0)
    hidden = [k for k in ep.processes if k not in shown]
    if hidden:
        imgs = Counter(g.image.get(k, "?") for k in hidden)
        lines.append(f"(+{len(hidden)} more processes in this episode, not shown: "
                     + ", ".join(f"{i}×{n}" for i, n in _ranked(imgs)[:8]) + ")")
    return "\n".join(lines), labels
