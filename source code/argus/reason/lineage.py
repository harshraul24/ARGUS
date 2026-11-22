"""W-E — process lineage: claims as a causal tree, not a bag.

A kill-chain correlator that fuses discovery, staging and exfiltration primitives firing
ANYWHERE in the same window would, on a busy host, fuse two unrelated processes that each
do one suspicious-looking thing into a "kill chain". The lab windows carry the process
tree (auditd execve, `lineage.json`); this module uses it:

  * `ProcessGraph` is rebuilt from the claims themselves. The events collector attaches
    each performing process and its ancestry (`facts["_procs"]`), so every caller of
    `reason()` gets lineage without an interface change, and a claim set without
    lineage (auth.log, Zeek) simply has no graph — behaviour there is unchanged.
  * `find_episode` asks whether the kill-chain stages are linked by descent from one
    process — the episode root — and re-evaluates every stage on that root's subtree
    alone, so a stage only counts if it fires on the root's own activity.
  * The episode (root + every claim its subtree performed) is reported separately from
    hypothesis evidence: evidence is what supports the verdict, the episode is the scope
    an analyst would investigate. Keeping them apart keeps the audit trail honest.

A root may not be a SESSION HUB: a process whose direct children span many distinct
programs, in this window or over its recorded life (a login shell, systemd, a user-activity
driver). Fusing under a
hub is exactly the coincidence this module exists to prevent. The rule is instance-level
and label-free — it reads only the process tree — so renaming an implant after a hub's
image (masquerading) does not make it one.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

# A process whose direct children in the window span at least this many distinct
# programs is treated as a session hub, never an episode root. Carried over from the
# earlier prototype; to be re-checked on the lab's design operations.
HUB_CHILD_IMAGES = 4

# Executables under these folders are the OS or installed packages: writing there needs
# root. Anything else (home directories, /tmp, /var/tmp, /dev/shm, /run/user) runs from a
# folder its owner could write, so its NAME is the owner's choice (S3 §11). Decided from
# `image_path` in the telemetry, never labels.
TRUSTED_DIRS = ("/usr/bin/", "/usr/sbin/", "/bin/", "/sbin/", "/usr/lib/", "/usr/lib64/",
                "/usr/libexec/", "/lib/", "/lib64/", "/usr/local/bin/", "/usr/local/sbin/",
                "/usr/share/", "/opt/", "/snap/")


def user_writable(path) -> bool | None:
    """True if an executable at `path` runs from a folder a user can write; None when the
    path is not absolute (a kernel thread has none)."""
    p = str(path or "")
    if not p.startswith("/"):
        return None
    return not p.startswith(TRUSTED_DIRS)


class ProcessGraph:
    """Parent links, images, image paths and performed claims per process key
    (`pid@start`)."""

    def __init__(self) -> None:
        self.parent: dict[str, str | None] = {}
        self.image: dict[str, str] = {}
        self.path: dict[str, str] = {}
        self.children: dict[str, set[str]] = defaultdict(set)
        self.claims_of: dict[str, list] = defaultdict(list)
        # distinct child programs over each process's recorded life (the lineage map), which
        # a single window may show only part of
        self.life_children: dict[str, set[str]] = {}

    @classmethod
    def from_claims(cls, claims) -> "ProcessGraph | None":
        g = cls()
        seen = False
        for c in claims:
            chains = c.facts.get("_procs")
            if not chains:
                continue
            seen = True
            for chain in chains:
                for k, p in zip(chain, list(chain[1:]) + [None]):
                    if g.parent.get(k) is None:
                        g.parent[k] = p
                g.claims_of[chain[0]].append(c)
                # `image` is the performing process's image (for a creation, the created
                # process), so any claim names its actor; a creation is preferred because
                # a process started before the capture has no creation to read.
                img = str(c.facts.get("image") or "").lower()
                if img and (c.claim_type == "process_create" or chain[0] not in g.image):
                    g.image[chain[0]] = img
                    if c.facts.get("image_path"):
                        g.path[chain[0]] = str(c.facts["image_path"])
        if not seen:
            return None
        # processes known only from the lineage map (launched in an earlier window)
        for c in claims:
            for k, (img, path, *kids) in (c.facts.get("_proc_meta") or {}).items():
                if img and k not in g.image:
                    g.image[k] = str(img).lower()
                if path and k not in g.path:
                    g.path[k] = str(path)
                if kids and kids[0] and k not in g.life_children:
                    g.life_children[k] = {str(x).lower() for x in kids[0]}
        for k, p in g.parent.items():
            if p:
                g.children[p].add(k)
        return g

    @staticmethod
    def actors(claim) -> list[str]:
        return [ch[0] for ch in (claim.facts.get("_procs") or []) if ch]

    def ancestry(self, key: str, limit: int = 64) -> list[str]:
        """`key` and its ancestors, nearest first."""
        out = []
        while key and key not in out and len(out) < limit:
            out.append(key)
            key = self.parent.get(key)
        return out

    def depth(self, key: str) -> int:
        return len(self.ancestry(key)) - 1

    def subtree(self, key: str) -> set[str]:
        out, todo = set(), [key]
        while todo:
            k = todo.pop()
            if k in out:
                continue
            out.add(k)
            todo.extend(self.children.get(k, ()))
        return out

    def writable(self, key: str | None) -> bool | None:
        return user_writable(self.path.get(key)) if key else None

    def child_images(self, key: str) -> set[str]:
        return {self.image.get(c, "?") for c in self.children.get(key, ())}

    def is_hub(self, key: str, threshold: int = HUB_CHILD_IMAGES) -> bool:
        """A session hub by its children in this window or over its recorded life: a login
        shell that launched many programs is a hub even where it launched two."""
        kids = self.child_images(key) | self.life_children.get(key, set())
        return len(kids - {"?"}) >= threshold


@dataclass
class Episode:
    root: str
    root_image: str
    stages: list[str]
    claims: list = field(default_factory=list)       # every claim the root's subtree performed

    def to_dict(self) -> dict:
        return {"root": self.root, "root_image": self.root_image, "stages": self.stages,
                "n_claims": len(self.claims), "claim_ids": [c.claim_id for c in self.claims]}


def find_episode(stages, claims, ctx, hub_threshold: int = HUB_CHILD_IMAGES) -> Episode | None:
    """The non-hub process whose own subtree fires the most distinct stages (at least
    two); among equals, the deepest.

    `stages` is [(name, matcher)]. Candidates are the ancestors of every process that
    performed a stage hit in the whole window; each candidate's subtree is re-scored with
    the same matchers, so a stage counts only if it fires on that subtree's claims alone.
    Most stages first, so a single process that happens to match two stages does not
    stand in for the process that launched the whole operation; deepest among equals,
    because an ancestor that adds nothing is not more specific. A hub is never a root.
    """
    g = ctx.graph
    if g is None:
        return None
    hit_actors: set[str] = set()
    for _, fn in stages:
        hits, s = fn(claims, ctx)
        if s > 0:
            for c in hits:
                hit_actors.update(g.actors(c))
    best: tuple | None = None
    for root in {a for k in hit_actors for a in g.ancestry(k)}:
        if g.is_hub(root, hub_threshold):
            continue
        # a claim performed by several processes of the subtree is still one claim
        scoped = list({c.claim_id: c for k in g.subtree(root)
                       for c in g.claims_of.get(k, ())}.values())
        fired = [name for name, fn in stages if scoped and fn(scoped, ctx)[1] > 0]
        if len(fired) < 2:
            continue
        rank = (len(fired), g.depth(root), root)
        if best is None or rank > best[0]:
            best = (rank, Episode(root=root, root_image=g.image.get(root, "?"),
                                  stages=fired, claims=scoped))
    return best[1] if best else None
