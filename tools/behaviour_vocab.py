"""Build the behaviour vocabulary (lab plan fix F3) from one intelligence snapshot's Sigma rules.

For every Linux process-creation Sigma rule, the programs it selects (`Image` endings) are
credited with the rule's ATT&CK tactic tags. The result maps a program name to the tactics
the detection community associates with it (`whoami`, `id`, `uname` -> discovery).
Detection metadata only; no labels, nothing written by hand.

Each rule's credit is split across the programs it selects: a rule about one program
counts 1 for it, a rule listing twelve reconnaissance programs (the web-shell rules) counts
1/12 for each, so a long list cannot stamp its own tactic on every program it names. A
program selected by rules of many tactics (bash, python) is general-purpose: a
tactic is kept only when it carries at least `--min-share` of that program's weight. Full
weights are kept in the file.

Writes intel/snapshots/<name>/behaviour_vocab.json and, with --install, the copy ARGUS loads
by default (source code/argus/normalize/behaviour_vocab.json).

Usage (from the ARGUS root):  .venv/bin/python tools/behaviour_vocab.py --snapshot lab --install
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
from collections import Counter, defaultdict
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
TACTICS = {"reconnaissance", "resource_development", "initial_access", "execution", "persistence",
           "privilege_escalation", "defense_evasion", "credential_access", "discovery",
           "lateral_movement", "collection", "command_and_control", "exfiltration", "impact"}


def _program(value: str) -> str | None:
    name = re.split(r"[\\/]", str(value))[-1].lower().strip("*")
    if not name or any(c in name for c in "*?"):
        return None
    return name


def _programs(sel) -> set[str]:
    out = set()
    for s in (sel if isinstance(sel, list) else [sel]):
        if not isinstance(s, dict):
            continue
        for k, v in s.items():
            field, *mods = k.split("|")
            if field == "Image" and ("endswith" in mods or not mods):
                vals = v if isinstance(v, list) else [v]
                out |= {p for p in map(_program, vals) if p}
    return out


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--snapshot", required=True)
    ap.add_argument("--min-share", type=float, default=0.25)
    ap.add_argument("--install", action="store_true", help="also write the copy ARGUS loads by default")
    args = ap.parse_args()
    snap = ROOT / "intel" / "snapshots" / args.snapshot
    man = json.loads((snap / "MANIFEST.json").read_text())
    counts: dict[str, Counter] = defaultdict(Counter)
    rules_of: Counter = Counter()
    weight_of: Counter = Counter()
    used = 0
    for f in sorted((snap / "sigma" / "rules").rglob("*.yml")):
        try:
            docs = [d for d in yaml.safe_load_all(f.read_text(errors="ignore")) if isinstance(d, dict)]
        except yaml.YAMLError:
            continue
        for d in docs:
            ls = d.get("logsource") or {}
            if ls.get("category") != "process_creation" or ls.get("product") != "linux":
                continue
            tactics = {t[7:].replace("-", "_") for t in map(str, d.get("tags") or [])
                       if t.startswith("attack.") and t[7:].replace("-", "_") in TACTICS}
            if not tactics:
                continue
            progs = set()
            for k, sel in (d.get("detection") or {}).items():
                if k != "condition" and not k.startswith("filter"):
                    progs |= _programs(sel)
            if not progs:
                continue
            used += 1
            w = 1.0 / len(progs)
            for p in progs:
                rules_of[p] += 1
                weight_of[p] += w
                for t in tactics:
                    counts[p][t] += w
    binaries = {}
    for p, c in sorted(counts.items()):
        n = weight_of[p]
        binaries[p] = {"tactics": sorted(t for t, k in c.items() if k / n >= args.min_share),
                       "rules": rules_of[p], "weight": round(n, 4),
                       "tactic_weights": {t: round(k, 4) for t, k in c.most_common()}}
    out = {"format": "argus-behaviour-vocab/1", "platform": "linux", "snapshot": args.snapshot, "as_of": man["as_of"],
           "sigma_commit": man["sources"]["sigma"]["commit"], "min_share": args.min_share,
           "rules_used": used, "binaries": binaries}
    blob = json.dumps(out, indent=1, sort_keys=True)
    (snap / "behaviour_vocab.json").write_text(blob)
    if args.install:
        (ROOT / "source code" / "argus" / "normalize" / "behaviour_vocab.json").write_text(blob)
    print(f"{args.snapshot}: {len(binaries)} programs from {used} Sigma rules "
          f"(sha256 {hashlib.sha256(blob.encode()).hexdigest()[:16]})")
    for p in ("whoami", "id", "uname", "ps", "hostname", "netstat", "ss", "ip", "tar", "curl", "bash"):
        if p in binaries:
            print(f"  {p:<11} {binaries[p]['tactics']}  ({binaries[p]['rules']} rules)")


if __name__ == "__main__":
    main()
