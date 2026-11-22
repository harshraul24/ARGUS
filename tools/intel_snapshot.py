"""Dated, hashed snapshots of community intelligence for ARGUS.

A capture may only be scored with intelligence published BEFORE it was recorded, or the
attack's own public write-ups leak into the test. So intelligence is never read live: each
source is exported as it stood at `--as-of`, into intel/snapshots/<name>/, with a manifest
naming the commit or version, its date, the licence and a hash of every file. Results cite
the snapshot by name and aggregate hash.

Sources (cloned/downloaded into intel/sources/ with full history):
  sigma     SigmaHQ/sigma, rules/ only           Detection Rule License (DRL) 1.1
  gtfobins  GTFOBins/GTFOBins.github.io, _gtfobins/   GPL-3.0
  attack    MITRE ATT&CK Enterprise STIX bundle, the newest version released before --as-of
            (ATT&CK Terms of Use: royalty-free, attribution required)

Usage (from the ARGUS root):
  .venv/bin/python tools/intel_snapshot.py --as-of 2026-10-06 --name lab
"""
from __future__ import annotations

import argparse
import hashlib
import io
import json
import shutil
import subprocess
import tarfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SRC = ROOT / "intel" / "sources"
OUT = ROOT / "intel" / "snapshots"

GIT = {
    "sigma": ("sigma", "https://github.com/SigmaHQ/sigma", ["rules"], "Detection Rule License (DRL) 1.1"),
    "gtfobins": ("GTFOBins.github.io", "https://github.com/GTFOBins/GTFOBins.github.io", ["_gtfobins"], "GPL-3.0"),
}


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(["git", "-C", str(repo), *args], check=True, capture_output=True, text=True).stdout.strip()


def _export(repo: Path, commit: str, paths: list[str], dest: Path) -> None:
    data = subprocess.run(["git", "-C", str(repo), "archive", "--format=tar", commit, *paths],
                          check=True, capture_output=True).stdout
    with tarfile.open(fileobj=io.BytesIO(data)) as t:
        t.extractall(dest, filter="data")


def _hash_tree(d: Path) -> tuple[int, str]:
    h = hashlib.sha256()
    files = sorted(p for p in d.rglob("*") if p.is_file())
    for p in files:
        h.update(str(p.relative_to(d)).encode())
        h.update(hashlib.sha256(p.read_bytes()).digest())
    return len(files), h.hexdigest()


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--as-of", required=True, help="YYYY-MM-DD: nothing published after this is included")
    ap.add_argument("--name", required=True)
    args = ap.parse_args()
    dest = OUT / args.name
    if dest.exists():
        shutil.rmtree(dest)
    dest.mkdir(parents=True)
    man = {"name": args.name, "as_of": args.as_of, "created": time.strftime("%Y-%m-%dT%H:%M:%S"),
           "sources": {}}

    for key, (dirname, url, paths, lic) in GIT.items():
        repo = SRC / dirname
        commit = _git(repo, "rev-list", "-1", f"--before={args.as_of}T00:00:00Z", "HEAD")
        if not commit:
            man["sources"][key] = {"error": f"no commit before {args.as_of}"}
            continue
        date = _git(repo, "show", "-s", "--format=%cI", commit)
        _export(repo, commit, paths, dest / key)
        n, agg = _hash_tree(dest / key)
        man["sources"][key] = {"url": url, "commit": commit, "commit_date": date, "paths": paths,
                               "licence": lic, "files": n, "sha256": agg}
        print(f"  {key:<9} {commit[:10]} {date}  {n} files  {agg[:16]}")

    idx = json.loads((SRC / "attack" / "index.json").read_text())
    ent = next(c for c in idx["collections"] if "Enterprise" in c["name"])
    ok = [v for v in ent["versions"] if v["modified"][:10] < args.as_of]
    v = max(ok, key=lambda v: v["modified"])
    f = SRC / "attack" / f"enterprise-attack-{v['version']}.json"
    if not f.exists():
        raise SystemExit(f"ATT&CK {v['version']} is the version for {args.as_of}; download {v['url']} first")
    (dest / "attack").mkdir()
    shutil.copy(f, dest / "attack" / f.name)
    man["sources"]["attack"] = {"url": v["url"], "version": v["version"], "modified": v["modified"],
                                "licence": "MITRE ATT&CK Terms of Use (royalty-free, attribution)",
                                "files": 1, "sha256": hashlib.sha256(f.read_bytes()).hexdigest()}
    print(f"  attack    v{v['version']} {v['modified'][:10]}")

    man["aggregate_sha256"] = hashlib.sha256(json.dumps(
        {k: s.get("sha256") for k, s in sorted(man["sources"].items())}).encode()).hexdigest()
    (dest / "MANIFEST.json").write_text(json.dumps(man, indent=1))
    print(f"snapshot {args.name} as of {args.as_of}: aggregate {man['aggregate_sha256'][:16]} -> {dest}")


if __name__ == "__main__":
    main()
