#!/usr/bin/env python3
"""Create a Linux multi-tactic adversary profile in CALDERA from its OWN stockpile.

It asks CALDERA for its abilities, keeps the ones that (a) have a linux executor and (b) match
a target ATT&CK technique in the plan below, orders them across the kill chain, and POSTs a new
adversary profile. It references CALDERA's existing, published abilities by ATT&CK id and orders
them — it does not author any attack commands; those live in CALDERA's stockpile.

Run on the Mac (reaches Kali's CALDERA over the vmnet) or on Kali itself:
    CALDERA_KEY=<api_key_red from conf/default.yml> \
    python3 build_linux_profile.py --server http://192.168.64.8:8888

Then use the printed adversary in a new Operation against group 'red'.
"""
from __future__ import annotations
import argparse, json, os, sys, uuid, urllib.request, urllib.error

# LAB_TEST_SUITE.md §5 profiles, as {tactic: [ATT&CK techniques]}. This is eval DESIGN — which
# tactics each capture must exercise — expressed as ATT&CK ids, not procedures. The builder
# resolves each technique to one of CALDERA's own published Linux abilities.
PROFILES = {
    "A": {"discovery": ["T1082", "T1033", "T1016", "T1049", "T1087.001", "T1518"]},
    "B": {"discovery": ["T1057", "T1083"],
          "credential-access": ["T1552.001", "T1552.004"],
          "collection": ["T1005", "T1074.001", "T1560.001"],
          "exfiltration": ["T1041"]},
    "C": {"discovery": ["T1082", "T1016"],
          "lateral-movement": ["T1021.004"],
          "defense-evasion": ["T1070.003", "T1070.002"]},
    "D": {"discovery": ["T1057", "T1083"],
          "credential-access": ["T1552.003"],
          "collection": ["T1560.001"],
          "exfiltration": ["T1048"]},
    "E": {"discovery": ["T1069"],
          "lateral-movement": ["T1021.004"],
          "collection": ["T1005"],
          "defense-evasion": ["T1070.002", "T1070.004"]},
}
# Kill-chain order the selected abilities are laid out in.
TACTIC_ORDER = ["discovery", "credential-access", "collection", "staging",
                "exfiltration", "lateral-movement", "defense-evasion", "impact"]
# P9: drop abilities that have a linux executor but target ANOTHER platform's files, so they
# no-op on Debian (run 1's FreeBSD /etc/master.passwd ability). Match on ability name.
DENY_NAME_SUBSTR = ["master.passwd"]


def _api(server, path, key, data=None):
    req = urllib.request.Request(
        server.rstrip("/") + path,
        headers={"KEY": key, "Content-Type": "application/json"},
        data=json.dumps(data).encode() if data is not None else None,
        method="POST" if data is not None else "GET")
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return json.load(r)
    except urllib.error.HTTPError as e:
        sys.exit(f"CALDERA API {path} -> HTTP {e.code}: {e.read().decode(errors='ignore')[:200]}")
    except urllib.error.URLError as e:
        sys.exit(f"cannot reach CALDERA at {server} ({e.reason}) — is the server up and the IP right?")


def _linux(ab):
    return any((e.get("platform") == "linux") for e in (ab.get("executors") or []))


def _runnable(ab):
    """P9: a usable attack-data ability — has a linux executor and isn't a known no-op here."""
    if not _linux(ab):
        return False
    name = (ab.get("name") or "").lower()
    return not any(bad in name for bad in DENY_NAME_SUBSTR)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--server", default="http://192.168.2.7:8888")
    ap.add_argument("--key", default=os.environ.get("CALDERA_KEY", ""))
    ap.add_argument("--profile", default="A", choices=sorted(PROFILES),
                    help="which LAB_TEST_SUITE profile to build (A..E)")
    ap.add_argument("--name", default=None, help="adversary name (default ARGUS-Linux-<profile>)")
    ap.add_argument("--ability-ids", default=None,
                    help="comma-separated ability_ids to use verbatim, in order (overrides selection; P9)")
    ap.add_argument("--manifest", default=None, help="write the chosen ability IDs here (run manifest, §6.2)")
    ap.add_argument("--dry-run", action="store_true", help="print the choice for review; don't create")
    a = ap.parse_args()
    if not a.key:
        sys.exit("need the CALDERA API key: CALDERA_KEY=... (from conf/default.yml, api_key_red)")
    name = a.name or f"ARGUS-Linux-{a.profile}"

    abilities = _api(a.server, "/api/v2/abilities", a.key)
    by_id = {ab.get("ability_id"): ab for ab in abilities}
    by_tech = {}
    for ab in abilities:
        if _runnable(ab):
            by_tech.setdefault(ab.get("technique_id") or "", []).append(ab)

    ordering, picked, missing = [], [], []
    if a.ability_ids:                                  # P9: explicit IDs, used verbatim and in order
        for aid in [x.strip() for x in a.ability_ids.split(",") if x.strip()]:
            ab = by_id.get(aid)
            if not ab:
                sys.exit(f"ability id not found in stockpile: {aid}")
            ordering.append(aid)
            picked.append((ab.get("tactic", "?"), ab.get("technique_id", "?"), ab.get("name", "?")))
    else:
        plan = PROFILES[a.profile]
        for tactic in TACTIC_ORDER:
            for t in plan.get(tactic, []):
                cand = by_tech.get(t) or []
                if cand:
                    ab = cand[0]
                    if ab["ability_id"] not in ordering:
                        ordering.append(ab["ability_id"])
                        picked.append((tactic, t, ab.get("name", "?")))
                else:
                    missing.append((tactic, t))

    print(f"profile {a.profile}: {len(ordering)} runnable linux abilities across "
          f"{len({p[0] for p in picked})} tactics:")
    for tac, t, n in picked:
        print(f"  {tac:18} {t:12} {n}")
    if missing:
        print("\nno runnable linux ability for (coverage gap — report as untested):")
        for tac, t in missing:
            print(f"  {tac:18} {t}")

    manifest = {"profile": a.profile, "name": name, "server": a.server,
                "abilities": [{"tactic": tac, "technique": t, "ability_id": aid, "name": n}
                              for (tac, t, n), aid in zip(picked, ordering)]}
    if a.manifest:
        __import__("pathlib").Path(a.manifest).write_text(json.dumps(manifest, indent=2))
        print(f"\nwrote manifest {a.manifest}")

    if a.dry_run:
        print("\n--dry-run: not created."); return
    if not ordering:
        sys.exit("\nno usable abilities — check the stockpile plugin, or pass --ability-ids.")

    adv = {"adversary_id": str(uuid.uuid4()), "name": name,
           "description": f"LAB_TEST_SUITE profile {a.profile}; abilities selected by ATT&CK id.",
           "atomic_ordering": ordering}
    res = _api(a.server, "/api/v2/adversaries", a.key, adv)
    print(f"\ncreated adversary '{res.get('name')}'  id={res.get('adversary_id')}")
    print("→ CALDERA UI: Operations → new operation → this adversary → group 'red' → Start.")


if __name__ == "__main__":
    main()
