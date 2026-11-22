"""Auto-labeller: APT-Agent experiment log -> structured ground truth.

APT-Agent does not emit a ground-truth file, but its `APT-Agent_experiment_log.txt`
records everything needed: per-iteration Tactic, relative TIME, the selected
Metasploit module (as `Best match:` and in the `CMM EXPLOIT`/`CMM EXFILTRATE`
JSON), and each step's success/fail. This parses that into an ordered action
trace with absolute timestamps and ATT&CK technique labels.

Usage:
    python label_campaign.py APT-Agent_experiment_log.txt \
        --start 2026-03-02T21:10:00Z --out ground_truth.json
"""
from __future__ import annotations

import argparse
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

HERE = Path(__file__).parent
ATTACK_MAP = json.loads((HERE / "module_attack_map.json").read_text())
ATTACK_MAP.pop("_comment", None)

RE_ITER = re.compile(r"---\s*Iteration\s+(?P<n>\d+)\s*---\s*TIME:\s*(?P<t>[\d.]+)")
RE_TACTIC = re.compile(r"^Tactic:\s*(?P<tactic>\w+)")
RE_BEST = re.compile(r"Best match:\s*(?P<mod>\S+)")
RE_CMM = re.compile(r"CMM (?:EXPLOIT|EXFILTRATE):\s*(?P<json>\[.*\])")
RE_SESSION = re.compile(r"Session\s+\S+:\s*type=(?P<type>\w+)")


def map_technique(text: str) -> str | None:
    """Longest-substring match against the module map."""
    text = (text or "").lower()
    best = None
    for key, tech in ATTACK_MAP.items():
        if key.lower() in text and (best is None or len(key) > len(best[0])):
            best = (key, tech)
    return best[1] if best else None


def parse(log_text: str, start: datetime) -> dict:
    actions: list[dict] = []
    techniques: set[str] = set()
    cur_tactic = None
    cur_iter = 0
    cur_offset = 0.0

    for line in log_text.splitlines():
        it = RE_ITER.search(line)
        if it:
            cur_iter = int(it.group("n"))
            cur_offset = float(it.group("t"))
            continue
        tac = RE_TACTIC.match(line.strip())
        if tac:
            cur_tactic = tac.group("tactic")
            # RECON is itself an ATT&CK-labellable action (nmap -> T1046).
            if cur_tactic == "RECON":
                techniques.add("T1046")
                actions.append({
                    "iter": cur_iter, "tactic": "RECON",
                    "time": _abs(start, cur_offset), "technique": "T1046",
                    "detail": "reconnaissance", "result": "n/a"})
            continue
        best = RE_BEST.search(line)
        if best:
            tech = map_technique(best.group("mod"))
            if tech:
                techniques.add(tech)
            continue
        cmm = RE_CMM.search(line)
        if cmm:
            try:
                entries = json.loads(cmm.group("json"))
            except json.JSONDecodeError:
                continue
            for e in entries:
                tech = map_technique(e.get("cmd", ""))
                if tech:
                    techniques.add(tech)
                actions.append({
                    "iter": e.get("iter"), "tactic": cur_tactic or "?",
                    "time": _abs(start, cur_offset), "technique": tech,
                    "detail": e.get("cmd"), "result": e.get("result")})

    # de-duplicate actions on (iter, detail)
    seen, deduped = set(), []
    for a in actions:
        key = (a["iter"], a["detail"])
        if key not in seen:
            seen.add(key)
            deduped.append(a)

    succeeded = any(a["result"] == "success" and a["technique"] == "T1041"
                    for a in deduped)
    return {
        "category": "attack",
        "campaign_start": start.isoformat().replace("+00:00", "Z"),
        "techniques": sorted(techniques),
        "primary_technique": _primary(techniques),
        "objective_reached": succeeded,
        "actions": deduped,
    }


def _abs(start: datetime, offset: float) -> str:
    return (start + timedelta(seconds=offset)).isoformat().replace("+00:00", "Z")


def _primary(techs: set[str]) -> str | None:
    # exfiltration > exploitation > brute force > recon
    for t in ("T1041", "T1210", "T1110", "T1046"):
        if t in techs:
            return t
    return None


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("log")
    ap.add_argument("--start", required=True, help="campaign start, ISO-8601 e.g. 2026-03-02T21:10:00Z")
    ap.add_argument("--out", default=None)
    args = ap.parse_args()

    start = datetime.fromisoformat(args.start.replace("Z", "+00:00")).astimezone(timezone.utc)
    gt = parse(Path(args.log).read_text(errors="ignore"), start)
    text = json.dumps(gt, indent=2)
    if args.out:
        Path(args.out).write_text(text)
        print(f"wrote {args.out}  ({len(gt['actions'])} actions, techniques {gt['techniques']})")
    else:
        print(text)


if __name__ == "__main__":
    main()
