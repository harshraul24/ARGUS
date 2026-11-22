"""Package a captured APT-Agent campaign into an ARGUS case directory.

Assembles:
    <out>/host/auth.log        (+ syslog if present)   captured target logs
    <out>/network/conn.log     (+ dns/ssh/...)          Zeek output
    <out>/meta.json            topology, expected_observables, capture,
                               category, mitre, ground truth from the labeller

Usage:
    python to_argus_case.py \
        --auth captured/auth.log --net captured/zeek/ \
        --ground-truth ground_truth.json \
        --target-ip 10.0.2.20 --attacker-ip 10.0.2.10 \
        --out ../../cases_linux/apt_ssh_bruteforce_001
"""
from __future__ import annotations

import argparse
import json
import shutil
from pathlib import Path

TECH_NAME = {
    "T1046": "Network Service Scanning",
    "T1110": "Brute Force",
    "T1210": "Exploitation of a Remote Service",
    "T1041": "Exfiltration Over C2 Channel",
    "T1021": "Remote Services",
}


def build(out: Path, auth: Path | None, syslog: Path | None, net_dir: Path | None,
          gt: dict, target_ip: str, attacker_ip: str,
          category: str, title: str, sensor_blind: list[str] | None,
          audit: Path | None = None) -> None:
    out = Path(out)
    (out / "host").mkdir(parents=True, exist_ok=True)
    (out / "network").mkdir(parents=True, exist_ok=True)

    if auth and auth.exists():
        shutil.copy(auth, out / "host" / "auth.log")
    if syslog and syslog.exists():
        shutil.copy(syslog, out / "host" / "syslog")
    if audit and audit.exists():
        # endpoint sensor: auditd execve log -> process_create claims (eCAR-parity)
        shutil.copy(audit, out / "host" / "audit.log")
    if net_dir and net_dir.exists():
        for f in net_dir.glob("*.log"):
            shutil.copy(f, out / "network" / f.name)

    primary = gt.get("primary_technique")
    techs = gt.get("techniques", [])
    actions = gt.get("actions", [])
    times = [a["time"] for a in actions if a.get("time")]
    window = {"start": min(times), "end": max(times)} if times else {}

    # What a defender SHOULD observe if the campaign happened — the coverage prior.
    # A backdoor exploit (T1210) intentionally lacks an auth record: that is the
    # blind spot the reasoner should surface, not evidence of innocence.
    expected = {
        "authlog": {"logon_failure": "T1110" in techs,
                    "logon_success": "T1210" in techs or "T1110" in techs},
        "zeek": {"conn": True, "ssh": "T1110" in techs or "T1210" in techs},
    }

    meta = {
        "meta_version": "v0.2",
        "scenario_id": out.name,
        "category": category,
        "title": title or (TECH_NAME.get(primary, "Linux campaign")),
        "generated_by": "APT-Agent + apt_capture harness",
        "topology": {
            "hosts": [
                {"name": "attacker", "ip": attacker_ip, "role": "attacker", "os": "Linux"},
                {"name": "target", "ip": target_ip, "role": "victim", "os": "Linux"},
            ],
            "zeek_sensor": {"host": "capture", "position": "attacker-target path"},
        },
        "capture": {"window": window, "clean_capture": True},
        "expected_observables": expected,
        "mitre": {"technique": primary or ""} if category == "attack" else {},
        "ground_truth": gt,
    }
    if sensor_blind:
        # Record a deliberately induced blind spot (harness coverage variant).
        meta["topology"]["zeek_sensor"]["blind_to"] = sensor_blind

    (out / "meta.json").write_text(json.dumps(meta, indent=2))
    print(f"wrote case {out}  category={category}  technique={primary}  "
          f"actions={len(actions)}")


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--auth", type=Path)
    ap.add_argument("--syslog", type=Path)
    ap.add_argument("--audit", type=Path, help="target's auditd audit.log (endpoint sensor)")
    ap.add_argument("--net", type=Path, help="directory of Zeek .log files")
    ap.add_argument("--ground-truth", type=Path)
    ap.add_argument("--target-ip", required=True)
    ap.add_argument("--attacker-ip", required=True)
    ap.add_argument("--category", default="attack", choices=["attack", "benign"])
    ap.add_argument("--title", default="")
    ap.add_argument("--sensor-blind", nargs="*", default=None,
                    help="subnets the capture sensor could NOT see (coverage variant)")
    ap.add_argument("--out", type=Path, required=True)
    args = ap.parse_args()

    gt = json.loads(args.ground_truth.read_text()) if args.ground_truth else {"category": args.category}
    build(args.out, args.auth, args.syslog, args.net, gt,
          args.target_ip, args.attacker_ip, args.category, args.title, args.sensor_blind,
          audit=args.audit)


if __name__ == "__main__":
    main()
