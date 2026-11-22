"""Linux host collectors — auth.log / syslog -> Claim objects.

Identity telemetry of a Linux host: SSH `Failed password` / `Accepted password` map
onto `logon_failure` / `logon_success` (read by the T1110 brute-force hypothesis), sudo
onto `privileged_command`, PAM sessions onto `session_opened`.

auth.log lines have no year and no timezone (a syslog quirk), so `year` is
passed in from the capture metadata; times are emitted ISO-8601 with a `Z`.
"""
from __future__ import annotations

import re
from datetime import datetime, timezone
from pathlib import Path

from argus.models import Claim, Control, Provenance
from argus.normalize.redact import redact

PRIVATE_NET = re.compile(r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.)")


def source_locality(ip: str | None) -> str:
    if not ip or ip in ("-", "", "::1", "127.0.0.1"):
        return "local"
    if PRIVATE_NET.match(ip):
        return "internal"
    return "external"


# syslog line prefix:  "Mar  2 21:10:05 victim sshd[1234]: ..."
SYSLOG = re.compile(
    r"^(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+"
    r"(?P<time>\d{2}:\d{2}:\d{2})\s+(?P<host>\S+)\s+"
    r"(?P<proc>[\w./-]+?)(?:\[(?P<pid>\d+)\])?:\s+(?P<msg>.*)$"
)

MONTHS = {m: i for i, m in enumerate(
    ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
     "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"], 1)}

RE_FAILED = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from "
    r"(?P<ip>\S+) port (?P<port>\d+)")
RE_ACCEPTED = re.compile(
    r"Accepted (?P<method>\w+) for (?P<user>\S+) from "
    r"(?P<ip>\S+) port (?P<port>\d+)")
RE_SESSION = re.compile(r"session opened for user (?P<user>[\w.-]+)")
RE_INVALID_USER = re.compile(r"Invalid user (?P<user>\S+) from (?P<ip>\S+)")
RE_SUDO = re.compile(
    r"(?P<who>[\w.-]+)\s*:.*?USER=(?P<target>[\w.-]+)\s*;\s*COMMAND=(?P<cmd>.+)$")


def _iso(mon: str, day: str, time_str: str, year: int) -> str | None:
    try:
        dt = datetime(year, MONTHS[mon], int(day),
                      *(int(x) for x in time_str.split(":")), tzinfo=timezone.utc)
        return dt.isoformat().replace("+00:00", "Z")
    except (KeyError, ValueError):
        return None


def collect_auth(path: Path, year: int, sensor_id: str = "authlog") -> list[Claim]:
    """/var/log/auth.log -> identity + privileged-command claims."""
    if not path.exists():
        return []
    claims: list[Claim] = []
    n = 0
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = SYSLOG.match(line)
        if not m:
            continue
        msg, host = m.group("msg"), m.group("host")
        ts = _iso(m.group("mon"), m.group("day"), m.group("time"), year)
        proc = m.group("proc")

        fail = RE_FAILED.search(msg)
        ok = RE_ACCEPTED.search(msg)
        sess = RE_SESSION.search(msg)
        sudo = RE_SUDO.search(msg) if proc.startswith("sudo") else None

        if fail:
            n += 1
            user, ip = fail.group("user"), fail.group("ip")
            claims.append(Claim(
                claim_id=f"auth_{n:05d}", modality="identity",
                claim_type="logon_failure", entity=user,
                event=f"ssh failed password for {user} from {ip}", time=ts,
                confidence=0.97,
                facts={"principal": user, "src_ip": ip, "is_remote": True,
                       "source_locality": source_locality(ip), "logon_type": "ssh",
                       "auth_package": "sshd", "host": host},
                # user is attacker-chosen (L1); the source IP is not (came over TCP)
                provenance=[Provenance(sensor_id=f"{sensor_id}:{host}",
                                       source=str(path), span=msg[:120],
                                       control=Control.L1)],
            ))
        elif ok:
            n += 1
            user, ip = ok.group("user"), ok.group("ip")
            claims.append(Claim(
                claim_id=f"auth_{n:05d}", modality="identity",
                claim_type="logon_success", entity=user,
                event=f"ssh accepted {ok.group('method')} for {user} from {ip}",
                time=ts, confidence=0.98,
                facts={"principal": user, "src_ip": ip, "is_remote": True,
                       "source_locality": source_locality(ip), "logon_type": "ssh",
                       "auth_method": ok.group("method"), "host": host},
                provenance=[Provenance(sensor_id=f"{sensor_id}:{host}",
                                       source=str(path), span=msg[:120],
                                       control=Control.L0)],
            ))
        elif sudo:
            n += 1
            cmd, _ = redact(sudo.group("cmd"))
            claims.append(Claim(
                claim_id=f"auth_{n:05d}", modality="endpoint",
                claim_type="privileged_command", entity=sudo.group("who"),
                event=f"sudo: {sudo.group('who')} ran a command as {sudo.group('target')}",
                time=ts, confidence=0.95,
                facts={"principal": sudo.group("who"), "target_user": sudo.group("target"),
                       "command": cmd, "host": host},
                # the command string is attacker-authored (L2)
                provenance=[Provenance(sensor_id=f"{sensor_id}:{host}",
                                       source=str(path), span=cmd[:120],
                                       control=Control.L2)],
            ))
        elif sess:
            n += 1
            claims.append(Claim(
                claim_id=f"auth_{n:05d}", modality="identity",
                claim_type="session_opened", entity=sess.group("user"),
                event=f"session opened for {sess.group('user')}", time=ts,
                confidence=0.9,
                facts={"principal": sess.group("user"), "host": host},
                provenance=[Provenance(sensor_id=f"{sensor_id}:{host}",
                                       source=str(path), span=msg[:120],
                                       control=Control.L0)],
            ))
    return claims


RE_SVC = re.compile(r"(?P<unit>[\w.@-]+)\.service|Started (?P<name>.+)")


def collect_syslog(path: Path, year: int, sensor_id: str = "syslog") -> list[Claim]:
    """/var/log/syslog -> service start/stop + generic host events.

    Deliberately light: the security signal on this substrate lives in auth.log
    and the network logs. syslog contributes service-control context.
    """
    if not path.exists():
        return []
    claims: list[Claim] = []
    n = 0
    for line in path.read_text(encoding="utf-8", errors="ignore").splitlines():
        m = SYSLOG.match(line)
        if not m:
            continue
        proc, msg, host = m.group("proc"), m.group("msg"), m.group("host")
        if proc not in ("systemd",) and "Started" not in msg and "Stopped" not in msg:
            continue
        ts = _iso(m.group("mon"), m.group("day"), m.group("time"), year)
        n += 1
        claims.append(Claim(
            claim_id=f"sys_{n:05d}", modality="endpoint",
            claim_type="service_control", entity=host,
            event=msg[:160], time=ts, confidence=0.7,
            facts={"host": host, "detail": msg[:200]},
            provenance=[Provenance(sensor_id=f"{sensor_id}:{host}",
                                   source=str(path), span=msg[:120],
                                   control=Control.L1)],
        ))
    return claims
