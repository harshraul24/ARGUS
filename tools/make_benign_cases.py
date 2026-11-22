#!/usr/bin/env python3
"""Generate benign Linux test cases in the ARGUS `cases_linux/` layout.

Every scenario here is *legitimate activity*, so the expected verdict is a
non-attack disposition. Several are deliberately near-misses: activity that
looks like a technique to a rate-only detector (an authorised scanner sweeping
ports, a mistyped password, a backup account logging in every night). Those are
the cases that measure specificity rather than confirm it.

Each case is written as:

    <out>/<scenario_id>/
        meta.json            category: benign, ground_truth, confounds
        host/auth.log        sshd / sudo / cron, syslog line format
        host/syslog          service control noise
        network/conn.log     Zeek TSV
        network/dns.log      (some scenarios)
        network/capture_loss.log, notice.log  (degraded-sensor scenario)

Usage:
    python3 tools/make_benign_cases.py --list
    python3 tools/make_benign_cases.py --out cases_linux
    python3 tools/make_benign_cases.py --out cases_linux --only benign_typo_login_002 --force
"""
from __future__ import annotations

import argparse
import json
import shutil
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from pathlib import Path

MON = ["Jan", "Feb", "Mar", "Apr", "May", "Jun",
       "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"]

TARGET = "10.0.2.20"          # the monitored host
JUMPHOST = "10.0.2.5"         # admin workstation
BACKUP = "10.0.2.6"           # backup server
SCANNER = "10.0.2.9"          # authorised vulnerability scanner
WORKSTATION = "10.0.2.31"     # ordinary user's desktop
DNS_SERVER = "10.0.2.2"


# --------------------------------------------------------------- log writers

def syslog_line(ts: datetime, host: str, proc: str, pid: int | None, msg: str) -> str:
    """`Sep  8 08:05:41 host sshd[4285]: message` — the format collect_auth parses."""
    stamp = f"{MON[ts.month - 1]} {ts.day:2d} {ts:%H:%M:%S}"
    tag = f"{proc}[{pid}]" if pid is not None else proc
    return f"{stamp} {host} {tag}: {msg}"


@dataclass
class ZeekLog:
    """A Zeek TSV log: header block plus rows, written only if non-empty."""
    name: str
    fields: list[str]
    types: list[str]
    rows: list[list[str]] = field(default_factory=list)

    def render(self) -> str:
        head = [
            "#separator \\x09",
            "#set_separator\t,",
            "#empty_field\t(empty)",
            "#unset_field\t-",
            f"#path\t{self.name.removesuffix('.log')}",
            "#fields\t" + "\t".join(self.fields),
            "#types\t" + "\t".join(self.types),
        ]
        body = ["\t".join(str(v) for v in r) for r in self.rows]
        return "\n".join(head + body + ["#close\t-"]) + "\n"


def conn_log() -> ZeekLog:
    return ZeekLog(
        "conn.log",
        ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
         "proto", "service", "duration", "conn_state"],
        ["time", "string", "addr", "port", "addr", "port",
         "enum", "string", "interval", "string"])


def dns_log() -> ZeekLog:
    return ZeekLog(
        "dns.log",
        ["ts", "uid", "id.orig_h", "id.orig_p", "id.resp_h", "id.resp_p",
         "proto", "query", "qtype_name", "rcode_name"],
        ["time", "string", "addr", "port", "addr", "port",
         "enum", "string", "string", "string"])


def epoch(ts: datetime) -> str:
    return f"{ts.replace(tzinfo=timezone.utc).timestamp():.6f}"


def uid(n: int) -> str:
    return f"C{n:07d}Bx"


@dataclass
class Case:
    scenario_id: str
    title: str
    why_benign: str
    confounds: list[str]
    start: datetime
    end: datetime
    auth: list[str] = field(default_factory=list)
    syslog: list[str] = field(default_factory=list)
    zeek: list[ZeekLog] = field(default_factory=list)
    expected_observables: dict = field(default_factory=dict)
    clean_capture: bool = True
    sensor_note: str | None = None

    def meta(self) -> dict:
        return {
            "meta_version": "v0.2",
            "scenario_id": self.scenario_id,
            "category": "benign",
            "title": self.title,
            "generated_by": "tools/make_benign_cases.py (synthetic benign corpus)",
            "topology": {
                "hosts": [
                    {"name": "target", "ip": TARGET, "role": "victim", "os": "Linux"},
                    {"name": "jumphost", "ip": JUMPHOST, "role": "admin", "os": "Linux"},
                ],
                "zeek_sensor": {"host": "capture", "position": "target segment"},
            },
            "capture": {
                "window": {"start": iso(self.start), "end": iso(self.end)},
                "clean_capture": self.clean_capture,
                **({"sensor_note": self.sensor_note} if self.sensor_note else {}),
            },
            "expected_observables": self.expected_observables,
            "mitre": {"technique": None},
            "ground_truth": {
                "category": "benign",
                "objective_reached": False,
                "techniques": [],
                "primary_technique": None,
                "why_benign": self.why_benign,
                # What a rate-only or presence-only detector would mistake this for.
                "confounds": self.confounds,
                "actions": [],
            },
        }

    def write(self, out: Path, force: bool) -> Path:
        d = out / self.scenario_id
        if d.exists():
            if not force:
                raise FileExistsError(f"{d} exists (use --force to overwrite)")
            shutil.rmtree(d)
        (d / "host").mkdir(parents=True)
        (d / "network").mkdir(parents=True)
        (d / "meta.json").write_text(json.dumps(self.meta(), indent=2) + "\n")
        if self.auth:
            (d / "host" / "auth.log").write_text("\n".join(self.auth) + "\n")
        if self.syslog:
            (d / "host" / "syslog").write_text("\n".join(self.syslog) + "\n")
        for log in self.zeek:
            (d / "network" / log.name).write_text(log.render())
        return d


def iso(ts: datetime) -> str:
    return ts.replace(tzinfo=timezone.utc).isoformat().replace("+00:00", "Z")


def boot_noise(t0: datetime, host: str) -> list[str]:
    """Background syslog every capture has: cron, ntp, logrotate."""
    lines = []
    for i in range(4):
        t = t0 + timedelta(minutes=17 * i)
        lines.append(syslog_line(t, host, "systemd", None,
                                 "Started Session of user root."))
        lines.append(syslog_line(t + timedelta(seconds=2), host, "systemd", None,
                                 "Stopped Session of user root."))
    return lines


def cron_noise(t0: datetime, host: str, hours: int = 6) -> list[str]:
    lines = []
    for h in range(hours):
        t = t0 + timedelta(hours=h)
        pid = 5000 + h
        lines.append(syslog_line(t, host, "CRON", pid,
                                 "pam_unix(cron:session): session opened for user root by (uid=0)"))
        lines.append(syslog_line(t + timedelta(seconds=1), host, "CRON", pid,
                                 "pam_unix(cron:session): session closed for user root"))
    return lines


# ----------------------------------------------------------------- scenarios

def sc_admin_maintenance() -> Case:
    """Routine patching window: one admin, one session, expected sudo commands."""
    host = "appsrv01"
    t0 = datetime(2026, 3, 4, 9, 12, 0)
    auth = [
        syslog_line(t0, host, "sshd", 2101,
                    f"Accepted publickey for sysadmin from {JUMPHOST} port 51120 ssh2: RSA SHA256:9c1f"),
        syslog_line(t0, host, "sshd", 2101,
                    "pam_unix(sshd:session): session opened for user sysadmin by (uid=0)"),
        syslog_line(t0 + timedelta(minutes=1), host, "sudo", None,
                    "sysadmin : TTY=pts/0 ; PWD=/home/sysadmin ; USER=root ; COMMAND=/usr/bin/apt-get update"),
        syslog_line(t0 + timedelta(minutes=4), host, "sudo", None,
                    "sysadmin : TTY=pts/0 ; PWD=/home/sysadmin ; USER=root ; COMMAND=/usr/bin/apt-get -y upgrade"),
        syslog_line(t0 + timedelta(minutes=11), host, "sudo", None,
                    "sysadmin : TTY=pts/0 ; PWD=/home/sysadmin ; USER=root ; COMMAND=/bin/systemctl restart nginx"),
        syslog_line(t0 + timedelta(minutes=13), host, "sshd", 2101,
                    "pam_unix(sshd:session): session closed for user sysadmin"),
    ]
    sysl = boot_noise(t0 - timedelta(hours=1), host) + [
        syslog_line(t0 + timedelta(minutes=11), host, "systemd", None, "Stopped A high performance web server."),
        syslog_line(t0 + timedelta(minutes=11, seconds=2), host, "systemd", None, "Started A high performance web server."),
    ]
    c = conn_log()
    c.rows.append([epoch(t0), uid(1), JUMPHOST, 51120, TARGET, 22, "tcp", "ssh", "790.4", "SF"])
    for i in range(3):  # apt talking to the internal mirror
        t = t0 + timedelta(minutes=1, seconds=20 * i)
        c.rows.append([epoch(t), uid(10 + i), TARGET, 40100 + i, "10.0.2.8", 80, "tcp", "http", "12.5", "SF"])
    d = dns_log()
    d.rows.append([epoch(t0 + timedelta(minutes=1)), uid(20), TARGET, 53311, DNS_SERVER, 53,
                   "udp", "mirror.internal.lan", "A", "NOERROR"])
    return Case(
        scenario_id="benign_admin_maintenance_001",
        title="Scheduled patching window by an administrator",
        why_benign="Key-based login by a known admin from the jump host, followed by "
                   "package-manager and service-restart commands inside the change window.",
        confounds=["remote logon success", "privileged commands as root",
                   "service stop/start pair resembling service tampering"],
        start=t0 - timedelta(hours=1), end=t0 + timedelta(minutes=20),
        auth=auth, syslog=sysl, zeek=[c, d],
        expected_observables={"authlog": {"logon_success": True, "logon_failure": False},
                              "zeek": {"conn": True, "ssh": True, "dns": True}},
    )


def sc_typo_then_login() -> Case:
    """Two mistyped passwords then success — the classic v1 false positive."""
    host = "appsrv01"
    t0 = datetime(2026, 3, 5, 8, 41, 12)
    auth = [
        syslog_line(t0, host, "sshd", 3310,
                    f"Failed password for jdoe from {WORKSTATION} port 44810 ssh2"),
        syslog_line(t0 + timedelta(seconds=9), host, "sshd", 3310,
                    f"Failed password for jdoe from {WORKSTATION} port 44812 ssh2"),
        syslog_line(t0 + timedelta(seconds=21), host, "sshd", 3312,
                    f"Accepted password for jdoe from {WORKSTATION} port 44814 ssh2"),
        syslog_line(t0 + timedelta(seconds=21), host, "sshd", 3312,
                    "pam_unix(sshd:session): session opened for user jdoe by (uid=0)"),
        syslog_line(t0 + timedelta(minutes=6), host, "sshd", 3312,
                    "pam_unix(sshd:session): session closed for user jdoe"),
    ]
    c = conn_log()
    for i, state in enumerate(["RSTO", "RSTO", "SF"]):
        t = t0 + timedelta(seconds=[0, 9, 21][i])
        c.rows.append([epoch(t), uid(30 + i), WORKSTATION, 44810 + 2 * i, TARGET, 22,
                       "tcp", "ssh", "2.1" if state == "RSTO" else "372.0", state])
    return Case(
        scenario_id="benign_typo_login_002",
        title="User mistypes a password twice, then logs in",
        why_benign="Two failures and one success, one username, one source, inside 21 "
                   "seconds — the shape of a human at a keyboard, not a credential attack.",
        confounds=["logon_failure burst (small)", "failure followed by success"],
        start=t0 - timedelta(minutes=5), end=t0 + timedelta(minutes=10),
        auth=auth, syslog=cron_noise(t0 - timedelta(hours=3), host, hours=4), zeek=[c],
        expected_observables={"authlog": {"logon_success": True, "logon_failure": True},
                              "zeek": {"conn": True, "ssh": True}},
    )


def sc_nightly_backup() -> Case:
    """A service account logging in at the same minute every night."""
    host = "appsrv01"
    base = datetime(2026, 3, 1, 2, 15, 0)
    auth, c = [], conn_log()
    for night in range(3):
        t = base + timedelta(days=night)
        pid = 6100 + night
        auth += [
            syslog_line(t, host, "sshd", pid,
                        f"Accepted publickey for backup from {BACKUP} port 39900 ssh2: RSA SHA256:aa41"),
            syslog_line(t, host, "sshd", pid,
                        "pam_unix(sshd:session): session opened for user backup by (uid=0)"),
            syslog_line(t + timedelta(minutes=38), host, "sshd", pid,
                        "pam_unix(sshd:session): session closed for user backup"),
        ]
        c.rows.append([epoch(t), uid(40 + night), BACKUP, 39900, TARGET, 22,
                       "tcp", "ssh", "2281.6", "SF"])
    sysl = []
    for night in range(3):
        t = base + timedelta(days=night)
        sysl += [
            syslog_line(t - timedelta(minutes=1), host, "systemd", None, "Started Daily backup job."),
            syslog_line(t + timedelta(minutes=39), host, "systemd", None, "Stopped Daily backup job."),
        ]
    return Case(
        scenario_id="benign_nightly_backup_003",
        title="Nightly rsync backup over SSH by a service account",
        why_benign="Same service account, same source, same schedule, three nights running; "
                   "the long sessions are the backup transferring data.",
        confounds=["repeated remote logon success", "off-hours activity",
                   "long-lived session moving large volume (exfiltration shape)"],
        start=base - timedelta(hours=1), end=base + timedelta(days=2, hours=1),
        auth=auth, syslog=sysl, zeek=[c],
        expected_observables={"authlog": {"logon_success": True, "logon_failure": False},
                              "zeek": {"conn": True, "ssh": True}},
    )


def sc_authorized_scan() -> Case:
    """The hardest benign case: an approved scanner doing exactly what recon does."""
    host = "appsrv01"
    t0 = datetime(2026, 3, 6, 1, 30, 0)
    ports = [21, 22, 23, 25, 53, 80, 110, 111, 139, 143, 389, 443, 445, 512,
             513, 514, 587, 993, 995, 1099, 1524, 2049, 3306, 3389, 5432,
             5900, 6000, 6667, 8009, 8180]
    c = conn_log()
    for i, p in enumerate(ports):
        t = t0 + timedelta(seconds=i * 2)
        state = "SF" if p in (22, 80, 445, 3306) else "REJ"
        c.rows.append([epoch(t), uid(100 + i), SCANNER, 50000 + i, TARGET, p,
                       "tcp", "-", "0.4", state])
    sysl = [
        syslog_line(t0 - timedelta(minutes=5), host, "systemd", None,
                    "Started Scheduled vulnerability scan window."),
        syslog_line(t0 + timedelta(hours=1), host, "systemd", None,
                    "Stopped Scheduled vulnerability scan window."),
    ] + cron_noise(t0, host, hours=3)
    return Case(
        scenario_id="benign_authorized_scan_004",
        title="Authorised vulnerability scan from the inventoried scanner",
        why_benign="The source is the asset-inventory scanner, inside its approved "
                   "Sunday 01:30 window; no authentication follows the scan.",
        confounds=["port sweep across 30 ports (T1046 shape)",
                   "multi-service probe against one target",
                   "no host-side evidence to corroborate intent"],
        start=t0 - timedelta(minutes=10), end=t0 + timedelta(hours=1, minutes=10),
        auth=[], syslog=sysl, zeek=[c],
        expected_observables={"authlog": {"logon_success": False, "logon_failure": False},
                              "zeek": {"conn": True}},
    )


def sc_cron_only() -> Case:
    """A quiet host. Nothing happens, and nothing should be read into that."""
    host = "appsrv01"
    t0 = datetime(2026, 3, 7, 0, 9, 0)
    sysl = cron_noise(t0, host, hours=12) + [
        syslog_line(t0 + timedelta(hours=6, minutes=25), host, "systemd", None,
                    "Started Rotate log files."),
        syslog_line(t0 + timedelta(hours=6, minutes=25, seconds=4), host, "systemd", None,
                    "Stopped Rotate log files."),
    ]
    auth = [syslog_line(t0 + timedelta(hours=h), host, "CRON", 7000 + h,
                        "pam_unix(cron:session): session opened for user root by (uid=0)")
            for h in range(0, 12, 4)]
    c = conn_log()
    for i in range(6):  # NTP and monitoring polls
        t = t0 + timedelta(hours=2 * i)
        c.rows.append([epoch(t), uid(200 + i), TARGET, 41000 + i, DNS_SERVER, 123,
                       "udp", "ntp", "0.1", "SF"])
    return Case(
        scenario_id="benign_cron_quiet_host_005",
        title="Quiet production host: cron, NTP and log rotation only",
        why_benign="No interactive logins and no remote access at all during the window; "
                   "the only sessions are local cron jobs run as root.",
        confounds=["root sessions opened repeatedly",
                   "near-total absence of security-relevant telemetry"],
        start=t0, end=t0 + timedelta(hours=12),
        auth=auth, syslog=sysl, zeek=[c],
        expected_observables={"authlog": {"logon_success": False, "logon_failure": False},
                              "zeek": {"conn": True}},
    )


def sc_degraded_sensor() -> Case:
    """Ordinary activity seen through a sensor that admits it dropped 41% of packets.

    The point of the case: the network silence here is uninformative, not
    exculpatory and not incriminating.
    """
    host = "appsrv01"
    t0 = datetime(2026, 3, 8, 14, 2, 0)
    auth = [
        syslog_line(t0, host, "sshd", 8110,
                    f"Accepted publickey for sysadmin from {JUMPHOST} port 52210 ssh2: RSA SHA256:9c1f"),
        syslog_line(t0, host, "sshd", 8110,
                    "pam_unix(sshd:session): session opened for user sysadmin by (uid=0)"),
        syslog_line(t0 + timedelta(minutes=3), host, "sudo", None,
                    "sysadmin : TTY=pts/1 ; PWD=/var/log ; USER=root ; COMMAND=/usr/bin/tail -n 200 /var/log/nginx/error.log"),
        syslog_line(t0 + timedelta(minutes=9), host, "sshd", 8110,
                    "pam_unix(sshd:session): session closed for user sysadmin"),
    ]
    c = conn_log()
    # Only one of the session's flows survived the loss.
    c.rows.append([epoch(t0), uid(300), JUMPHOST, 52210, TARGET, 22, "tcp", "ssh", "540.0", "SF"])

    loss = ZeekLog("capture_loss.log",
                   ["ts", "ts_delta", "peer", "gaps", "acks", "percent_lost"],
                   ["time", "interval", "string", "count", "count", "double"])
    for i in range(3):
        t = t0 + timedelta(minutes=15 * i)
        loss.rows.append([epoch(t), "900.000000", "zeek", 4120 + i, 10000, f"{41.2 - i:.3f}"])

    notice = ZeekLog("notice.log", ["ts", "uid", "note", "msg"],
                     ["time", "string", "enum", "string"])
    notice.rows.append([epoch(t0 + timedelta(minutes=15)), uid(301),
                        "CaptureLoss::Too_Much_Loss",
                        "The capture loss script detected an estimated loss rate above 10%"])
    return Case(
        scenario_id="benign_degraded_sensor_006",
        title="Routine admin session captured by a degraded Zeek sensor",
        why_benign="A single key-based admin session and one read-only log-inspection "
                   "command. The sensor reports 41.2% packet loss, so most flows are "
                   "missing from conn.log — absence here carries no information.",
        confounds=["41.2% measured packet loss", "CaptureLoss::Too_Much_Loss notice",
                   "network evidence largely missing for a host-visible session"],
        start=t0 - timedelta(minutes=5), end=t0 + timedelta(minutes=45),
        auth=auth, syslog=boot_noise(t0 - timedelta(hours=2), host), zeek=[c, loss, notice],
        expected_observables={"authlog": {"logon_success": True, "logon_failure": False},
                              "zeek": {"conn": True, "ssh": False}},
        clean_capture=False,
        sensor_note="zeek reported 41.2% loss; segment coverage partial",
    )


def sc_helpdesk_lockout() -> Case:
    """Failures spread across a working day, one user, ending in a reset."""
    host = "appsrv01"
    t0 = datetime(2026, 3, 9, 8, 5, 0)
    offsets = [0, 47, 129, 194]  # minutes: sparse, not a burst
    auth = [syslog_line(t0 + timedelta(minutes=m), host, "sshd", 9100 + i,
                        f"Failed password for rlangley from {WORKSTATION} port {45000 + i} ssh2")
            for i, m in enumerate(offsets)]
    reset = t0 + timedelta(minutes=210)
    auth += [
        syslog_line(reset, host, "passwd", 9200,
                    "pam_unix(passwd:chauthtok): password changed for rlangley"),
        syslog_line(reset + timedelta(minutes=4), host, "sshd", 9210,
                    f"Accepted password for rlangley from {WORKSTATION} port 45010 ssh2"),
        syslog_line(reset + timedelta(minutes=4), host, "sshd", 9210,
                    "pam_unix(sshd:session): session opened for user rlangley by (uid=0)"),
    ]
    c = conn_log()
    for i, m in enumerate(offsets + [214]):
        t = t0 + timedelta(minutes=m)
        c.rows.append([epoch(t), uid(400 + i), WORKSTATION, 45000 + i, TARGET, 22,
                       "tcp", "ssh", "3.0", "RSTO" if i < 4 else "SF"])
    return Case(
        scenario_id="benign_helpdesk_lockout_007",
        title="Forgotten password: sparse failures, then a help-desk reset",
        why_benign="Four failures for one account from that user's own workstation over "
                   "3.5 hours, resolved by a password change and a successful login.",
        confounds=["four logon failures (crosses a naive count threshold)",
                   "failure sequence terminating in success"],
        start=t0 - timedelta(minutes=10), end=reset + timedelta(minutes=30),
        auth=auth, syslog=cron_noise(t0, host, hours=5), zeek=[c],
        expected_observables={"authlog": {"logon_success": True, "logon_failure": True},
                              "zeek": {"conn": True, "ssh": True}},
    )


def sc_app_traffic() -> Case:
    """Application chatter only: DNS plus web and database flows."""
    host = "appsrv01"
    t0 = datetime(2026, 3, 10, 10, 0, 0)
    c, d = conn_log(), dns_log()
    for i in range(40):
        t = t0 + timedelta(seconds=i * 45)
        c.rows.append([epoch(t), uid(500 + i), TARGET, 42000 + i, "10.0.2.40", 5432,
                       "tcp", "postgresql", "1.8", "SF"])
    for i in range(12):
        t = t0 + timedelta(minutes=3 * i)
        c.rows.append([epoch(t), uid(600 + i), WORKSTATION, 46000 + i, TARGET, 443,
                       "tcp", "ssl", "6.2", "SF"])
        d.rows.append([epoch(t), uid(700 + i), TARGET, 53400 + i, DNS_SERVER, 53,
                       "udp", "api.internal.lan", "A", "NOERROR"])
    return Case(
        scenario_id="benign_app_traffic_008",
        title="Application-tier traffic: HTTPS clients and a database backend",
        why_benign="Two service ports, stable peers, steady rate — the host's normal "
                   "production traffic profile with no authentication events at all.",
        confounds=["high connection volume", "repeated connections to a database port",
                   "no host telemetry to corroborate the network view"],
        start=t0, end=t0 + timedelta(minutes=40),
        auth=[], syslog=cron_noise(t0, host, hours=1), zeek=[c, d],
        expected_observables={"authlog": {"logon_success": False, "logon_failure": False},
                              "zeek": {"conn": True, "dns": True}},
    )


SCENARIOS = {
    "benign_admin_maintenance_001": sc_admin_maintenance,
    "benign_typo_login_002": sc_typo_then_login,
    "benign_nightly_backup_003": sc_nightly_backup,
    "benign_authorized_scan_004": sc_authorized_scan,
    "benign_cron_quiet_host_005": sc_cron_only,
    "benign_degraded_sensor_006": sc_degraded_sensor,
    "benign_helpdesk_lockout_007": sc_helpdesk_lockout,
    "benign_app_traffic_008": sc_app_traffic,
}


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--out", default="cases_linux",
                    help="directory the case folders are written into (default: cases_linux)")
    ap.add_argument("--only", action="append", metavar="ID",
                    help="generate just this scenario; repeatable")
    ap.add_argument("--list", action="store_true", help="list scenarios and exit")
    ap.add_argument("--force", action="store_true", help="overwrite existing case directories")
    args = ap.parse_args()

    if args.list:
        for name, fn in SCENARIOS.items():
            case = fn()
            print(f"{name:<32} {case.title}")
            for cf in case.confounds:
                print(f"{'':<32}   looks like: {cf}")
        return 0

    names = args.only or list(SCENARIOS)
    unknown = [n for n in names if n not in SCENARIOS]
    if unknown:
        ap.error(f"unknown scenario(s): {', '.join(unknown)}")

    out = Path(args.out)
    out.mkdir(parents=True, exist_ok=True)
    for name in names:
        case = SCENARIOS[name]()
        d = case.write(out, args.force)
        n_auth, n_net = len(case.auth), sum(len(z.rows) for z in case.zeek)
        print(f"wrote {d}  ({n_auth} auth lines, {len(case.syslog)} syslog lines, "
              f"{n_net} zeek records)")

    print(f"\n{len(names)} benign case(s) in {out}/. All are labelled "
          f"category=benign; a correct run disposes of every one as non-attack.")
    print(f"  ./.venv/bin/python -m argus.cli bench {out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
