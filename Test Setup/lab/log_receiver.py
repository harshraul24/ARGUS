#!/usr/bin/env python3
"""log_receiver.py — receive the victims' logs as they are written (replaces the SSH pull).

Each victim's rsyslog follows its audit.log, auth.log and the persona's benign-activity.log and
streams every new line to this receiver over TCP (set up once per victim by forward-logs.sh).
Lines are written unchanged to

    captured/<RUN>/<host>/audit.log   auth.log   benign-activity.log

so when the operation ends the capture is already complete: nothing is fetched, no login or
sudo is needed, and a host that goes quiet shows in the live status while it can still be
fixed. The victims keep their own logs (the local view); this copy is the forwarded view that
a log-clearing attacker on a victim cannot erase (LAB_TEST_SUITE.md S10).

  * Lines arrive as RFC 5424 syslog frames (octet-counted, or one per line). The frame's host
    name picks the folder and its tag picks the file (argus-audit, argus-auth, argus-activity).
  * A victim that cannot reach the receiver keeps unsent lines in a disk queue and sends them
    later; a line resent after a reconnect is written once.
  * Lines recorded before the receiver started (less a margin) are dropped: they belong to an
    earlier run, not this one (`--since` overrides).

Usage (on the Mac, from Test Setup/lab):
  python3 log_receiver.py run3              # receive until Ctrl-C, with a live status table
  python3 log_receiver.py run3 --check      # after the run: is every host's copy complete?
"""
from __future__ import annotations

import argparse
import hashlib
import json
import re
import signal

import socketserver
import subprocess
import sys
import threading
import time
from collections import OrderedDict, defaultdict
from datetime import datetime, timezone
from pathlib import Path

LAB = Path(__file__).resolve().parent
PORT = 10514
FILES = {"argus-audit": "audit.log", "argus-auth": "auth.log", "argus-activity": "benign-activity.log"}
TEST_TAG = "argus-test"
HOST_OK = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")
RFC5424 = re.compile(r"^<\d{1,3}>1 (\S+) (\S+) (\S+) (\S+) (\S+) (-|(?:\[.*?\])+)(?: (.*))?$", re.S)
AUDIT_T = re.compile(r"msg=audit\((\d+)\.\d+:\d+\)")
ISO_T = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?(?:Z|[+-]\d\d:\d\d)?)")
SILENT_WARN_S = 300
MARGIN_S = 300


# ============================================================ lines

def record_time(name: str, line: str) -> float | None:
    """The time a line was recorded on the victim (audit epoch, or a leading ISO time)."""
    if name == "audit.log":
        m = AUDIT_T.search(line)
        return float(m.group(1)) if m else None
    m = ISO_T.match(line)
    if not m:
        return None
    try:
        t = datetime.fromisoformat(m.group(1).replace("Z", "+00:00"))
        return (t if t.tzinfo else t.replace(tzinfo=timezone.utc)).timestamp()
    except ValueError:
        return None


def parse_frame(frame: bytes) -> tuple[str, str, str] | None:
    """(host, tag, message) from one RFC 5424 frame, the message byte-for-byte as sent."""
    text = frame.decode("utf-8", errors="surrogateescape").rstrip("\n")
    m = RFC5424.match(text)
    if not m:
        return None
    host, tag, msg = m.group(2), m.group(3).rstrip(":"), m.group(7) or ""
    if msg.startswith("\ufeff"):
        msg = msg[1:]
    if tag == "argus-audit":
        msg = msg.replace("#035", "\x1d")      # if the victim escaped auditd's field separator
    return host, tag, msg


class Framer:
    """Splits a TCP byte stream into frames: octet-counted (`LEN SP MSG`) or one per line."""

    def __init__(self) -> None:
        self.buf = b""

    def feed(self, data: bytes) -> list[bytes]:
        self.buf += data
        out = []
        while self.buf:
            m = re.match(rb"(\d{1,6}) ", self.buf)
            if m:
                n, start = int(m.group(1)), m.end()
                if len(self.buf) < start + n:
                    break
                out.append(self.buf[start:start + n])
                self.buf = self.buf[start + n:]
            else:
                i = self.buf.find(b"\n")
                if i < 0:
                    break
                out.append(self.buf[:i])
                self.buf = self.buf[i + 1:]
        return out


# ============================================================ the run's files

class Store:
    def __init__(self, run_dir: Path, since: float) -> None:
        self.dir, self.since = run_dir, since
        self.lock = threading.Lock()
        self.fh: dict[tuple[str, str], object] = {}
        self.stat: dict[str, dict] = defaultdict(dict)
        self.seen: OrderedDict = OrderedDict()
        self.dropped = defaultdict(int)
        self.tests: list[str] = []

    def write(self, host: str, tag: str, msg: str, peer: str) -> None:
        if not HOST_OK.match(host):
            self.dropped["bad host name"] += 1
            return
        if tag == TEST_TAG:
            with self.lock:
                self.tests.append(f"{host} ({peer})")
            print(f"  forwarding test received from {host} ({peer})", flush=True)
            return
        name = FILES.get(tag)
        if name is None:
            self.dropped["other tag"] += 1
            return
        t = record_time(name, msg)
        if t is not None and t < self.since:
            self.dropped["recorded before this run"] += 1
            return
        digest = hashlib.blake2b(f"{host}\0{name}\0{msg}".encode("utf-8", "surrogateescape"), digest_size=12).digest()
        with self.lock:
            if digest in self.seen:                 # resent after a reconnect
                self.dropped["duplicate (resent)"] += 1
                return
            self.seen[digest] = None
            if len(self.seen) > 500_000:
                self.seen.popitem(last=False)
            f = self.fh.get((host, name))
            if f is None:
                (self.dir / host).mkdir(parents=True, exist_ok=True)
                f = self.fh[(host, name)] = open(self.dir / host / name, "ab")
            f.write(msg.encode("utf-8", "surrogateescape") + b"\n")
            f.flush()
            s = self.stat[host].setdefault(name, {"lines": 0, "first": None, "last": None, "arrived": None})
            s["lines"] += 1
            if t is not None:
                s["first"] = t if s["first"] is None else min(s["first"], t)
                s["last"] = t if s["last"] is None else max(s["last"], t)
            s["arrived"] = time.time()

    def close(self) -> None:
        with self.lock:
            for f in self.fh.values():
                f.close()
            self.fh.clear()

    def status(self) -> dict:
        with self.lock:
            return {"since": _iso(self.since), "hosts": json.loads(json.dumps(self.stat)),
                    "dropped": dict(self.dropped), "tests": list(self.tests)}


def _iso(t: float | None) -> str | None:
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ") if t else None


# ============================================================ network

def bridge_ip() -> str | None:
    """The Mac's address on the victims' subnet (from fleet.txt), as capture.sh finds it."""
    fleet = LAB / "fleet.txt"
    if not fleet.exists():
        return None
    ips = [ln.split()[2] for ln in fleet.read_text().splitlines()
           if ln.strip() and not ln.lstrip().startswith("#") and len(ln.split()) >= 3]
    if not ips:
        return None
    prefix = ips[0].rsplit(".", 1)[0] + "."
    try:
        out = subprocess.run(["ifconfig"], capture_output=True, text=True, timeout=10).stdout
    except (OSError, subprocess.SubprocessError):
        return None
    return next((m.group(1) for m in re.finditer(r"inet (\d+\.\d+\.\d+\.\d+)", out)
                 if m.group(1).startswith(prefix)), None)


def make_server(store: Store, bind: str, port: int) -> socketserver.ThreadingTCPServer:
    """A TCP server writing every frame it receives into `store` (not yet serving)."""

    class Handler(socketserver.BaseRequestHandler):
        def handle(self):
            fr, peer = Framer(), self.client_address[0]
            while True:
                try:
                    data = self.request.recv(65536)
                except OSError:
                    return
                if not data:
                    return
                for frame in fr.feed(data):
                    p = parse_frame(frame)
                    if p is None:
                        store.dropped["not syslog"] += 1
                    else:
                        store.write(*p, peer=peer)

    class Server(socketserver.ThreadingTCPServer):
        daemon_threads = True
        allow_reuse_address = True

    return Server((bind, port), Handler)


def serve(run: str, bind: str, port: int, since: float) -> None:
    run_dir = LAB / "captured" / run
    run_dir.mkdir(parents=True, exist_ok=True)
    store = Store(run_dir, since)
    srv = make_server(store, bind, port)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"receiving logs for {run} on {bind}:{port}  ->  {run_dir}")
    print(f"  keeping lines recorded after {_iso(since)}")
    print(f"  on each victim (once, as root):  sudo ./forward-logs.sh {bind} {port}")
    print("  Ctrl-C to stop\n", flush=True)
    stop = threading.Event()
    for sig in (signal.SIGINT, signal.SIGTERM):
        signal.signal(sig, lambda *_: stop.set())
    while not stop.wait(30):
        st = store.status()
        (run_dir / ".receiver_status.json").write_text(json.dumps(st, indent=1))
        _print_status(st)
    srv.shutdown()
    store.close()
    st = store.status()
    (run_dir / ".receiver_status.json").write_text(json.dumps(st, indent=1))
    _print_status(st)
    print(f"stopped. Next: python3 log_receiver.py {run} --check")


def _print_status(st: dict) -> None:
    now = time.time()
    print(time.strftime("%H:%M:%S"), "  host        file                 lines     last recorded (UTC)   quiet")
    for host, files in sorted(st["hosts"].items()):
        for name, s in sorted(files.items()):
            quiet = now - (s["arrived"] or now)
            flag = "  <- QUIET" if name == "audit.log" and quiet > SILENT_WARN_S else ""
            print(f"           {host:<11} {name:<20} {s['lines']:>8}   {(_iso(s['last']) or '-'):<21} {quiet:>5.0f}s{flag}")
    if st["dropped"]:
        print("           dropped:", st["dropped"])
    print(flush=True)


# ============================================================ after the run

def _victims() -> list[str]:
    """The victims in fleet.txt (lines `name user ip`); Kali is the server, not a victim."""
    fleet = LAB / "fleet.txt"
    if not fleet.exists():
        return []
    return [ln.split()[0] for ln in fleet.read_text().splitlines()
            if ln.strip() and not ln.lstrip().startswith("#") and ln.split()[0].lower() != "kali"]


def _utc(s: str | None) -> float | None:
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp() if s and s != "FILL" else None
    except ValueError:
        return None


def check(run: str) -> int:
    """Is every host's copy complete? Each victim must have an audit log that runs past the end of
    the operation without a long gap during it. Victims and times come from the CALDERA report
    (its agents, start and finish), else from fleet.txt and the manifest."""
    run_dir = LAB / "captured" / run
    hosts, start, end = _victims(), None, None
    for rep in sorted(run_dir.glob("*_report.json")):
        try:
            r = json.loads(rep.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        agents = sorted({a.get("host") for a in r.get("host_group", []) if a.get("host")})
        if agents:
            hosts = agents
        start, end = _utc(r.get("start")) or start, _utc(r.get("finish")) or end
    man = run_dir / "manifest.json"
    if man.exists():
        try:
            m = json.loads(man.read_text())
        except json.JSONDecodeError:
            m = {}
        start = start or _utc(m.get("op_start_utc"))
        end = end or _utc(m.get("op_finish_utc"))
    print(f"{run}: hosts {hosts}; operation ends {_iso(end) or 'unknown (no report or manifest time)'}")
    bad = 0
    for h in hosts:
        log = run_dir / h / "audit.log"
        if not log.exists():
            print(f"  FAIL {h:<10} no audit.log")
            bad += 1
            continue
        ts = sorted(float(m.group(1)) for m in AUDIT_T.finditer(log.read_text(errors="ignore")))
        if not ts:
            print(f"  FAIL {h:<10} audit.log has no records")
            bad += 1
            continue
        # gaps that matter are during the operation (a host may be off between runs)
        lo, hi = (start or ts[0]) - 15 * 60, (end or ts[-1]) + 60
        span = [t for t in ts if lo <= t <= hi]
        gaps = [(b - a, a) for a, b in zip(span, span[1:])]
        gap, at = max(gaps) if gaps else (0.0, ts[0])
        problems = []
        if end is not None and ts[-1] < end + 60:
            problems.append(f"ends {_iso(ts[-1])}, before the operation's end")
        if gap > 15 * 60:
            problems.append(f"{gap / 60:.0f}-minute gap from {_iso(at)}")
        others = [n for n in ("auth.log", "benign-activity.log") if not (run_dir / h / n).exists()]
        state = "FAIL" if problems else "ok  "
        bad += bool(problems)
        print(f"  {state} {h:<10} audit {_iso(ts[0])} -> {_iso(ts[-1])} ({len(ts)} records)"
              + (f"; {'; '.join(problems)}" if problems else "")
              + (f"; missing {', '.join(others)}" if others else ""))
    print("complete" if not bad else f"{bad} host(s) incomplete: recapture rather than patch (LAB_TEST_SUITE.md §6)")
    return 1 if bad else 0


def main() -> None:
    ap = argparse.ArgumentParser(description="receive the victims' logs as they are written")
    ap.add_argument("run", help="the run name: the capture folder under captured/")
    ap.add_argument("--check", action="store_true", help="after the run: report whether each host's copy is complete")
    ap.add_argument("--bind", default=None, help="address to listen on (default: the Mac's address on the victims' subnet)")
    ap.add_argument("--port", type=int, default=PORT)
    ap.add_argument("--since", default=None, help="keep lines recorded after this UTC time (default: start - 5 min)")
    a = ap.parse_args()
    if not re.match(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$", a.run):
        sys.exit("a run name is letters, digits, dot, dash or underscore")
    if a.check:
        sys.exit(check(a.run))
    bind = a.bind or bridge_ip()
    if not bind:
        sys.exit("cannot find the Mac's address on the victims' subnet (fleet.txt); pass --bind <ip>")
    since = datetime.fromisoformat(a.since.replace("Z", "+00:00")).timestamp() if a.since else time.time() - MARGIN_S
    try:
        serve(a.run, bind, a.port, since)
    except OSError as exc:
        sys.exit(f"cannot listen on {bind}:{a.port}: {exc}")


if __name__ == "__main__":
    main()
