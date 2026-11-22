"""Real multi-host auditd capture (+ CALDERA operation report) -> ARGUS lab windows.

INPUT-FITTING ONLY: no detection logic. Each victim's `audit.log` (enriched format, rules
from `Test Setup/lab/make-victim.sh`) becomes `events.jsonl` + `lineage.json` + `meta.json`
+ `labels.json` per window (format argus-events-v1), read by argus/collectors/events.py.

  events      process_create      one per successful execve: image, image_path (exe),
                                  command_line (EXECVE argv), parent_image, user, cwd
              network_connection  one per connect() to an inet/inet6 address (`net` rule):
                                  dst_ip, dst_port, image, success/exit (EINPROGRESS kept:
                                  the attempt is the behaviour). Unix/netlink sockets skipped
              file_*              one per hit on a watched path (identity, privilege,
                                  schedule, service, sshkeys, auditconfig, auditlog rules):
                                  file_read/_write/_create/_delete/_rename by syscall and
                                  PATH nametype, file_path, audit_key
  lineage     process key = host/pid@exec-time, with its image and path, so an ancestor
              launched in an earlier window keeps its name and folder; parent = the parent
              pid's current key, or
              host/ppid@pre when the parent started before the capture. A connect or file
              access belongs to the process holding that pid with the same exe; a child
              forked without execve runs its parent's program and is attributed to it
  windows     a fixed grid per host (`--window-minutes`), aligned to the hour; decided
              without labels
  contract    what the sensor was configured to record in each window, from the audit
              rules the host had loaded by its end (`add_rule`/`remove_rule` records):
              process_create with the execve rule, network_connection with the connect
              rule. A contracted type with no events is a blind spot (meta.sensor_contract)
  labels      from CALDERA only: each step's process (host + pid within the run time; a
              step with no pid in the report, e.g. status -3, by its exact command text as
              the executor's `sh -c` argument) and its descendants, and the agent process
              with all its descendants, are malicious (the convention: the agent's
              lineage), plus the agent's deployment (the commands that fetched and launched
              it, matched by its file name and server address). Bootstrap abilities are not in
              the operation report; with
              `--ground-truth`, its `actions` are matched by exact command text on the host
              whose agent was created at that time, and listed as steps (`bootstrap: true`)
  gaps        when the sensor could not record: from the audit daemon's stop to its next
              start (every type), and from an audit rule's removal to its next addition
              (that rule's type). A window lists the gaps that overlap it
              (meta.sensor_gaps); each is a blind spot, never read as "nothing happened"
  gate        the capture-validity gate of LAB_EVAL_PLAN.md §2 ("no collection or admin
              activity inside a window being scored"), matched on the lab protocol's own
              command text and recorded per window; nothing is dropped

A capture is one folder with `<host>/audit.log` per victim (and optionally auth.log and
Zeek's network/*.log, recorded as captured but not ingested). Without a CALDERA report the
windows are written without labels.json: imported for triage only, never evaluated.

Used by the workbench's Import capture sheet (argus/api/workbench.py) and by
tools/apt_capture/auditd_to_windows.py (the same conversion from a terminal).
"""
from __future__ import annotations

import base64
import json
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime, timezone
from pathlib import Path

RE_HDR = re.compile(r"^type=(\w+) msg=audit\((\d+\.\d+):(\d+)\):\s?(.*)$")
RE_KV = re.compile(r'(\w+)=("(?:[^"\\]|\\.)*"|\S+)')

# Watch keys set by make-victim.sh, each guarding a set of sensitive paths.
FILE_KEYS = {"identity", "privilege", "schedule", "service", "sshkeys", "auditconfig", "auditlog"}
_WRITE_FLAGS = 0o1 | 0o2 | 0o100 | 0o1000                # O_WRONLY | O_RDWR | O_CREAT | O_TRUNC
_ATTR_WRITES = {"truncate", "ftruncate", "setxattr", "lsetxattr", "fsetxattr", "fchmodat",
                "fchownat", "chmod", "fchmod", "chown", "fchown", "utimensat"}

# Experimenter activity of the lab protocol itself, by its own command text (Test Setup/lab/
# capture.sh, RUN_CAMPAIGN.md): the log pull (run 1's `cp`, and the later `cat` of rotated
# logs into /tmp), the victims' first-boot provisioning (cloud-init runcmd) and `fixup.sh`,
# packages installed from an interactive login, the sensor checks, starting or stopping the
# benign persona's service, and powering a victim off. The persona's own actions, including
# its scheduled auditd restart, are not protocol: they are the benign activity being scored.
_PULLED = ("/var/log/auth.log", "/var/log/audit/audit.log")


def _pulls(a: list[str]) -> bool:
    return bool(a) and all(v.startswith(_PULLED) for v in a)


PROTOCOL = {
    "log_collection": lambda x: x["argv"][:2] == ["cp", "/var/log/auth.log"]
                                or (x["argv"][:2] == ["chmod", "644"]
                                    and set(x["argv"][2:]) <= {"/tmp/auth.log", "/tmp/audit.log"} and len(x["argv"]) > 2)
                                or (Path(x["exe"]).name == "cat" and _pulls(x["argv"][1:]))
                                or (x["argv"][:2] == ["bash", "-c"] and len(x["argv"]) > 2
                                    and "ls -1tr /var/log/audit/audit.log*" in x["argv"][2]),
    "first_boot": lambda x: "/var/lib/cloud/instance/scripts/runcmd" in x["argv"],
    "provisioning": lambda x: any(Path(a).name == "fixup.sh" for a in x["argv"][:2]),
    "package_install": lambda x: Path(x["exe"]).name in ("apt-get", "apt") and "install" in x["argv"]
                                 and x.get("tty", "(none)") != "(none)",
    "sensor_check": lambda x: x["argv"][:2] in (["/usr/sbin/auditctl", "-l"], ["auditctl", "-l"])
                              or x["argv"][:3] == ["wc", "-l", "/var/log/audit/audit.log"],
    "persona_control": lambda x: (Path(x["exe"]).name == "systemd-run" and "--unit=benign" in x["argv"])
                                 or (Path(x["exe"]).name == "systemctl" and "benign" in x["argv"][2:3]
                                     and x["argv"][1:2] in (["stop"], ["start"], ["reset-failed"])),
    # by command name: poweroff and reboot are links to systemctl
    "power": lambda x: bool(x["argv"]) and Path(x["argv"][0]).name in ("poweroff", "shutdown", "reboot", "halt")
                       and x.get("tty", "(none)") != "(none)",
}


def _unhex(v: str) -> str:
    if v.startswith('"'):
        return v[1:-1]
    try:
        return bytes.fromhex(v).decode(errors="replace").replace("\x00", " ")
    except ValueError:
        return v


def group_lines(lines, ev: dict | None = None) -> dict[tuple[str, str], dict]:
    """Add audit lines to `ev`, grouped by event id: {(time, serial): {"ts", "types"}}.
    The id is time and serial together (`audit(1791991842.524:5426)`): the serial alone
    restarts at every boot, so on a host that rebooted it would merge unrelated events.
    Shared by the batch converter and the live feed (argus.live)."""
    ev = {} if ev is None else ev
    for line in lines:
        m = RE_HDR.match(line)
        if not m:
            continue
        typ, ts, serial, rest = m.groups()
        body = rest.replace("\x1d", " ")
        fields = dict(RE_KV.findall(body))
        e = ev.setdefault((ts, serial), {"ts": float(ts), "types": defaultdict(list)})
        e["types"][typ].append(fields)
    return ev


def _records(path: Path):
    """A whole audit log's events in time order."""
    # split on newlines only: splitlines() also breaks at \x1d, the separator auditd puts
    # before the enriched fields (SYSCALL=connect, UID="www", SADDR={...}), and lost them
    return sorted(group_lines(path.read_text(errors="ignore").split("\n")).values(), key=lambda e: e["ts"])


def parse_rules(path: Path) -> list[tuple[float, str, str]]:
    """(time, op, key) for every audit rule added or removed, in time order."""
    return rules_of(_records(path))


def rules_of(records) -> list[tuple[float, str, str]]:
    out = []
    for e in records:
        for f in e["types"].get("CONFIG_CHANGE", []):
            op = f.get("op")
            if op in ("add_rule", "remove_rule"):
                out.append((e["ts"], op, _unhex(f.get("key", '""'))))
    return out


# audit rule key -> the event type it makes the sensor record
RULE_TYPES = {"exec": "process_create", "net": "network_connection"}
MIN_GAP_S = 0.05        # shorter than this, a sensor gap is not reported


class SensorGaps:
    """When a host's audit log could not record, from the log's own records:
      - the audit daemon was stopped (DAEMON_END or DAEMON_ABORT to the next DAEMON_START):
        nothing is written;
      - the daemon started with no recorded stop (a crash or a kill): nothing was written
        since the record before it;
      - an audit rule was removed (`remove_rule` to the next `add_rule` of the same key):
        the type that rule records is not written.
    `apply` takes events in time order, a whole log at once or as they arrive (argus.live).
    A gap still open has `end` None. Label-free: read from the sensor's own log."""

    def __init__(self) -> None:
        self.gaps: list[dict] = []
        self._down: dict | None = None
        self._unloaded: dict[str, dict] = {}
        self._last: float | None = None

    def _open(self, ts: float, types: list[str], cause: str) -> dict:
        g = {"start": ts, "end": None, "types": types, "cause": cause}
        self.gaps.append(g)
        return g

    def apply(self, records) -> None:
        for e in records:
            ts, types = e["ts"], e["types"]
            if ("DAEMON_END" in types or "DAEMON_ABORT" in types) and self._down is None:
                self._down = self._open(ts, sorted(RULE_TYPES.values()), "audit daemon stopped")
            if "DAEMON_START" in types:
                if self._down is not None:
                    self._down["end"], self._down = ts, None
                elif self._last is not None:
                    self._open(self._last, sorted(RULE_TYPES.values()),
                               "audit daemon started with no recorded stop")["end"] = ts
            for f in types.get("CONFIG_CHANGE", []):
                key = _unhex(f.get("key", '""'))
                if key not in RULE_TYPES:
                    continue
                if f.get("op") == "remove_rule" and key not in self._unloaded:
                    self._unloaded[key] = self._open(ts, [RULE_TYPES[key]], "audit rule removed")
                elif f.get("op") == "add_rule" and key in self._unloaded:
                    self._unloaded.pop(key)["end"] = ts
            self._last = ts

    def overlapping(self, start: float, end: float, join: float = 1.0) -> list[dict]:
        """The gaps that overlap [start, end), in time order. Gaps that touch or lie within
        `join` seconds of each other are one gap (a restart stops the daemon, then reloads
        its rules: one interruption, not three)."""
        out: list[dict] = []
        for g in sorted(self.gaps, key=lambda g: g["start"]):
            if g["start"] >= end or (g["end"] is not None and g["end"] < start):
                continue
            last = out[-1] if out else None
            if last and (last["end"] is None or g["start"] - last["end"] <= join):
                last["end"] = None if None in (last["end"], g["end"]) else max(last["end"], g["end"])
                last["types"] = sorted(set(last["types"]) | set(g["types"]))
                if g["cause"] not in last["cause"]:
                    last["cause"] += "; " + g["cause"]
            else:
                out.append(dict(g))
        # a rule replaced, or a daemon started, within the same instant is not an interval
        out = [g for g in out if g["end"] is None or g["end"] - g["start"] >= MIN_GAP_S]
        return [{"start": _iso(g["start"]), "end": _iso(g["end"]) if g["end"] is not None else None,
                 "seconds": round(g["end"] - g["start"], 1) if g["end"] is not None else None,
                 "types": g["types"], "cause": g["cause"]} for g in out]


def gaps_of(records) -> SensorGaps:
    g = SensorGaps()
    g.apply(records)
    return g


def loaded_keys(rules: list[tuple[float, str, str]], until: float) -> set[str]:
    """Rule keys with more additions than removals before `until`."""
    n: Counter = Counter()
    for ts, op, key in rules:
        if ts < until:
            n[key] += 1 if op == "add_rule" else -1
    return {k for k, v in n.items() if v > 0}


def _base(e: dict, host: str) -> dict:
    sc = (e["types"].get("SYSCALL") or [{}])[0]
    return {"ts": e["ts"], "host": host, "pid": int(sc.get("pid", -1)), "ppid": int(sc.get("ppid", -1)),
            "exe": _unhex(sc.get("exe", '""')), "user": _unhex(sc.get("UID", '""')) or sc.get("uid"),
            "tty": sc.get("tty", "(none)")}


def parse_host(path: Path, host: str) -> list[dict]:
    """Successful execve events of one host, in time order."""
    return execs_of(_records(path), host)


def execs_of(records, host: str) -> list[dict]:
    out = []
    for e in records:
        sc = (e["types"].get("SYSCALL") or [{}])[0]
        if sc.get("SYSCALL") != "execve" and sc.get("syscall") not in ("221", "59"):
            continue
        if sc.get("success") != "yes" or "EXECVE" not in e["types"]:
            continue
        ex = e["types"]["EXECVE"][0]
        argc = int(ex.get("argc", "0"))
        argv = [_unhex(ex.get(f"a{i}", "")) for i in range(argc)]
        cwd = _unhex((e["types"].get("CWD") or [{}])[0].get("cwd", '""'))
        out.append({**_base(e, host), "argv": argv, "cwd": cwd, "auid": _unhex(sc.get("AUID", '""'))})
    return out


def _file_kind(call: str, sc: dict, paths: list[dict]) -> str:
    types = {p.get("nametype") for p in paths}
    if call.startswith("rename") and types & {"CREATE", "DELETE"}:
        return "file_rename"
    if "DELETE" in types:
        return "file_delete"
    if "CREATE" in types:
        return "file_create"
    if call in ("openat", "open"):
        try:
            flags = int(sc.get("a2" if call == "openat" else "a1", "0"), 16)
        except ValueError:
            flags = 0
        return "file_write" if flags & _WRITE_FLAGS else "file_read"
    return "file_write" if call in _ATTR_WRITES else "file_read"      # getxattr, readlinkat: metadata reads


def parse_activity(path: Path, host: str) -> list[dict]:
    """connect() to inet/inet6 addresses and hits on watched paths, of one host."""
    return acts_of(_records(path), host)


def acts_of(records, host: str) -> list[dict]:
    out = []
    for e in records:
        sc = (e["types"].get("SYSCALL") or [{}])[0]
        key, call = _unhex(sc.get("key", '""')), sc.get("SYSCALL", "")
        if key == "net" and call == "connect":
            sa = (e["types"].get("SOCKADDR") or [{}])[0]          # enriched fields, used raw
            if sa.get("saddr_fam") not in ("inet", "inet6"):
                continue
            port = sa.get("lport", "")
            out.append({**_base(e, host), "kind": "network_connection",
                        "facts": {"dst_ip": sa.get("laddr"), "dst_port": int(port) if port.isdigit() else None,
                                  "direction": "outbound", "success": sc.get("success"), "exit": sc.get("exit")}})
        elif key in FILE_KEYS:
            paths = [p for p in e["types"].get("PATH", []) if p.get("nametype") != "PARENT"]
            if not paths:
                continue
            p = next((p for p in paths if p.get("nametype") == "CREATE"), paths[0])
            name = _unhex(p.get("name", '""'))
            if name and not name.startswith("/"):
                cwd = _unhex((e["types"].get("CWD") or [{}])[0].get("cwd", '""'))
                name = f"{cwd.rstrip('/')}/{name}" if cwd else name
            facts = {"file_path": name, "audit_key": key, "syscall": call, "success": sc.get("success")}
            old = next((_unhex(q.get("name", '""')) for q in paths if q.get("nametype") == "DELETE"), None)
            kind = _file_kind(call, sc, e["types"].get("PATH", []))
            if kind == "file_rename" and old:
                facts["old_path"] = old
            out.append({**_base(e, host), "kind": kind, "facts": facts})
    return out


class Lineage:
    """Process keys assigned as events arrive, in time order. The batch converter applies it
    once to a whole log; the live feed applies it to each new batch, keeping `current`."""

    def __init__(self) -> None:
        self.current: dict[tuple[str, int], tuple[str, str, str]] = {}   # (host, pid) -> (key, image, exe)

    def apply(self, execs: list[dict], acts: list[dict] = ()) -> None:
        """Assign in place: key, parent_key, parent_image (activity: key, parent_key)."""
        current = self.current
        stream = sorted([(x["ts"], 0, i) for i, x in enumerate(execs)] + [(a["ts"], 1, i) for i, a in enumerate(acts)])
        for _, kind, i in stream:
            x = (execs if kind == 0 else acts)[i]
            par = current.get((x["host"], x["ppid"]))
            if kind == 0:
                x["parent_key"] = par[0] if par else f"{x['host']}/{x['ppid']}@pre"
                x["parent_image"] = par[1] if par else None
                x["key"] = f"{x['host']}/{x['pid']}@{x['ts']:.3f}"
                current[(x["host"], x["pid"])] = (x["key"], Path(x["exe"]).name, x["exe"])
                continue
            me = current.get((x["host"], x["pid"]))
            if me and me[2] == x["exe"]:
                x["key"] = me[0]
            elif par and par[2] == x["exe"]:                  # forked without execve: its parent's program
                x["key"] = par[0]
            else:
                x["key"] = f"{x['host']}/{x['pid']}@pre"
                x["parent_key"] = par[0] if par else f"{x['host']}/{x['ppid']}@pre"


def build_lineage(execs: list[dict], acts: list[dict] = ()) -> None:
    """Assign process keys in place over a whole capture (see Lineage)."""
    Lineage().apply(execs, acts)


def _iso(ts: float) -> str:
    return datetime.fromtimestamp(ts, tz=timezone.utc).isoformat()


def _epoch(s: str) -> float:
    return datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def _command(link: dict) -> str | None:
    if link.get("plaintext_command"):
        return link["plaintext_command"]
    c = link.get("command")
    try:
        return base64.b64decode(c, validate=True).decode() if c else None
    except ValueError:
        return c


def _by_command(execs: list[dict], host: str, cmd: str | None, t: float | None, off: float,
                slack: float) -> list[dict]:
    """The executor shell `sh -c <cmd>` on `host`, the first at or after t (less slack)."""
    if not cmd:
        return []
    xs = [x for x in execs if x["host"] == host and len(x["argv"]) >= 3 and x["argv"][1] == "-c"
          and x["argv"][2] == cmd and (t is None or x["ts"] - off >= t - slack)]
    return sorted(xs, key=lambda x: x["ts"])[:1]


_STATUS = {0: "success", -3: "no_result"}           # -3: collected by the agent, never reported back


def labels_from_report(report: dict, execs: list[dict], ground_truth: dict | None = None,
                       slack: float = 120.0) -> dict:
    """Malicious process keys and per-step process keys, from the CALDERA report."""
    by_host_pid = defaultdict(list)
    for x in execs:
        by_host_pid[(x["host"], x["pid"])].append(x)
    children = defaultdict(list)
    for x in execs:
        children[x["parent_key"]].append(x["key"])

    def subtree(keys):
        out, todo = set(), list(keys)
        while todo:
            k = todo.pop()
            if k not in out:
                out.add(k)
                todo.extend(children.get(k, ()))
        return out

    paw_host = {a["paw"]: a.get("host") for a in report.get("host_group", [])}
    # Per-host clock offset (host clock minus CALDERA clock), from the steps whose pid occurs
    # on that host: the median of the nearest-execution differences. Measured on the first
    # capture: three hosts within 1 s, ws-fin01 ~17 min behind (its time sync had failed).
    # Telemetry keeps the host's own timestamps; only the label matching corrects for it.
    offset = {}
    for paw, v in report.get("steps", {}).items():
        host, diffs = paw_host.get(paw), []
        for l in (v["steps"] if isinstance(v, dict) else v):
            run = l.get("run") or l.get("agent_reported_time") or l.get("delegated")
            xs = by_host_pid.get((host, l.get("pid")), [])
            if run and xs:
                t = _epoch(run)
                diffs.append(min((x["ts"] - t for x in xs), key=abs))
        offset[host] = statistics.median(diffs) if diffs else 0.0
    roots = set()
    for a in report.get("host_group", []):                   # the agent process itself
        roots |= {x["key"] for x in by_host_pid.get((a.get("host"), a.get("pid")), [])
                  if Path(x["exe"]).name == a.get("exe_name") or x["exe"] == a.get("location")}
        # an agent that was already running when the capture began is the parent of its steps
    steps = []
    # The agent's deployment: the commands its parent ran in the two minutes before launching
    # it that name the agent's file or its CALDERA server (download, chmod, launch). Attack
    # activity outside the agent's own process tree (lab plan amendment A2).
    deploy: set[str] = set()
    for agent in [x for x in execs if x["key"] in roots]:
        name = Path(agent["exe"]).name
        server = next((v for v in agent["argv"] if v.startswith(("http://", "https://"))), None)
        keys = {agent["key"]}
        for y in execs:
            if (y is not agent and y["host"] == agent["host"] and y["parent_key"] == agent["parent_key"]
                    and agent["ts"] - 120 <= y["ts"] <= agent["ts"]):
                text = " ".join(y["argv"])
                if name in text or (server and server in text):
                    keys |= subtree([y["key"]])
        deploy |= keys
        steps.append({"host": agent["host"], "name": "Agent deployment", "status": "success",
                      "technique_id": "T1105", "command": " ; ".join(" ".join(y["argv"]) for y in execs
                                                                     if y["key"] in keys)[:300],
                      "run": _iso(agent["ts"]), "keys": keys, "matched": True, "deployment": True})
    for paw, v in report.get("steps", {}).items():
        host = paw_host.get(paw)
        for l in (v["steps"] if isinstance(v, dict) else v):
            run = l.get("run") or l.get("agent_reported_time") or l.get("delegated")
            t = _epoch(run) if run else None
            cands = [x for x in by_host_pid.get((host, l.get("pid")), [])
                     if t is None or abs(x["ts"] - t - offset.get(host, 0.0)) <= slack]
            if not cands and l.get("pid") is None:
                cands = _by_command(execs, host, _command(l), t, offset.get(host, 0.0), slack)
            keys = subtree(x["key"] for x in cands)
            steps.append({"host": host, "name": l.get("name"), "status": _STATUS.get(l.get("status"), "failed"),
                          "technique_id": (l.get("attack") or {}).get("technique_id"),
                          "command": _command(l), "run": run, "keys": keys, "matched": bool(cands)})
            # the step's parent is the agent: include it as a root
            for x in cands:
                roots.add(x["parent_key"])
    # Bootstrap abilities run by each agent on creation: not in the operation report.
    created = {a.get("host"): _epoch(a["created"]) for a in report.get("host_group", []) if a.get("created")}
    for act in (ground_truth or {}).get("actions", []):
        t = _epoch(act["time"])
        host = min(created, key=lambda h: abs(created[h] - t), default=None)
        if host is None or abs(created[host] - t) > slack:
            continue
        cands = _by_command(execs, host, act.get("detail"), t, offset.get(host, 0.0), slack)
        steps.append({"host": host, "name": f"Bootstrap {act.get('technique')}",
                      "status": "success" if act.get("result") == "success" else "failed",
                      "technique_id": act.get("technique"), "command": act.get("detail"), "run": act["time"],
                      "keys": subtree(x["key"] for x in cands), "matched": bool(cands), "bootstrap": True})
    return {"malicious": subtree(roots) | deploy, "steps": steps, "clock_offset_s": offset}


def _event(name: str, i: int, x: dict) -> dict:
    if x.get("kind") is None:                                        # an execve
        et, facts = "process_create", {"image": Path(x["exe"]).name, "image_path": x["exe"],
                                       "command_line": " ".join(x["argv"]),
                                       "parent_image": x["parent_image"], "user": x["user"], "cwd": x["cwd"]}
    else:
        et, facts = x["kind"], {"image": Path(x["exe"]).name, "image_path": x["exe"], "user": x["user"],
                                **x["facts"]}
    return {"event_id": f"{name}:auditd:{i}", "ts": x["ts"], "time": _iso(x["ts"]), "source": "auditd",
            "event_type": et, "host": x["host"], "facts": facts, "provenance": {"file": f"{x['host']}/audit.log"}}


def convert(captured: Path, out: Path, name: str, report: Path | None = None,
            ground_truth: Path | None = None, window_minutes: int = 30, progress=None,
            source: str | None = None) -> dict:
    """Write the capture's windows to `out/<name>_<host>_<HHMM>/`. `progress(stage, done,
    total)` is told how far it got; `source` (the capture folder, as the analyst named it) is
    recorded in each window's meta. Returns a summary of what was written."""
    tell = progress or (lambda *_: None)
    captured, out = Path(captured), Path(out)
    hosts = sorted(p.parent.name for p in captured.glob("*/audit.log"))
    if not hosts:
        raise ValueError(f"no <host>/audit.log in {captured}")
    execs, acts, rules, gaps = [], [], {}, {}
    for i, h in enumerate(hosts):
        tell("reading", i, len(hosts))
        records = _records(captured / h / "audit.log")
        execs += execs_of(records, h)
        acts += acts_of(records, h)
        rules[h] = rules_of(records)
        gaps[h] = gaps_of(records)
    execs.sort(key=lambda x: x["ts"])
    acts.sort(key=lambda x: x["ts"])
    build_lineage(execs, acts)
    rep = json.loads(Path(report).read_text()) if report else None
    gt = json.loads(Path(ground_truth).read_text()) if ground_truth else None
    lab = labels_from_report(rep or {}, execs, gt)
    other_sensors = sorted({p.name for p in captured.glob("*/auth.log")} |
                           ({"zeek (network/*.log)"} if any(captured.glob("network/conn.log")) else set()))

    w = window_minutes * 60
    grid = {h: sorted({int(x["ts"] // w) * w for x in execs + acts if x["host"] == h}) for h in hosts}
    total, n = sum(len(v) for v in grid.values()), 0
    summary = []
    for h in hosts:
        mine = sorted([x for x in execs + acts if x["host"] == h], key=lambda x: (x["ts"], x.get("kind") is not None))
        for start in grid[h]:
            tell("writing", n, total)
            n += 1
            xs = [x for x in mine if start <= x["ts"] < start + w]
            wname = f"{name}_{h}_{datetime.fromtimestamp(start, tz=timezone.utc):%H%M}"
            d = out / wname
            d.mkdir(parents=True, exist_ok=True)
            events = [_event(wname, i, x) for i, x in enumerate(xs)]
            actors, procs = {}, {}
            for e, x in zip(events, xs):
                actors[e["event_id"]] = [x["key"]]
                if x.get("kind") is None:
                    procs[x["key"]] = {"image": Path(x["exe"]).name, "path": x["exe"], "parent": x["parent_key"]}
                elif x["key"].endswith("@pre") and x["key"] not in procs:
                    procs[x["key"]] = {"image": Path(x["exe"]).name, "path": x["exe"],
                                       "parent": x.get("parent_key")}
            # parents seen in this window but launched earlier: keep the chain walkable
            for x in mine:
                if x.get("kind") is None and x["key"] not in procs and x["ts"] < start:
                    procs[x["key"]] = {"image": Path(x["exe"]).name, "path": x["exe"], "parent": x["parent_key"]}
            # each process's distinct child programs over its recorded life up to the window's
            # end, so a session hub (a login shell) is recognised even in a window where it
            # launched little (lab plan amendment A2)
            kids: dict[str, set] = defaultdict(set)
            for x in mine:
                if x.get("kind") is None and x["ts"] < start + w:
                    kids[x["parent_key"]].add(Path(x["exe"]).name)
            for k in sorted({p["parent"] for p in procs.values() if p.get("parent")} - set(procs)):
                procs[k] = {"image": None, "path": None, "parent": None}       # started before the capture
            for k, p in procs.items():
                if kids.get(k):
                    p["children"] = sorted(kids[k])[:64]
            (d / "events.jsonl").write_text("".join(json.dumps(e) + "\n" for e in events))
            (d / "lineage.json").write_text(json.dumps({"format": "lineage-v1", "actors": actors,
                                                        "processes": procs,
                                                        "note": "auditd execve/connect/watch; key = host/pid@exec-time"}))
            mal = [e["event_id"] for e, x in zip(events, xs) if x["key"] in lab["malicious"]]
            abil = []
            for s in lab["steps"]:
                if s["host"] != h:
                    continue
                ev = [e["event_id"] for e, x in zip(events, xs) if x["key"] in s["keys"]]
                if ev:
                    abil.append({"name": s["name"], "status": s["status"], "technique_id": s["technique_id"],
                                 "command": s["command"], "event_ids": ev, "bootstrap": bool(s.get("bootstrap")),
                                 "deployment": bool(s.get("deployment")),
                                 "process_event_ids": [e["event_id"] for e in events
                                                       if e["event_id"] in set(ev) and e["event_type"] == "process_create"]})
            if rep is not None:                       # labels only from a CALDERA report
                (d / "labels.json").write_text(json.dumps({
                    "category": "attack" if mal else "benign", "malicious_event_ids": mal,
                    "abilities": abil, "source": f"CALDERA report {Path(report).name}"
                    + (f" + bootstrap actions from {Path(ground_truth).name}" if gt else "")
                    + ": step pid + descendants, agent lineage"}, indent=1))
            proto = Counter(k for x in xs if x.get("kind") is None for k, f in PROTOCOL.items() if f(x))
            kinds = Counter(e["event_type"] for e in events)
            keys = loaded_keys(rules[h], start + w)
            contract = (["process_create"] if "exec" in keys else []) + \
                       (["network_connection"] if "net" in keys else [])
            meta = {
                "scenario_id": wname, "dataset": "lab", "campaign": name, "host": h,
                "format": "argus-events-v1", "generated_by": "argus/collectors/lab_capture.py (real auditd capture)",
                "capture": {"window": {"start": _iso(start), "end": _iso(start + w)}},
                "events": len(events), "event_types": dict(sorted(kinds.items())),
                "sensor": "auditd", "audit_rules_loaded": sorted(keys), "sensor_contract": contract,
                "sensor_gaps": gaps[h].overlapping(start, start + w),
                "captured_not_ingested": other_sensors,
                "clock_offset_vs_caldera_s": round(lab["clock_offset_s"].get(h, 0.0), 1),
                "protocol_activity": dict(proto),
                "capture_gate": "pass" if not proto else "fail: " + ", ".join(sorted(proto))}
            if source:
                meta["capture_folder"] = source
            (d / "meta.json").write_text(json.dumps(meta, indent=1))
            summary.append((wname, len(events), kinds.get("network_connection", 0),
                            sum(v for k, v in kinds.items() if k.startswith("file_")), len(mal), len(abil),
                            "pass" if not proto else ",".join(sorted(proto))))
    tell("writing", total, total)
    unmatched = [s for s in lab["steps"] if not s["matched"]]
    return {"hosts": hosts, "windows": summary, "labelled": rep is not None,
            "steps": len(lab["steps"]), "steps_matched": len(lab["steps"]) - len(unmatched),
            "unmatched": [(s["host"], s["name"]) for s in unmatched],
            "clock_offset_s": {h: round(o, 1) for h, o in lab["clock_offset_s"].items()}}
