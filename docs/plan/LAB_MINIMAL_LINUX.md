# Minimal-space multi-victim lab (all-Linux, CoW overlays)

A space-frugal realization of `LAB_MULTI_VICTIM.md` for the Linux + CALDERA + auditd path you
chose. Same principle — **distinct identity/role/behaviour, shared base disk** — but sized so a
4–5 victim fleet costs ~6 GB disk and ~5 GB RAM instead of 60–100 GB. Kali (Metasploit +
CALDERA, already installed) stays your attacker/control + capture + log receiver.

> Carried over from `LAB_MULTI_VICTIM.md`, not repeated here: isolation checks (§2), burn-in
> philosophy (§7), capture-on-the-bridge and the two-views log-clearing run (§8–9).

---

## Where the space goes (and how this saves it)

| lever | costly way | minimal way |
|---|---|---|
| **OS family** | Windows 11 ARM (~28 GB, 3.5 GB RAM) | Debian cloud image (~2.5 GB, 0.6 GB RAM) |
| **per-victim disk** | full clone per host (×N) | one read-only **base** + a **CoW overlay** per host (stores only the diff) |
| **differentiation** | separate installs | one base, **cloud-init** sets hostname/users/role/persona on first boot |
| **concurrency** | all victims on at once | **rotate** the powered-on set; CoW snapshots are nearly free |
| **sensor** | — | lightweight **VMs**, not containers (see note) |

**Budget (4 victims + Kali):** base 2.5 GB + 4 × ~0.7 GB overlays ≈ **5.3 GB disk**;
Kali 2 GB + 4 × 0.64 GB ≈ **4.6 GB RAM**. Snapshots add little because overlays are CoW.

**Why VMs, not containers** (the tempting space-min idea): the Linux audit subsystem is
**kernel-global, not namespaced**, so per-container auditd can't cleanly separate one host's
`execve` stream from another's. You'd lose the per-host endpoint telemetry that is the whole
point. Lightweight micro-VMs with CoW overlays are the sweet spot: real kernel per host (clean
auditd) at near-container disk cost.

---

## 1. The estate (all-Linux, fits easily)

| host | base | role | RAM | IP |
|---|---|---|---|---|
| `kali` *(have it)* | Kali ARM64 | CALDERA, Metasploit, dnsmasq (DNS+DHCP), chrony, log receiver, capture | 2 GB | 10.10.0.10 |
| `web01` | Debian 12 cloud | internet-facing-style web app (nginx + a small app + sqlite/postgres) | 0.6 GB | 10.10.0.41 |
| `app01` | Debian 12 cloud | internal app server, SSH open to LAN | 0.6 GB | 10.10.0.42 |
| `ws-dev01` | Debian 12 cloud | developer box: git/python, user `bob` (sudo) | 0.75 GB | 10.10.0.32 |
| `ws-fin01` | Debian 12 cloud | "finance" box: office files, user `alice` (standard) | 0.75 GB | 10.10.0.31 |

Need more victims than RAM allows → build more overlays and **rotate** which are powered on per
campaign (your doc §1). Lateral movement is Linux→Linux over SSH (T1021.004), which is exactly
what `ws-dev01 → app01 → web01` gives you.

---

## 2. One base image (download once)

On the Mac (where the VMs run):
```bash
mkdir -p ~/lab && cd ~/lab
# Debian 12 "genericcloud" ARM64 — tiny, boots with cloud-init
curl -LO https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-arm64.qcow2
qemu-img info debian-12-genericcloud-arm64.qcow2      # ~2–3 GB virtual, ~0.3 GB on disk
```
This file is the **read-only base**. No victim ever writes to it.

## 3. Make each victim: CoW overlay + cloud-init seed

**Run this on the Mac** (where QEMU/UTM run the VMs and the base image lives), from `~/lab`.
Install the tools once: `brew install qemu cdrtools`. The script below uses `mkisofs` so it
runs natively on macOS; on Kali instead, swap the `mkisofs` line for
`cloud-localds "victims/$NAME/seed.iso" "victims/$NAME/user-data" "victims/$NAME/meta-data"`.

```bash
#!/usr/bin/env bash
# make-victim.sh NAME IP ROLE   (ROLE: web|app|dev|fin)
set -euo pipefail
NAME=$1 IP=$2 ROLE=${3:-app}; KALI=10.10.0.10
BASE="$PWD/debian-12-genericcloud-arm64.qcow2"
mkdir -p "victims/$NAME"
# CoW overlay: only $NAME's diffs are stored; base stays shared + read-only
qemu-img create -f qcow2 -F qcow2 -b "$BASE" "victims/$NAME/disk.qcow2" 12G
case $ROLE in
  web) PKGS="nginx sqlite3"; USER=www;;
  app) PKGS="openssh-server rsync"; USER=svc;;
  dev) PKGS="git python3 build-essential"; USER=bob;;
  fin) PKGS="libreoffice-calc"; USER=alice;;
esac
cat > "victims/$NAME/meta-data" <<EOF
instance-id: $NAME
local-hostname: $NAME
EOF
cat > "victims/$NAME/user-data" <<EOF
#cloud-config
hostname: $NAME
fqdn: $NAME.lab.local
users:
  - name: $USER
    groups: sudo
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: $LAB_PASSWORD
ssh_pwauth: true
packages: [auditd, chrony, $PKGS]
write_files:
  - path: /etc/audit/rules.d/execve.rules
    content: |
      -a always,exit -F arch=b64 -S execve -k exec
      -a always,exit -F arch=b32 -S execve -k exec
  - path: /etc/netplan/99-lab.yaml
    permissions: '0600'
    content: |
      network:
        version: 2
        ethernets:
          enp0s1:
            addresses: [$IP/24]
            nameservers: {addresses: [$KALI]}
            routes: []        # no default route = no internet during a run
  - path: /etc/chrony/sources.d/lab.sources
    content: "server $KALI iburst\n"
runcmd:
  - [ netplan, apply ]
  - [ augenrules, --load ]
  - [ systemctl, enable, --now, auditd ]
  - [ systemctl, restart, chrony ]
EOF
# macOS: volume MUST be named cidata for cloud-init NoCloud to find the seed
mkisofs -o "victims/$NAME/seed.iso" -V cidata -J -r \
  "victims/$NAME/user-data" "victims/$NAME/meta-data"
echo "built victims/$NAME  (role=$ROLE user=$USER ip=$IP)"
```

```bash
chmod +x make-victim.sh
./make-victim.sh web01    10.10.0.41 web
./make-victim.sh app01    10.10.0.42 app
./make-victim.sh ws-dev01 10.10.0.32 dev
./make-victim.sh ws-fin01 10.10.0.31 fin
du -sh debian-12-genericcloud-arm64.qcow2 victims/*   # confirm overlays are small
```

auditd (the eCAR-parity endpoint sensor), chrony (time sync to Kali — your doc's 34-hour-skew
lesson), the static lab IP and the per-role software/user are all set on first boot. No per-host
manual install.

## 4. Network: reuse Kali's isolated host-only net

Keep the one isolated L2 you already use for Kali so the victims, Kali and the capture point all
share it (your doc §2). Two practical ways:

- **UTM (simplest, matches your doc):** import each `victims/<name>/disk.qcow2` as the disk and
  `seed.iso` as a second CD in a new UTM Linux VM, 2 cores / 640–768 MB, on the **Host Only**
  network with Kali. Capture on the Mac bridge (`ifconfig | grep bridge`, usually `bridge100`).
- **CLI QEMU (lowest overhead):** boot each with `-accel hvf`, the overlay + seed as drives, and
  Apple `vmnet-host` (isolated, no internet) so guests + Kali + host interconnect. vmnet needs
  `sudo`. Let dnsmasq on Kali hand out the static leases, or keep the netplan addresses above.

Provisioning needs internet once (to `apt` the role packages): give each VM a temporary
**Shared** adapter for the first boot only, then switch it to **Host Only** and re-run the
isolation check (`ping 10.10.0.10` ok, `ping 8.8.8.8` / DNS fail) before any attack.

## 5. Differentiate behaviour + burn in (cheap, CoW)

Per your doc §6–7: give each persona a small benign-activity timer (open/edit files, hit the web
app, SSH between hosts, run builds) so each host accrues **its own** history. Then burn in on
benign-only for 10–15 two-hour windows per host. Overlay snapshots cost almost nothing:
```bash
qemu-img snapshot -c burned-in victims/web01/disk.qcow2   # repeat per victim (VM powered off)
# revert before each run:  qemu-img snapshot -a burned-in victims/web01/disk.qcow2
```
(In UTM, use its snapshot button instead.)

## 6. Run a campaign across the fleet

1. Revert all victims to `burned-in`; confirm time sync; start capture on the bridge + the log
   receiver on Kali; leave one benign window.
2. Deploy the CALDERA Sandcat agent on **each** powered-on victim into group `red`
   (`tools/apt_capture/CALDERA_KALI_SETUP.md` §4). Add lateral-movement abilities so the chain
   pivots `ws-dev01 → app01 → web01`.
3. Run one operation over group `red`; keep the operation report (ground truth).
4. Collect per victim: `audit.log`, `auth.log`, the forwarded copies on Kali; plus the shared
   pcap/Zeek and the CALDERA report.

## 7. Into ARGUS (per-host cases — works today)

One ARGUS case per victim; `eval_perevent.py` micro-averages the whole fleet:
```bash
export PYTHONPATH="source code"
python tools/apt_capture/caldera_report.py operation_report.json --out ground_truth.json
for v in web01 app01 ws-dev01 ws-fin01; do
  python tools/apt_capture/to_argus_case.py \
    --auth captured/$v/auth.log --audit captured/$v/audit.log --net captured/$v/zeek/ \
    --ground-truth ground_truth.json --target-ip <$v-ip> --attacker-ip 10.10.0.10 \
    --out cases_linux/${v}_run
  python tools/apt_capture/to_citar_windows.py --case cases_linux/${v}_run \
    --ground-truth ground_truth.json --attacker-ip 10.10.0.10 --name $v --out cases_apt
done
python tools/eval_perevent.py --root cases_apt
```

---

## Honest trade-offs of going minimal/all-Linux

- **You lose Windows/AD telemetry** (Security 4624/4648/5140, Sysmon, domain logons, SMB
  lateral). That's real CITAR-flavour signal. But you chose Linux, ARGUS's detectors are
  Windows-verb-shaped today anyway, and adding Windows back is a separate, heavier build — not a
  blocker for the Linux test.
- **Lateral movement across hosts** is generated and *labelled* (SSH, attacker-IP set), but ARGUS
  doesn't yet *correlate* the pivot across hosts (per-host reasoning + auditd flattens host id).
  Detecting the pivot itself is the cross-host-correlation build we flagged — separate from this
  lab setup.
- **Overlays share a base:** fine for identity/role/behaviour (set per host), but if you ever
  need genuinely different kernels/distros per victim, build a second base image for those.
