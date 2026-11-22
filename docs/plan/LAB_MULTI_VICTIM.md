# Multi-victim lab — N distinct victims, not N copies

**Purpose:** a fresh, real capture corpus for ARGUS: several victims, each a different machine
with its own identity, role, software, users and history, attacked by CALDERA's published
adversary profiles. Telemetry only, no synthetic data.

**Host:** this Mac: Apple Silicon, 16 GB RAM, 105 GB free, UTM installed. All guests are ARM64
and run in UTM's *Virtualize* mode, because emulating x86 Windows is too slow.

**Scope:** an isolated lab of machines you own. Victims never reach the internet while an
attack runs. Snapshot before every run.

---

## 0. Why copies are not enough

A cloned VM is the same machine twice: the same machine SID, hostname, users, software,
documents and behaviour. For ARGUS that breaks the evaluation in four ways:
- **Per-host baselines:** C4 history and P3 novelty learn one host's background, so two clones
  give one data point, not two.
- **Lateral movement:** identical hosts make every hop look the same.
- **Benign background:** a "different" benign window is the same workload replayed.
- **Identity:** duplicate SIDs and names break domain membership and confuse logon telemetry.

Sharing a base disk is not the problem. **Identity, role and behaviour must differ.** The
steps below get that difference from five sources:
1. different OS families and builds, installed separately;
2. a new identity per Windows machine (sysprep);
3. a role per machine;
4. a persona per user;
5. days of each host's own benign history before any attack.

---

## 1. Plan the estate (fits 16 GB)

| host | OS (install separately) | role | RAM | IP |
|---|---|---|---|---|
| `kali` | Kali ARM64 | CALDERA server, NTP and DNS for the lab, log receiver | 2 GB | 10.10.0.10 |
| `dc01` | Ubuntu Server 24.04 ARM64 | Samba AD domain controller + file shares (`\\dc01\finance`, `\\dc01\it`) | 1 GB | 10.10.0.20 |
| `ws-fin01` | Windows 11 ARM64 (one build) | finance workstation: user `alice`, office documents, mapped finance share | 3.5 GB | 10.10.0.31 |
| `ws-dev01` | Windows 11 ARM64 (a different build or edition, if you can) | developer workstation: user `bob`, git/Python/VS Code, local admin | 3.5 GB | 10.10.0.32 |
| `web01` | Debian 12 ARM64 | internal web app (nginx + small app + database) | 0.75 GB | 10.10.0.41 |

That's about 10.75 GB for guests, leaving about 5 GB for macOS: four victims plus the
attacker.

- **More victims than RAM allows:** build more distinct machines and **rotate** them. Each
  campaign runs against the set that is powered on (for example `ws-fin01 + ws-dev01 + dc01`,
  then `ws-fin02 + web01 + dc01`). The corpus then has N distinct victims even though only
  four run at once.
- **A second computer** on the same isolated network adds simultaneous victims.

---

## 2. One isolated network

1. **Network mode.** In UTM, give every VM a single network card in **Host Only** mode, with no
   *Shared* or *Bridged* adapter. The VMs then reach each other and the Mac, but not the
   internet.
2. **Static IPs** per the table. `kali` runs `dnsmasq` for lab DNS (`*.lab.local`) and `chrony`
   as the lab's time source.
3. **Prove isolation** on every victim. Pinging `10.10.0.10` must succeed; pinging `8.8.8.8` and
   resolving `example.com` must fail.
4. **Protect the Mac.** Turn on the macOS firewall (System Settings → Network → Firewall) so
   guests cannot reach services on the Mac itself.
5. **Network sensor.** UTM's host-only network is a bridge on the Mac. `ifconfig | grep bridge`
   shows it, usually `bridge100`/`bridge101`. Capture there (`tcpdump`/Zeek on the Mac, or in
   Kali if its card can see all traffic). That sees every guest-to-guest packet, including
   lateral movement.

---

## 3. Install each OS separately (do not clone across roles)

Install while the VM still has internet access (temporarily give it a *Shared Network*
adapter), then switch it to Host Only in step 7.

- **Windows 11 ARM64:** the official ARM64 ISO from Microsoft (or build one with CrystalFetch).
  - In UTM: *Virtualize* → *Windows* → attach the ISO; 4 cores, 3.5 GB RAM, 64 GB disk; install
    the UTM guest tools.
  - Use your university licence, or run it unactivated (that's fine for a lab).
- **Ubuntu Server 24.04 ARM64** (`dc01`) and **Debian 12 ARM64** (`web01`): minimal installs,
  with OpenSSH.
- **Kali ARM64:** the installer ISO or the prebuilt UTM image.

**Two Windows workstations without two full installs.** Install Windows once, configure only
the parts every workstation shares (step 5), then **generalise** it:
```
C:\Windows\System32\Sysprep\sysprep.exe /generalize /oobe /shutdown
```
Clone that powered-off VM in UTM once per workstation. Each clone runs OOBE on first boot and
gets a **new machine SID**. Give each its own name (`ws-fin01`, `ws-dev01`) during OOBE, or
with an `unattend.xml`. If you can, use a different Windows build for the second workstation;
patch-level differences are realistic and visible in telemetry.

---

## 4. A real domain (makes multi-host behaviour realistic)

On `dc01`:
- provision **Samba as an Active Directory DC** for `lab.local`;
- create the domain users `alice`, `bob`, `carol` (IT) and a helpdesk account;
- create a `Finance` and an `IT` group, and the two shares.

Join `ws-fin01` and `ws-dev01` to `lab.local`. Then:
- logons are domain logons;
- shares are real SMB;
- moving between hosts happens over the protocols an enterprise really uses, and ARGUS sees it
  in the Security log (4624/4648/5140) and in Zeek.

`web01` stays outside the domain, as a server would.

---

## 5. Defender telemetry on every victim (install before isolating)

**Windows** (golden image, then checked on each workstation):
- **Sysmon (ARM64 build)** with a maintained community configuration, such as
  *sysmon-modular* or *SwiftOnSecurity*. Enable process creation (with hashes and parent),
  network connections, image loads, file create/delete, registry, process access and DNS.
  Together these give the same depth as CITAR's eCAR, plus the process tree.
- **Audit policy:** process creation with **command line** (event 4688), logon and logoff,
  special logon, explicit credentials, file share access, and **audit log cleared** (1102).
- **PowerShell** script-block and module logging.
- **Forwarding a copy off the host:** install **Winlogbeat** (or NXLog) shipping Sysmon,
  Security, System and PowerShell logs to a receiver on `kali`. That copy is what survives
  when an attacker clears logs on the victim.

**Linux** (`dc01`, `web01`):
- **Sysmon for Linux** (same event schema as Windows Sysmon), or `auditd` with execve rules;
- `auth.log`;
- forward with Filebeat/rsyslog to `kali`.

**Time:** every victim syncs to `kali`.
- Windows: `w32tm /config /manualpeerlist:10.10.0.10 /syncfromflags:manual /update`
- Linux: `chrony` client.

Earlier lab runs had a 34-hour clock skew, and per-event labels need consistent time.

---

## 6. Make each victim a different machine

Apply per host after sysprep and the domain join. Stage every installer while the VM still has
internet.

| | `ws-fin01` | `ws-dev01` | `dc01` | `web01` |
|---|---|---|---|---|
| software | LibreOffice, PDF reader, browser, a mail client | git, Python, VS Code, a browser, 7-Zip | Samba AD, file shares | nginx, a small web app, PostgreSQL |
| users | alice (standard user) | bob (local admin), carol (IT) signs in sometimes | admin only | service accounts |
| data | spreadsheets/documents in the finance share and Documents | a source repo, scripts | the share contents | the app's database |
| scheduled activity | office hours, document edits, share access | builds, git, terminals, package installs from a local mirror | backups, AD replication noise | cron jobs, log rotation |
| distinct config | RDP off, Defender on | RDP on, a dev tool in user-writable AppData | — | SSH open to the LAN |

**Use real documents and code**, not generated ones: public-domain office documents, an
open-source repository, a public dataset for the database.

**Benign activity, the honest options:**
- **Best: a real person uses the machines** for a few sessions. Log the times, so those
  windows are known benign.
- **Practical: a per-persona activity driver**, a scheduled script that opens, edits and saves
  files, browses the internal web app, accesses shares and runs builds. Give each persona its
  own schedule and randomness. CITAR did the same thing (its "SimulatedFiles" user
  simulator).
  - Record in each window's metadata which kind produced it. A driver's activity is real
    telemetry from real processes, but its pattern is scripted, and the thesis should say so.

---

## 7. Isolate, burn in, snapshot

1. Switch every VM to **Host Only** (step 2) and repeat the isolation check.
2. **Burn in: run the estate on benign activity only for several days**, in at least 10–15
   two-hour windows per host. This builds each host's own history. The C4 history check and
   the novelty baseline need it, and it gives benign test windows. It is also what makes the
   hosts differ: each accumulates its own updates, caches, logs and quirks.
3. **Snapshot every VM: `burned-in`.** Revert to it before each attack run, so each campaign
   starts from the same estate.

---

## 8. Each capture run

1. Revert all victims to `burned-in`; check time sync; start the network capture on the bridge
   and the log receiver on `kali`.
2. Leave **at least one benign window** before the attack starts.
3. In CALDERA (install as in `tools/apt_capture/CALDERA_KALI_SETUP.md`), deploy agents to the
   chosen victims and run one of **CALDERA's published adversary profiles** from its UI. Vary
   the profile and the set of victims per run. Keep CALDERA's operation report: it is the
   ground truth.
4. Keep capturing for at least one window after the operation ends.
5. Collect:
   - each victim's local logs (exported `.evtx`, Linux logs);
   - the forwarded copies on `kali`;
   - the pcap/Zeek logs;
   - the CALDERA report.

**Log-clearing runs give two views of one run.**
- *Local-only:* telemetry as collected from the victim, so cleared logs are gone.
- *Forwarded:* the copy on `kali`, so the evidence survives.

The same attack scored both ways measures exactly what ARGUS claims: does it report the blind
spot when the logs are gone, and still find the attack when the copy survives?

---

## 9. Hand-off to ARGUS (real data only)

Once the first real capture exists, I build and check against it:
1. the converter: Sysmon/Security from several hosts → CITAR-format windows (events, process
   tree, metadata);
2. the multi-host labeller: CALDERA report → per-step, per-host labels;
3. the evaluation, **pre-registered before scoring**. ARGUS and the S3 rule library stay
   frozen. The design/test split of runs is fixed in advance, and nothing is tuned on the test
   runs.

No synthetic fixtures are used. Every tool is validated on the first real capture, with the
checks recorded.
