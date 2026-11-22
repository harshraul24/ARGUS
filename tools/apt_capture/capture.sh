#!/usr/bin/env bash
# capture.sh — run ONE APT-Agent campaign against Metasploitable 2 while capturing
# the DEFENDER telemetry ARGUS consumes: the target's auth.log/syslog + Zeek from a
# wire capture on the attacker↔target path.
#
# Runs on the ATTACKER VM. APT-Agent stays unmodified — this only wraps it.
#
# Usage (env-var driven; sensible defaults):
#   TARGET_IP=10.0.2.20 IFACE=eth0 ./capture.sh
#
# Env vars:
#   TARGET_IP       (required) Metasploitable 2 IP
#   IFACE           capture interface facing the target        (default: eth0)
#   TARGET_SSH_USER ssh user on the target for log snapshot     (default: msfadmin)
#   APT_AGENT_DIR   path to APT-Agent_single_host-master        (default: ~/APT-Agent_single_host-master)
#   VENV_PY         python that has langchain/pymetasploit3      (default: $APT_AGENT_DIR/.venv/bin/python)
#   OUT             output directory                            (default: ./run_<timestamp>)
#
# Requires on the attacker: tcpdump, zeek, ssh/scp, nmap (optional). msfrpcd must be
# running and .env filled before you start. Target must be reachable and ISOLATED
# (no internet). Run only in your licensed lab against Metasploitable 2.
set -euo pipefail

: "${TARGET_IP:?set TARGET_IP=<metasploitable ip>}"
IFACE="${IFACE:-eth0}"
TARGET_SSH_USER="${TARGET_SSH_USER:-msfadmin}"
APT_AGENT_DIR="${APT_AGENT_DIR:-$HOME/APT-Agent_single_host-master}"
VENV_PY="${VENV_PY:-$APT_AGENT_DIR/.venv/bin/python}"
OUT="${OUT:-./run_$(date -u +%Y%m%d_%H%M%S)}"

mkdir -p "$OUT"/{pcap,zeek,captured}
OUT="$(cd "$OUT" && pwd)"    # absolutise

echo "[*] output dir : $OUT"
echo "[*] target     : $TARGET_IP  (iface $IFACE)"
echo "[*] apt-agent  : $APT_AGENT_DIR"

# --- 1. record the exact campaign start; the labeller absolutises TIME offsets from it
CAMPAIGN_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "$CAMPAIGN_START" > "$OUT/CAMPAIGN_START"
echo "[*] start      : $CAMPAIGN_START"

# --- 2. start the wire capture (attacker<->target only)
echo "[*] starting tcpdump ..."
sudo tcpdump -i "$IFACE" -w "$OUT/pcap/campaign.pcap" "host $TARGET_IP" >/dev/null 2>&1 &
TCPDUMP_PID=$!
# ensure we always stop capture, even on error/ctrl-c
cleanup() { sudo kill "$TCPDUMP_PID" 2>/dev/null || true; }
trap cleanup EXIT
sleep 2

# --- 3. run APT-Agent to completion (reads its own .env for model/IPs/MSF/MySQL)
echo "[*] running APT-Agent (this drives the full kill chain) ..."
( cd "$APT_AGENT_DIR" && "$VENV_PY" APT-Agent.py ) 2>&1 | tee "$OUT/apt_agent_run.stdout"

# --- 4. stop capture
echo "[*] stopping tcpdump ..."
sudo kill "$TCPDUMP_PID" 2>/dev/null || true
trap - EXIT
sleep 1

# --- 5. snapshot the TARGET's own logs (the defender telemetry fixtures faked)
echo "[*] pulling target logs over ssh (enter target password if prompted) ..."
scp "$TARGET_SSH_USER@$TARGET_IP:/var/log/auth.log" "$OUT/captured/auth.log" || \
    echo "[!] auth.log copy failed — check ssh/path on target"
scp "$TARGET_SSH_USER@$TARGET_IP:/var/log/syslog"   "$OUT/captured/syslog"   || \
    echo "[!] syslog copy failed (ok if target has none)"

# --- 6. pcap -> Zeek logs (conn.log, ssh.log, dns.log, ...)
# Prefer a native zeek; fall back to the official Docker image (Kali's apt zeek is
# broken by a libc6 conflict, so Docker is the reliable path); else just keep the pcap.
run_zeek() {
    if command -v zeek >/dev/null 2>&1; then
        ( cd "$OUT/zeek" && zeek -C -r "$OUT/pcap/campaign.pcap" )
    elif command -v docker >/dev/null 2>&1; then
        docker run --rm -v "$OUT":/data -w /data/zeek \
            zeek/zeek zeek -C -r /data/pcap/campaign.pcap
    else
        echo "[!] no zeek and no docker — pcap saved, process it later"
        return 1
    fi
}
echo "[*] running Zeek over the pcap ..."
run_zeek || echo "[!] zeek step skipped — pcap is at $OUT/pcap/campaign.pcap for later"

# --- 7. copy APT-Agent's own log next to the capture (auto ground truth source)
cp "$APT_AGENT_DIR/APT-Agent_experiment_log.txt" "$OUT/" 2>/dev/null || \
    echo "[!] APT-Agent_experiment_log.txt not found — did the campaign run?"

echo
echo "[+] capture complete."
echo "    CAMPAIGN_START = $CAMPAIGN_START   (feed to label_campaign.py --start)"
echo "    target logs    : $OUT/captured/"
echo "    zeek logs      : $OUT/zeek/"
echo "    apt-agent log  : $OUT/APT-Agent_experiment_log.txt"
echo
echo "Next (on the machine with the ARGUS repo):"
echo "  python tools/apt_capture/label_campaign.py $OUT/APT-Agent_experiment_log.txt \\"
echo "      --start $CAMPAIGN_START --out $OUT/ground_truth.json"
echo "  python tools/apt_capture/to_argus_case.py \\"
echo "      --auth $OUT/captured/auth.log --syslog $OUT/captured/syslog --net $OUT/zeek \\"
echo "      --ground-truth $OUT/ground_truth.json \\"
echo "      --target-ip $TARGET_IP --attacker-ip <attacker-ip> \\"
echo "      --out cases_linux/apt_live_001"
