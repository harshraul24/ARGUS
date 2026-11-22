#!/usr/bin/env bash
# benign_agent.sh — capture BENIGN background telemetry against the same target, in the
# same shape as capture.sh, so to_citar_windows.py can turn it into the benign half of the
# CITAR-style test. The CITAR test is ~99% benign; a capture that is 100% attack measures
# recall but never the false-positive rate, which is the whole point of the benign windows.
#
# It drives ordinary administrator activity over SSH FROM A BENIGN HOST (not the attacker
# IP) — normal logins, file and package operations, service checks, web fetches — while a
# wire capture + the target's auth.log/syslog record it. No exploitation, no Metasploit.
#
# Runs on the BENIGN-admin VM. Usage (env-var driven):
#   TARGET_IP=10.0.2.20 IFACE=eth0 DURATION_MIN=120 ./benign_agent.sh
#
# Env vars:
#   TARGET_IP        (required) target IP
#   IFACE            capture interface facing the target        (default: eth0)
#   TARGET_SSH_USER  ssh user on the target                     (default: msfadmin)
#   TARGET_SSH_PASS  password for non-interactive ssh (sshpass) (optional; else key auth)
#   DURATION_MIN     how long to generate benign activity, min  (default: 120, = CITAR window)
#   PERIOD_SEC       seconds between benign actions             (default: 20)
#   OUT              output directory                           (default: ./benign_<timestamp>)
#
# Requires on this host: tcpdump, zeek, ssh/scp (sshpass if using TARGET_SSH_PASS).
# Run only in your licensed, isolated lab.
set -euo pipefail

: "${TARGET_IP:?set TARGET_IP=<target ip>}"
IFACE="${IFACE:-eth0}"
TARGET_SSH_USER="${TARGET_SSH_USER:-msfadmin}"
DURATION_MIN="${DURATION_MIN:-120}"
PERIOD_SEC="${PERIOD_SEC:-20}"
OUT="${OUT:-./benign_$(date -u +%Y%m%d_%H%M%S)}"

mkdir -p "$OUT"/{pcap,zeek,captured}
OUT="$(cd "$OUT" && pwd)"

echo "[*] output dir : $OUT"
echo "[*] target     : $TARGET_IP  (iface $IFACE)"
echo "[*] duration   : ${DURATION_MIN}m  (action every ${PERIOD_SEC}s)"

# ssh/scp wrappers: use sshpass if a password is supplied, else key auth. StrictHostKey
# off is for the throwaway lab target only.
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5"
if [ -n "${TARGET_SSH_PASS:-}" ]; then
  _ssh() { sshpass -p "$TARGET_SSH_PASS" ssh $SSH_OPTS "$TARGET_SSH_USER@$TARGET_IP" "$@"; }
  _scp() { sshpass -p "$TARGET_SSH_PASS" scp $SSH_OPTS "$@"; }
else
  _ssh() { ssh $SSH_OPTS "$TARGET_SSH_USER@$TARGET_IP" "$@"; }
  _scp() { scp $SSH_OPTS "$@"; }
fi

CAMPAIGN_START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
echo "$CAMPAIGN_START" > "$OUT/CAMPAIGN_START"
echo "[*] start      : $CAMPAIGN_START"

echo "[*] starting tcpdump ..."
sudo tcpdump -i "$IFACE" -w "$OUT/pcap/campaign.pcap" "host $TARGET_IP" >/dev/null 2>&1 &
TCPDUMP_PID=$!
cleanup() { sudo kill "$TCPDUMP_PID" 2>/dev/null || true; }
trap cleanup EXIT
sleep 2

# --- benign workload: a rotation of ordinary admin actions, each a fresh SSH session so
#     auth.log fills with *accepted* logins from this benign host (never the attacker IP).
BENIGN_ACTIONS=(
  "uptime; whoami"
  "ls -la /home/$TARGET_SSH_USER; df -h"
  "cat /etc/hostname; uname -a"
  "ps aux | head -20"
  "netstat -tuln 2>/dev/null | head; free -m 2>/dev/null || true"
  "echo working >> /home/$TARGET_SSH_USER/notes.txt; tail -n 3 /home/$TARGET_SSH_USER/notes.txt"
  "apt-get -s upgrade 2>/dev/null | head -5 || true"
  "service --status-all 2>/dev/null | head || true"
)

echo "[*] generating benign activity ..."
END=$(( $(date +%s) + DURATION_MIN * 60 ))
i=0
while [ "$(date +%s)" -lt "$END" ]; do
  action="${BENIGN_ACTIONS[$(( i % ${#BENIGN_ACTIONS[@]} ))]}"
  if _ssh "$action" >/dev/null 2>&1; then
    echo "  [$(date -u +%H:%M:%S)] ok  : ${action%%;*}"
  else
    echo "  [$(date -u +%H:%M:%S)] skip: ${action%%;*} (unreachable?)"
  fi
  i=$(( i + 1 ))
  sleep "$PERIOD_SEC"
done
echo "[*] generated $i benign actions"

echo "[*] stopping tcpdump ..."
sudo kill "$TCPDUMP_PID" 2>/dev/null || true
trap - EXIT
sleep 1

# --- snapshot the target's logs (same as capture.sh) ---
echo "[*] fetching target logs ..."
_scp "$TARGET_SSH_USER@$TARGET_IP:/var/log/auth.log" "$OUT/captured/auth.log" 2>/dev/null \
  || echo "[!] could not fetch auth.log (check ssh/perms)"
_scp "$TARGET_SSH_USER@$TARGET_IP:/var/log/syslog" "$OUT/captured/syslog" 2>/dev/null || true

# --- Zeek over the pcap (same as capture.sh) ---
if command -v zeek >/dev/null 2>&1; then
  echo "[*] running Zeek over the capture ..."
  ( cd "$OUT/zeek" && zeek -r "$OUT/pcap/campaign.pcap" >/dev/null 2>&1 ) || echo "[!] zeek failed"
  cp "$OUT"/zeek/*.log "$OUT/captured/" 2>/dev/null || true
else
  echo "[!] zeek not found — skipping network logs"
fi

cat > "$OUT/benign_ground_truth.json" <<EOF
{ "category": "benign", "campaign_start": "$CAMPAIGN_START",
  "techniques": [], "primary_technique": null, "objective_reached": false,
  "actions": [], "note": "benign admin workload ($i actions), no exploitation" }
EOF

echo
echo "[*] done. next:"
echo "    python tools/apt_capture/to_argus_case.py --auth $OUT/captured/auth.log \\"
echo "        --net $OUT/captured/ --ground-truth $OUT/benign_ground_truth.json \\"
echo "        --target-ip $TARGET_IP --attacker-ip - --category benign \\"
echo "        --out cases_benign/admin_$(date -u +%Y%m%d)"
echo "    python tools/apt_capture/to_citar_windows.py --case cases_benign/admin_$(date -u +%Y%m%d) \\"
echo "        --category benign --window-minutes 120 --name admin --out cases_apt"
