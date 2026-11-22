#!/usr/bin/env bash
# fixup.sh KALI_IP   — run on a victim as root after boot.
# Idempotent repair so a victim is sensor-complete regardless of what vmnet did this boot:
#   1. install any missing sensors (needs internet)
#   2. point rsyslog forwarding + chrony at the CURRENT Kali IP (so the stale baked seed IP
#      doesn't matter)
#   3. load the audit rules and start every sensor
# Usage:  sudo ./fixup.sh 192.168.64.<kali>
set -u
KALI="${1:?usage: sudo ./fixup.sh KALI_IP}"
export DEBIAN_FRONTEND=noninteractive

echo "[*] internet check:"
if ping -c1 -W2 deb.debian.org >/dev/null 2>&1; then echo "  ok"; NET=1; else echo "  NO INTERNET — package install will be skipped"; NET=0; fi

if [ "$NET" = 1 ]; then
  echo "[*] installing any missing sensors ..."
  apt-get update -qq
  for p in auditd rsyslog cron sshpass; do
    dpkg -s "$p" >/dev/null 2>&1 || apt-get install -y "$p"
  done
fi

echo "[*] forwarding + time -> $KALI"
echo "*.* @@$KALI:514" > /etc/rsyslog.d/10-forward.conf
printf 'server %s iburst prefer\n' "$KALI" > /etc/chrony/sources.d/lab.sources

echo "[*] raising auditd max_log_file (fewer rotations per window; pull-all still catches any) ..."
sed -i 's/^max_log_file *=.*/max_log_file = 100/' /etc/audit/auditd.conf 2>/dev/null || true
sed -i 's/^num_logs *=.*/num_logs = 10/' /etc/audit/auditd.conf 2>/dev/null || true

echo "[*] loading audit rules ..."
augenrules --load 2>/dev/null || auditctl -R /etc/audit/rules.d/argus.rules 2>/dev/null || true

echo "[*] starting sensors ..."
systemctl enable --now auditd rsyslog cron 2>/dev/null || true
systemctl restart rsyslog chrony 2>/dev/null || true

echo "[*] result:"
echo -n "  rules: "; auditctl -l 2>/dev/null | wc -l
echo -n "  services: "; systemctl is-active auditd rsyslog cron | tr '\n' ' '; echo
echo "[*] forwarding test (check on Kali: sudo grep fixup-test /var/log/lab/*/forwarded.log):"
logger "fixup-test from $(hostname)"
