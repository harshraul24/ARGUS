#!/usr/bin/env bash
# forward-logs.sh MAC_IP [PORT]  — run on a victim as root, once (after fixup.sh, before the
# burned-in snapshot, so every revert keeps it).
#
# Streams this victim's audit.log, auth.log and the persona's ~/benign-activity.log to the
# Mac's log_receiver.py as they are written, so nothing has to be pulled at the end of a run.
# The victim keeps its own logs (the local view); the Mac's copy is the forwarded view.
#   - rsyslog (already installed) follows the files with imfile and sends each new line over
#     TCP, octet-counted, so a line arrives exactly as written
#   - auditd's enriched-field separator (0x1d) is not escaped, and lines up to 64 KB pass whole
#   - lines that cannot be sent wait in a disk queue and go when the Mac is listening again
#   - only lines written from now on are sent (no backlog of older logs)
# Usage:  sudo ./forward-logs.sh 192.168.64.1          (the Mac's address log_receiver.py prints)
set -eu
MAC="${1:?usage: sudo ./forward-logs.sh MAC_IP [PORT]}"
PORT="${2:-10514}"
[ "$(id -u)" = 0 ] || { echo "run as root (sudo)"; exit 1; }

# settings rsyslog reads before any input starts: at the top of the main file
for line in '$MaxMessageSize 64k' '$EscapeControlCharactersOnReceive off'; do
  grep -qxF "$line" /etc/rsyslog.conf || sed -i "1i $line" /etc/rsyslog.conf
done

cat > /etc/rsyslog.d/20-argus-forward.conf <<EOF
# written by forward-logs.sh — stream the capture's logs to the Mac (log_receiver.py)
module(load="imfile")
input(type="imfile" File="/var/log/audit/audit.log" Tag="argus-audit" Ruleset="argus" freshStartTail="on" reopenOnTruncate="on")
input(type="imfile" File="/var/log/auth.log" Tag="argus-auth" Ruleset="argus" freshStartTail="on" reopenOnTruncate="on")
input(type="imfile" File="/home/*/benign-activity.log" Tag="argus-activity" Ruleset="argus" freshStartTail="on")
ruleset(name="argus") {
  action(type="omfwd" target="$MAC" port="$PORT" protocol="tcp" TCP_Framing="octet-counted"
         template="RSYSLOG_SyslogProtocol23Format"
         queue.type="LinkedList" queue.filename="argus_fwd" queue.maxDiskSpace="1g"
         queue.saveOnShutdown="on" action.resumeRetryCount="-1" action.resumeInterval="5")
}
EOF

rsyslogd -N1 >/dev/null 2>&1 || { echo "rsyslog rejected the configuration:"; rsyslogd -N1; exit 1; }
systemctl restart rsyslog
echo "[*] $(hostname): forwarding audit.log, auth.log, benign-activity.log -> $MAC:$PORT"

# a test line straight to the receiver (it is announced there, never written into the capture)
if logger --help 2>&1 | grep -q -- --octet-count; then
  logger -n "$MAC" -P "$PORT" -T --octet-count --rfc5424 -t argus-test "forwarding test from $(hostname)" \
    && echo "[*] test line sent: the receiver should print 'forwarding test received from $(hostname)'" \
    || echo "[!] could not reach $MAC:$PORT — is log_receiver.py running on the Mac?"
fi
