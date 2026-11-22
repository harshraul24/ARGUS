#!/usr/bin/env bash
# capture.sh {start|stop|pull} [RUN]
# Multi-sensor capture for the ARGUS lab:
#   start  — begin a network pcap on the Mac's vmnet bridge (sees guest<->guest too)
#   stop   — end the pcap
#   pull   — fetch auth.log (identity) + audit.log (endpoint) from every host in fleet.txt
# Zeek is run separately over the pcap (see notes at the bottom) because it is not on the Mac.
#
# Layout produced:  captured/<RUN>/network/campaign.pcap  and  captured/<RUN>/<victim>/{auth,audit}.log
set -euo pipefail

LAB="$(cd "$(dirname "$0")" && pwd)"
cd "$LAB"
CMD="${1:-}"
RUN="${2:-run_$(date -u +%Y%m%d_%H%M%S)}"
PCAP="captured/$RUN/network/campaign.pcap"
PIDF="captured/$RUN/.tcpdump.pid"
SSH_OPTS="-o StrictHostKeyChecking=accept-new -o ConnectTimeout=6"

# The victim subnet is derived from fleet.txt (first host IP -> /24), so this survives vmnet
# handing out a different subnet between boots. The host vmnet bridge is the interface whose
# own address sits in that /24 (the gateway, usually x.x.x.1).
SUBNET="$(awk '!/^[[:space:]]*#/ && NF>=3 {print $3; exit}' fleet.txt | awk -F. '{print $1"."$2"."$3}')"
bridge_if() {
  [ -n "$SUBNET" ] || return
  ifconfig 2>/dev/null | awk -v p="${SUBNET}." '/^[a-z0-9]+:/{i=substr($1,1,length($1)-1)} $1=="inet" && index($2,p)==1 {print i; exit}'
}

case "$CMD" in
  start)
    mkdir -p "captured/$RUN/network"
    [ -n "$SUBNET" ] || { echo "no usable IP in fleet.txt — fill in the victims' current IPs first"; exit 1; }
    IF="$(bridge_if)"
    [ -n "$IF" ] || { echo "no host interface on ${SUBNET}.0/24 — are the VMs running, and do fleet.txt IPs match 'ip a'?"; exit 1; }
    echo "[*] capturing on $IF (${SUBNET}.0/24)  ->  $PCAP"
    sudo tcpdump -i "$IF" -w "$PCAP" "net ${SUBNET}.0/24" >/dev/null 2>&1 &
    echo $! > "$PIDF"
    echo "[*] tcpdump pid $(cat "$PIDF").  RUN=$RUN"
    echo "    run the CALDERA operation now, then:  ./capture.sh stop $RUN"
    ;;
  stop)
    [ -f "$PIDF" ] && sudo kill "$(cat "$PIDF")" 2>/dev/null || true
    rm -f "$PIDF"
    echo "[*] stopped.  pcap: $PCAP"
    ;;
  pull)
    # read fleet.txt on FD 3 so ssh -t keeps the real tty for the sudo/password prompt
    while read -r name user ip _ <&3; do
      [ -z "${name:-}" ] && continue
      case "$name" in \#*) continue;; esac
      mkdir -p "captured/$RUN/$name"
      echo "[$name] $user@$ip — stage (sudo) then copy  (password: the lab password)"
      # Concatenate ALL rotated segments oldest->newest, so auditd/logrotate rotation inside a
      # window doesn't drop history (audit.log.1/.2 + the live audit.log; same for auth.log).
      ssh -t $SSH_OPTS "$user@$ip" \
        "sudo bash -c 'cat \$(ls -1tr /var/log/audit/audit.log* 2>/dev/null) > /tmp/audit.log 2>/dev/null; cat \$(ls -1tr /var/log/auth.log* 2>/dev/null) > /tmp/auth.log 2>/dev/null; chmod 644 /tmp/audit.log /tmp/auth.log'" || true
      scp $SSH_OPTS "$user@$ip:/tmp/auth.log"  "captured/$RUN/$name/auth.log"  || echo "  (no auth.log)"
      scp $SSH_OPTS "$user@$ip:/tmp/audit.log" "captured/$RUN/$name/audit.log" || echo "  (no audit.log)"
      # persona's own labelled log = the benign ground truth (which look-alike ran when)
      scp $SSH_OPTS "$user@$ip:benign-activity.log" "captured/$RUN/$name/benign-activity.log" 2>/dev/null || echo "  (no benign-activity.log)"
    done 3< fleet.txt
    echo "[*] pulled into captured/$RUN/<victim>/  — now run Zeek over $PCAP (see capture.sh notes)"
    ;;
  *)
    echo "usage: ./capture.sh {start|stop|pull} [RUN]"; exit 1;;
esac

# ---- Zeek over the pcap (Zeek is not installed on the Mac) ----
# Option A — on Kali (has/【apt install zeek】):
#     scp "<mac>:$LAB/captured/<RUN>/network/campaign.pcap" /tmp/
#     cd /tmp && zeek -C -r campaign.pcap            # writes conn.log, dns.log, ...
#     scp *.log "<mac>:$LAB/captured/<RUN>/network/"
# Option B — on the Mac:  brew install zeek  (large), then:
#     ( cd "captured/<RUN>/network" && zeek -C -r campaign.pcap )
#
# Then package a per-victim case with all three sensors, e.g. for web01:
#   python tools/apt_capture/to_argus_case.py \
#     --auth  "captured/<RUN>/web01/auth.log" \
#     --audit "captured/<RUN>/web01/audit.log" \
#     --net   "captured/<RUN>/network/" \
#     --ground-truth captured/<RUN>/ground_truth.json \
#     --target-ip <web01-ip> --attacker-ip 192.168.64.8 \
#     --out cases_linux/web01_<RUN>
