#!/usr/bin/env bash
# run_batch.sh — generate SEVERAL clean ARGUS cases fast, on the ATTACKER (Kali) VM.
#
# Why: one unbounded autonomous campaign wastes ~45 min in nmap full-port scans and
# never terminates. Instead we run ONE short, SERVICE-LOCKED campaign per Metasploitable
# service, each with a hard timeout and a CLEAN target log (baseline truncated first).
# Result: ~5 distinct, well-labelled cases in the time one flaily run took.
#
# APT-Agent is UNMODIFIED — this is an external wrapper (same idea as capture.sh).
#
# Usage:
#   sudo -v                      # cache sudo (for tcpdump); run as your normal user
#   TARGET_IP=10.0.2.20 IFACE=eth0 ./run_batch.sh
#
# Env (all optional except TARGET_IP):
#   TARGET_IP  target (Metasploitable 2) IP           (required)
#   IFACE      capture interface facing target         (default eth0)
#   ATTACKER_IP                                          (default 10.0.2.10)
#   APT_AGENT_DIR                                         (default ~/APT-Agent_single_host-master)
#   VENV_PY    python with langchain/pymetasploit3      (default $APT_AGENT_DIR/.venv/bin/python)
#   LLM_MODEL                                             (default gpt-oss:120b-cloud)
#   PER_TIMEOUT   seconds per campaign                   (default 300)
#   TARGET_SSH_USER / TARGET_SSH_PASS                     (default msfadmin / msfadmin — the public default creds)
#   CLEAN_LOGS    truncate target logs before each run   (default 1; set 0 to keep baseline)
#   OUTBASE       batch output dir                        (default $APT_AGENT_DIR/batch_<ts>)
set -uo pipefail   # NOT -e: one failed campaign must not abort the batch

TARGET_IP="${TARGET_IP:?set TARGET_IP=<metasploitable ip>}"
IFACE="${IFACE:-eth0}"
ATTACKER_IP="${ATTACKER_IP:-10.0.2.10}"
APT_AGENT_DIR="${APT_AGENT_DIR:-$HOME/APT-Agent_single_host-master}"
VENV_PY="${VENV_PY:-$APT_AGENT_DIR/.venv/bin/python}"
LLM_MODEL="${LLM_MODEL:-gpt-oss:120b-cloud}"
PER_TIMEOUT="${PER_TIMEOUT:-300}"
TARGET_SSH_USER="${TARGET_SSH_USER:-msfadmin}"
TARGET_SSH_PASS="${TARGET_SSH_PASS:-msfadmin}"
CLEAN_LOGS="${CLEAN_LOGS:-1}"
MSF_PASSWORD="${MSF_PASSWORD:-password}"
MSF_PORT="${MSF_PORT:-55553}"
RESET_MSF="${RESET_MSF:-1}"          # restart msfrpcd between campaigns (frees :8080 handler)
OUTBASE="${OUTBASE:-$APT_AGENT_DIR/batch_$(date -u +%Y%m%d_%H%M%S)}"

# preflight: refuse to run with an unfilled .env (the LOCAL_IP=<attacker-ip> trap)
if grep -qE '^(LOCAL_IP|TARGET_IP)=<' "$APT_AGENT_DIR/.env" 2>/dev/null; then
    echo "[FATAL] $APT_AGENT_DIR/.env still has placeholder <...> values — fix LOCAL_IP/TARGET_IP first."
    exit 1
fi

# Legacy SSH bundle — Metasploitable's OpenSSH 4.7 only speaks old algorithms.
SSH_OPTS="-o StrictHostKeyChecking=accept-new -o HostKeyAlgorithms=+ssh-rsa -o PubkeyAcceptedAlgorithms=+ssh-rsa -o KexAlgorithms=+diffie-hellman-group1-sha1 -o Ciphers=+aes128-cbc"

# --- service playbook: label | TARGET_SERVICE | TARGET_PORT | TARGET_VERSION -------
# EDIT to match APT-Agent's accepted TARGET_SERVICE tokens (check with:
#   grep -n TARGET_SERVICE ~/APT-Agent_single_host-master/APT-Agent.py ).
# vsftpd is the known-good one from the README; the rest are best-effort — verify.
SERVICES=(
  "vsftpd_backdoor|ftp|21|vsftpd 2.3.4"
  "proftpd_backdoor|ftp|2121|ProFTPD 1.3.1"
  "samba_usermap|samba|445|Samba 3.0.20"
  "unreal_ircd|irc|6667|UnrealIRCd 3.2.8.1"
  "postgres_payload|postgres|5432|PostgreSQL 8.3"
)

command -v sshpass >/dev/null 2>&1 || { echo "[!] install sshpass:  sudo apt install -y sshpass"; exit 1; }
mkdir -p "$OUTBASE"
echo "[*] batch dir: $OUTBASE   ($(( ${#SERVICES[@]} )) campaigns, ${PER_TIMEOUT}s each)"

sshx() { sshpass -p "$TARGET_SSH_PASS" ssh $SSH_OPTS "$TARGET_SSH_USER@$TARGET_IP" "$@"; }
scpx() { sshpass -p "$TARGET_SSH_PASS" scp -O $SSH_OPTS "$TARGET_SSH_USER@$TARGET_IP:$1" "$2"; }

for entry in "${SERVICES[@]}"; do
    IFS='|' read -r LABEL SVC PORT VER <<<"$entry"
    RUN="$OUTBASE/$LABEL"
    mkdir -p "$RUN/captured" "$RUN/zeek" "$RUN/pcap"
    echo
    echo "==================================================================="
    echo "[*] campaign: $LABEL   ($SVC:$PORT  $VER)"

    # 0. fresh Metasploit state so a prior campaign's handler doesn't hold :8080
    if [ "$RESET_MSF" = "1" ]; then
        echo "[*] restarting msfrpcd for a clean handler state ..."
        pkill -f msfrpcd 2>/dev/null; sleep 3
        # -f keeps it in the foreground of THIS backgrounded subshell (& returns control)
        msfrpcd -P "$MSF_PASSWORD" -p "$MSF_PORT" -S false -f >/tmp/msfrpcd.log 2>&1 &
        for i in $(seq 1 45); do          # wait up to 90s for the RPC port to listen
            ss -tln 2>/dev/null | grep -q ":$MSF_PORT " && break
            sleep 2
        done
        if ss -tln 2>/dev/null | grep -q ":$MSF_PORT "; then
            echo "    msfrpcd listening on $MSF_PORT"
        else
            echo "    [!] msfrpcd not up after 90s (see /tmp/msfrpcd.log) — continuing anyway"
        fi
    fi

    # 0.5 clear APT-Agent's OWN output logs so this campaign's log isn't polluted
    #     by previous campaigns (APT-Agent appends to these files).
    rm -f "$APT_AGENT_DIR"/APT-Agent_experiment_log.txt \
          "$APT_AGENT_DIR"/APT-Agent_experiment_commands.txt \
          "$APT_AGENT_DIR"/failed_modules_log.txt \
          "$APT_AGENT_DIR"/exfil_command_history.txt 2>/dev/null

    # 1. clean the target's logs so the case has no pre-attack baseline noise
    if [ "$CLEAN_LOGS" = "1" ]; then
        echo "[*] clearing target auth.log/syslog for a clean capture ..."
        # Metasploitable sudo wants a password on stdin; empty the files (needs root).
        sshx "echo '$TARGET_SSH_PASS' | sudo -S sh -c 'cat /dev/null >/var/log/auth.log; cat /dev/null >/var/log/syslog'" \
            >/dev/null 2>&1
        remain=$(sshx "wc -l < /var/log/auth.log" 2>/dev/null | tr -d ' ')
        echo "    auth.log now ~${remain:-?} lines (want ~0)"
    fi

    # 2. start capture
    START="$(date -u +%Y-%m-%dT%H:%M:%SZ)"; echo "$START" > "$RUN/CAMPAIGN_START"
    sudo tcpdump -i "$IFACE" -w "$RUN/pcap/campaign.pcap" "host $TARGET_IP" >/dev/null 2>&1 &
    TCPDUMP_PID=$!
    sleep 2

    # 3. run ONE service-locked campaign, hard-timed
    echo "[*] running APT-Agent (locked to $SVC, timeout ${PER_TIMEOUT}s) ..."
    ( cd "$APT_AGENT_DIR" && \
      TARGET_SERVICE="$SVC" TARGET_PORT="$PORT" TARGET_VERSION="$VER" LLM_MODEL="$LLM_MODEL" \
      timeout "$PER_TIMEOUT" "$VENV_PY" APT-Agent.py ) > "$RUN/apt_agent_run.stdout" 2>&1
    echo "[*] campaign ended (exit/timeout)."

    # 4. stop capture
    sudo kill "$TCPDUMP_PID" 2>/dev/null || true
    sleep 1

    # 5. pull the target's real logs + APT-Agent's log
    scpx /var/log/auth.log "$RUN/captured/auth.log" 2>/dev/null || echo "[!] auth.log pull failed"
    scpx /var/log/syslog   "$RUN/captured/syslog"   2>/dev/null || echo "[!] syslog pull failed"
    cp "$APT_AGENT_DIR/APT-Agent_experiment_log.txt" "$RUN/" 2>/dev/null || echo "[!] no experiment log"

    # 6. zeek over the pcap (native -> docker -> skip)
    if command -v zeek >/dev/null 2>&1; then
        ( cd "$RUN/zeek" && zeek -C -r "$RUN/pcap/campaign.pcap" ) 2>/dev/null || true
    elif command -v docker >/dev/null 2>&1; then
        docker run --rm -v "$RUN":/data -w /data/zeek zeek/zeek zeek -C -r /data/pcap/campaign.pcap 2>/dev/null || true
    fi

    fails=$(grep -c "Failed password" "$RUN/captured/auth.log" 2>/dev/null || echo 0)
    accs=$(grep -c "Accepted password" "$RUN/captured/auth.log" 2>/dev/null || echo 0)
    echo "[+] $LABEL done  (auth.log: $fails failed / $accs accepted, start $START)"
done

echo
echo "[+] BATCH COMPLETE -> $OUTBASE"
echo "    Copy it to the Mac, then run package_batch.sh there:"
echo "      scp -r attacker@$ATTACKER_IP:$OUTBASE  <repo root>/captures/"
echo "    (or from the Mac: scp -r attacker@<attacker-nat-ip>:$OUTBASE .../captures/)"
