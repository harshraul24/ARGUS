#!/usr/bin/env bash
# benign.sh ROLE [DURATION_MIN]     DURATION_MIN=0 runs forever (for the persona service)
# Env: PEERS="ip ip ..." enables the inter-host look-alikes; LAB_PASS=... enables the
#      password-SSH look-alikes via sshpass.
#
# Emits the LAB_TEST_SUITE.md §4.3 benign LOOK-ALIKES for this role — legitimate actions that
# resemble an attack technique — each timestamped and labelled to ~/benign-activity.log so the
# benign (false-alarm) windows have their own ground truth. Ordinary user work only; the
# scheduled root maintenance look-alikes (logrotate, auditd restart) run from cron, not here.
#
# Start it session-separated from any login (so no process is an ancestor of both persona and
# the CALDERA agent — S1 / §4.2):
#   sudo systemd-run --unit=benign --uid="$USER" --setenv=PEERS="a b" --setenv=LAB_PASS=<lab-password> \
#        /home/$USER/benign.sh <role> 0
set -u

ROLE="${1:-app}"; DUR="${2:-25}"
LOG="$HOME/benign-activity.log"
read -r -a PEERS <<< "${PEERS:-}"
log(){ echo "$(date -u +%FT%TZ) benign ROLE=$ROLE $*" >> "$LOG"; }
has(){ command -v "$1" >/dev/null 2>&1; }
mkdir -p "$HOME/work"

# --- the look-alikes (each resembles a technique, each is legitimate) ---
survey(){ uname -a >/dev/null; id >/dev/null; ip a >/dev/null 2>&1; ss -tuln >/dev/null 2>&1
          ps aux >/dev/null; df -h >/dev/null; log "lookalike=discovery survey (uname,id,ip,ss,ps,df)"; }

peer_ssh(){ [ "${#PEERS[@]}" -gt 0 ] || return 0; local p="${PEERS[$((RANDOM % ${#PEERS[@]}))]}"
  if has sshpass && [ -n "${LAB_PASS:-}" ]; then
    sshpass -p "$LAB_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$USER@$p" \
      'hostname; uptime; ls' >/dev/null 2>&1 && log "lookalike=lateral peer-ssh real task -> $p"
  else
    ssh -o BatchMode=yes -o ConnectTimeout=5 "$USER@$p" 'hostname' >/dev/null 2>&1 \
      && log "lookalike=lateral peer-ssh(key) -> $p"
  fi; }

mistyped_login(){ has sshpass || return 0; local p="${PEERS[0]:-127.0.0.1}"
  sshpass -p "wrong$RANDOM" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$USER@$p" true >/dev/null 2>&1
  [ -n "${LAB_PASS:-}" ] && sshpass -p "$LAB_PASS" ssh -o StrictHostKeyChecking=no -o ConnectTimeout=5 "$USER@$p" true >/dev/null 2>&1
  log "lookalike=bruteforce mistyped-then-success -> $p"; }

archive(){ mkdir -p "$HOME/stage"; printf 'data %s\n' "$RANDOM" > "$HOME/stage/report.txt"
  cp /etc/hostname "$HOME/stage/" 2>/dev/null
  # tar a SMALL fixed staging dir into ONE reused file OUTSIDE it (no compounding growth).
  tar czf "$HOME/loot.tgz" -C "$HOME" stage >/dev/null 2>&1
  log "lookalike=staging tar staged folder"; }

upload(){ [ "${#PEERS[@]}" -gt 0 ] || return 0; local p="${PEERS[0]}" f="$HOME/loot.tgz"
  [ -f "$f" ] || return 0
  if has sshpass && [ -n "${LAB_PASS:-}" ]; then
    sshpass -p "$LAB_PASS" scp -o StrictHostKeyChecking=no "$f" "$USER@$p:/tmp/" >/dev/null 2>&1 \
      && log "lookalike=exfil upload archive -> $p"
  fi; }

download(){ [ "${#PEERS[@]}" -gt 0 ] || return 0; local p="${PEERS[0]}"
  curl -s -o /dev/null "http://$p/" 2>/dev/null; log "lookalike=ingress download from lab host $p"; }

histclear(){ : > "$HOME/.bash_history" 2>/dev/null; history -c 2>/dev/null || true
  log "lookalike=defense-evasion user cleared own shell history"; }

portprobe(){ for port in 22 80 443 3306 5432; do
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && exec 3>&- 3<&- ; done
  log "lookalike=portscan local service health check"; }

work(){ case "$ROLE" in
  web) curl -s http://localhost/ >/dev/null 2>&1; echo "hit $(date -u)" >> "$HOME/work/access.log"; log "work=web serve";;
  dev) ( cd "$HOME/work"; git init -q 2>/dev/null; echo "l$RANDOM" >> src.py
         git add -A 2>/dev/null; git -c user.email=d@lab -c user.name=dev commit -qm "wip $RANDOM" 2>/dev/null ); log "work=dev git";;
  fin) printf 'row,%s\n' "$RANDOM" >> "$HOME/work/ledger.csv"; log "work=fin ledger";;
  hr)  printf 'record,%s\n' "$RANDOM" >> "$HOME/work/people.txt"; log "work=hr records";;
  *)   cp /etc/hostname "$HOME/work/host.bak" 2>/dev/null; log "work=app file";;
 esac; }

# role -> its look-alike repertoire (per §4.3)
case "$ROLE" in
  web) ACTIONS=(survey work download portprobe);;
  app) ACTIONS=(survey work peer_ssh);;
  dev) ACTIONS=(survey work peer_ssh archive histclear);;
  fin) ACTIONS=(survey work mistyped_login archive upload);;
  hr)  ACTIONS=(survey work mistyped_login);;
  *)   ACTIONS=(survey work);;
esac

log "START dur=${DUR}m peers=${PEERS[*]:-none} actions=${ACTIONS[*]}"
END=$(( $(date +%s) + DUR * 60 )); i=0
while [ "$DUR" -eq 0 ] || [ "$(date +%s)" -lt "$END" ]; do
  survey                                   # every host does admin survey
  "${ACTIONS[$(( i % ${#ACTIONS[@]} ))]}"  # plus a rotating role look-alike
  i=$(( i + 1 )); sleep $(( (RANDOM % 40) + 20 ))
done
log "END ($i iterations)"
echo "benign run done — $i iterations, log at $LOG"
