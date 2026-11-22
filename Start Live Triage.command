#!/bin/bash
# Double-click to start live triage in one step:
#   1. the log receiver (the victims stream their logs to it as they are written)
#   2. the workbench, opened in your browser on its Live page
#   3. ARGUS deciding each victim's activity as it arrives
# Boot at least one victim first ("Boot Victim.command"). Leave this window open; closing it
# (or Ctrl-C) stops everything. Each run's logs and decisions are kept under its name.
set -u
ADGUS="$(cd "$(dirname "$0")" && pwd)"
PY="$ADGUS/.venv/bin/python"
LAB="$ADGUS/Test Setup/lab"
PORT=8766
URL="http://127.0.0.1:$PORT"
pause() { echo; read -r -n1 -p "Press any key to close this window." _; echo; }

[ -x "$PY" ] || { echo "Run 'Setup ADGUS.command' first."; pause; exit 1; }
if curl -sf "$URL/workbench/live" >/dev/null 2>&1; then
  echo "The workbench is already running on port $PORT: close its window first."; pause; exit 1
fi

default="demo-$(date +%Y%m%d-%H%M)"
read -r -p "Name for this run (Enter = $default): " RUN
RUN=${RUN:-$default}
[[ "$RUN" =~ ^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$ ]] || { echo "Use letters, digits, dot, dash or underscore."; pause; exit 1; }

# 1. the Mac's address on the victims' network: it exists once a victim has booted
bind=""
for i in $(seq 1 72); do
  bind=$("$PY" -c "import sys; sys.path.insert(0, '$LAB'); import log_receiver as R; print(R.bridge_ip() or '')" 2>/dev/null)
  [ -n "$bind" ] && break
  [ "$i" = 1 ] && echo "Waiting for a victim's network (boot one with 'Boot Victim.command') ..."
  sleep 5
done
[ -n "$bind" ] || { echo "No victim network after 6 minutes. Is a victim running?"; pause; exit 1; }

mkdir -p "$LAB/captured/$RUN" "$ADGUS/live"
"$PY" "$LAB/log_receiver.py" "$RUN" --bind "$bind" > "$ADGUS/live/receiver-$RUN.log" 2>&1 &
RECV=$!
( cd "$ADGUS/source code" && exec "$PY" -m argus.cli ui --port "$PORT" --no-browser ) > "$ADGUS/live/workbench-$RUN.log" 2>&1 &
WB=$!

cleanup() {
  trap - EXIT INT TERM HUP
  echo; echo "Stopping ..."
  curl -s -X POST "$URL/workbench/live/stop" >/dev/null 2>&1
  kill "$RECV" "$WB" 2>/dev/null; wait 2>/dev/null
  echo "Stopped. Logs: Test Setup/lab/captured/$RUN/   Decisions: live/$RUN/"
}
trap cleanup EXIT INT TERM HUP

# 2. wait for the workbench, then 3. start deciding this run
for i in $(seq 1 60); do curl -sf "$URL/workbench/live" >/dev/null 2>&1 && break; sleep 1; done
if ! curl -sf -X POST -H 'Content-Type: application/json' -d "{\"run\": \"$RUN\"}" "$URL/workbench/live" >/dev/null; then
  echo "Could not start live triage: see live/workbench-$RUN.log"; pause; exit 1
fi
open "$URL/ui/"

echo
echo "Live triage is running on '$RUN'."
echo "  workbench:  $URL/ui/   (Live page)"
echo "  receiver:   $bind:10514   (victims send here; set up once per victim with forward-logs.sh)"
echo "  Close this window or press Ctrl-C to stop."
echo
tail -n 20 -f "$ADGUS/live/receiver-$RUN.log" &
TAIL=$!
wait "$RECV"
kill "$TAIL" 2>/dev/null
