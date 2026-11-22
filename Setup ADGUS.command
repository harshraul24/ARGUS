#!/bin/bash
# Double-click once (on a new Mac, or after moving the folder): creates ADGUS's Python
# environment, installs what it needs, and checks the lab is in place. Safe to run again.
cd "$(dirname "$0")" || exit 1
pause() { echo; read -r -n1 -p "Press any key to close this window." _; echo; }

echo "== ADGUS setup =="
PY=""
for c in python3.14 python3.13 python3.12 python3.11 python3; do
  p=$(command -v "$c" 2>/dev/null) || continue
  "$p" -c 'import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)' 2>/dev/null && { PY=$p; break; }
done
[ -n "$PY" ] || { echo "Python 3.11 or newer is needed:  brew install python"; pause; exit 1; }
echo "[1/4] Python: $PY ($("$PY" --version 2>&1))"

if [ ! -x .venv/bin/python ] || ! .venv/bin/python -c 'pass' 2>/dev/null; then
  echo "[2/4] creating the environment (.venv) ..."
  rm -rf .venv && "$PY" -m venv .venv || { echo "could not create .venv"; pause; exit 1; }
else
  echo "[2/4] environment (.venv) already exists"
fi

echo "[3/4] installing requirements ..."
.venv/bin/python -m pip install -q --upgrade pip && .venv/bin/python -m pip install -q -r requirements.txt \
  || { echo "installing requirements failed (internet needed for this step)"; pause; exit 1; }
( cd "source code" && ../.venv/bin/python -c "import argus.api.app, argus.live.loop" ) \
  && echo "      ADGUS loads" || { echo "ADGUS does not load: see the error above"; pause; exit 1; }

echo "[4/4] lab check:"
command -v qemu-system-aarch64 >/dev/null && echo "      QEMU found" \
  || echo "      QEMU not found: brew install qemu   (only needed to boot victims)"
for v in "Test Setup/lab/victims"/*/; do
  n=$(basename "$v"); [ -f "$v/disk.qcow2" ] && echo "      victim $n: disk present" || echo "      victim $n: NO disk"
done

echo
echo "Done. To run a live demo:"
echo "  1. double-click 'Boot Victim.command'        (boots app01 by default)"
echo "  2. double-click 'Start Live Triage.command'  (opens the workbench and decides live)"
pause
