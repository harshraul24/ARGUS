#!/bin/bash
# Double-click to boot a lab victim (asks which; app01 by default). The victims' virtual
# network needs administrator rights, so macOS asks for your Mac password here.
# This window becomes the victim's console: leave it open. To shut the victim down, log in
# and run `sudo poweroff`, or press Ctrl-A then X.
cd "$(dirname "$0")/Test Setup/lab" || exit 1
names=$(ls victims 2>/dev/null | tr '\n' ' ')
read -r -p "Victim to boot [ $names] (Enter = app01): " v
v=${v:-app01}
if [ ! -f "victims/$v/disk.qcow2" ]; then
  echo "No victim named '$v'."; read -r -n1 -p "Press any key to close." _; exit 1
fi
if pgrep -f "victims/$v/disk.qcow2" >/dev/null; then
  echo "$v is already running."; read -r -n1 -p "Press any key to close." _; exit 0
fi
echo "Booting $v. Enter your Mac password if asked. It takes about a minute to come up."
exec sudo ./run-victim.sh "$v"
