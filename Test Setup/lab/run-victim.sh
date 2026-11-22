#!/usr/bin/env bash
# run-victim.sh NAME   — boot a victim VM with plain QEMU (no UTM GUI).
# Network: vmnet-shared (needs sudo), so all victims + a Kali on UTM "Shared" land on the
# same 192.168.64.0/24 and can reach each other. Internet is available (for apt on first
# boot); isolate during an attack run by dropping the default route inside the guest.
#
#   sudo ./run-victim.sh web01
#
# Console is this terminal. Quit the VM with: Ctrl-A then X.
set -euo pipefail

NAME="${1:?usage: sudo ./run-victim.sh NAME}"
DIR="victims/$NAME"
CODE="/opt/homebrew/share/qemu/edk2-aarch64-code.fd"
VARS_TMPL="/opt/homebrew/share/qemu/edk2-arm-vars.fd"

[ -f "$DIR/disk.qcow2" ] || { echo "no $DIR/disk.qcow2 — run ./make-victim.sh $NAME <role> <kali-ip> first"; exit 1; }
# per-VM writable UEFI variable store (persists boot order etc.)
[ -f "$DIR/efi-vars.fd" ] || cp "$VARS_TMPL" "$DIR/efi-vars.fd"

# NOTE: do not set a per-VM mac= here. The burned-in snapshot's cloud-init netplan is pinned
# to the default QEMU MAC (52:54:00:12:34:56); changing the MAC makes the netplan match fail
# and the NIC comes up DOWN (no DHCP, no IP). vmnet-shared gives stable leases in practice
# despite the shared MAC, so the default is fine.
exec qemu-system-aarch64 \
  -machine virt -accel hvf -cpu host -smp 2 -m 768 \
  -drive if=pflash,format=raw,readonly=on,file="$CODE" \
  -drive if=pflash,format=raw,file="$DIR/efi-vars.fd" \
  -drive if=virtio,format=qcow2,file="$DIR/disk.qcow2" \
  -drive if=virtio,format=raw,file="$DIR/seed.iso" \
  -netdev vmnet-shared,id=net0 -device virtio-net-pci,netdev=net0 \
  -nographic
