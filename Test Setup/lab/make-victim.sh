#!/usr/bin/env bash
# make-victim.sh NAME ROLE KALI_IP   (ROLE: web|app|dev|fin)
# Run on the Mac from this lab folder, e.g.:  ./make-victim.sh web01 web 192.168.66.5
# Produces victims/NAME/disk.qcow2 (self-contained) + seed.iso (cloud-init).
set -euo pipefail

NAME="${1:?usage: make-victim.sh NAME ROLE KALI_IP}"
ROLE="${2:-app}"
KALI="${3:?usage: make-victim.sh NAME ROLE KALI_IP   KALI_IP is Kali host-only IP}"
BASE="$PWD/debian-12-genericcloud-arm64.qcow2"
# The victims' login password: choose your own and export it before running this script.
LAB_PASSWORD="${LAB_PASSWORD:?export LAB_PASSWORD=<the victims' login password> first}"

[ -f "$BASE" ] || { echo "base image not found: $BASE  (download it first)"; exit 1; }
# Refuse to overwrite a disk that a running VM has open (qemu holds a qcow2 lock).
if [ -f "victims/$NAME/disk.qcow2" ] && ! qemu-img info "victims/$NAME/disk.qcow2" >/dev/null 2>&1; then
  echo "ERROR: victims/$NAME/disk.qcow2 is in use — shut that VM down first (focus its terminal, Ctrl-A then X)."
  exit 1
fi
mkdir -p "victims/$NAME"

# Self-contained disk: a full copy of the base grown to 12G. NOT a CoW overlay, because
# UTM is sandboxed and cannot read a backing file outside its container. qcow2 stays thin
# on disk; cloud-init/growpart expand the filesystem to 12G on first boot.
cp "$BASE" "victims/$NAME/disk.qcow2"
qemu-img resize "victims/$NAME/disk.qcow2" 12G

case "$ROLE" in
  web) PKGS="nginx sqlite3";               VUSER=www;;
  app) PKGS="openssh-server rsync";        VUSER=svc;;
  dev) PKGS="git python3 build-essential"; VUSER=bob;;
  fin) PKGS="libreoffice-calc";            VUSER=alice;;
  hr)  PKGS="mutt";                        VUSER=carol;;
  *)   PKGS="vim";                         VUSER=user;;
esac

cat > "victims/$NAME/meta-data" <<EOF
instance-id: $NAME
local-hostname: $NAME
EOF

# DHCP by default (the cloud image built-in config). No static IP or NIC name is hard-coded,
# so it works on UTM Host-Only or Shared with no interface-name mismatch. Find the address
# after boot with: ip a. chrony points time at Kali (the clock-skew lesson).
cat > "victims/$NAME/user-data" <<EOF
#cloud-config
hostname: $NAME
fqdn: $NAME.lab.local
users:
  - name: $VUSER
    groups: sudo
    shell: /bin/bash
    lock_passwd: false
    plain_text_passwd: $LAB_PASSWORD
ssh_pwauth: true
packages: [auditd, chrony, rsyslog, cron, sshpass, $PKGS]
write_files:
  # Sensors (LAB_EVAL_PLAN.md: the smoke test recorded process launches only, so ARGUS was
  # blind to network and file activity). Network connections, and writes to the files and
  # folders that hold accounts, privileges, scheduled jobs, services, SSH keys and the audit
  # configuration itself.
  - path: /etc/audit/rules.d/argus.rules
    content: |
      -i
      -a always,exit -F arch=b64 -S execve -k exec
      -a always,exit -F arch=b32 -S execve -k exec
      -a always,exit -F arch=b64 -S connect -k net
      -a always,exit -F arch=b32 -S connect -k net
      -w /etc/passwd -p wa -k identity
      -w /etc/shadow -p rwa -k identity
      -w /etc/group -p wa -k identity
      -w /etc/sudoers -p wa -k privilege
      -w /etc/sudoers.d/ -p wa -k privilege
      -w /etc/crontab -p wa -k schedule
      -w /etc/cron.d/ -p wa -k schedule
      -w /var/spool/cron/ -p wa -k schedule
      -w /etc/systemd/system/ -p wa -k service
      -w /root/.ssh/ -p rwa -k sshkeys
      -w /home/$VUSER/.ssh/ -p rwa -k sshkeys
      -w /etc/audit/ -p wa -k auditconfig
      -w /var/log/audit/ -p wa -k auditlog
  # Time (ws-fin01 ran 17.5 min behind in the smoke test): Kali is the only source, and the
  # clock is stepped whenever it is more than 1 s off, not only at boot.
  - path: /etc/chrony/sources.d/lab.sources
    content: "server $KALI iburst prefer\n"
  - path: /etc/chrony/conf.d/lab-step.conf
    content: "makestep 1 -1\n"
  # Forwarding (§3.3): ship every log line to Kali over TCP as it is written, so a log cleared
  # on the victim still survives on Kali — the second view for the two-views test (S10).
  - path: /etc/rsyslog.d/10-forward.conf
    content: |
      *.* @@$KALI:514
  # Scheduled maintenance look-alikes (§4.3, root/cron, independent of the persona): a log
  # rotation that truncates logs (resembles T1070.002) and a short auditd restart (resembles
  # sensor tampering). These give S11 / S6 their benign cases.
  - path: /etc/cron.d/lab-maint
    content: |
      */30 * * * * root /usr/sbin/logrotate -f /etc/logrotate.conf
      47 * * * * root systemctl restart auditd
runcmd:
  - [ bash, -lc, "augenrules --load || auditctl -R /etc/audit/rules.d/argus.rules || true" ]
  - [ bash, -lc, "for i in 1 2 3 4 5; do systemctl enable --now auditd && systemctl is-active --quiet auditd && break; sleep 5; done" ]
  - [ bash, -lc, "systemctl restart chrony || true" ]
  - [ bash, -lc, "systemctl enable --now rsyslog || true" ]
  - [ bash, -lc, "systemctl enable --now cron || true" ]
  # a record of the sensor and the clock at first boot, for the capture manifest
  - [ bash, -lc, "sleep 20; { date -u; auditctl -l; chronyc tracking; } > /var/log/argus-sensor-check.txt 2>&1 || true" ]
EOF

# macOS: volume MUST be named cidata for cloud-init NoCloud to find the seed
mkisofs -o "victims/$NAME/seed.iso" -V cidata -J -r \
  "victims/$NAME/user-data" "victims/$NAME/meta-data"

echo "built victims/$NAME  (role=$ROLE user=$VUSER, time to $KALI)"
