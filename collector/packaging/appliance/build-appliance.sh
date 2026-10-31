#!/bin/sh
# Builds the VM appliance (qcow2 + OVA) from the official Debian 12 cloud image with libguestfs (virt-customize).
# Run on a Debian/Ubuntu build host:  sudo apt install libguestfs-tools qemu-utils; ./build-appliance.sh
set -eu
cd "$(dirname "$0")"
../build-deb.sh >/dev/null
DEB=$(ls -t ../../dist/guardian-collector_*_all.deb | head -1)
IMG=debian-12-genericcloud-amd64.qcow2
[ -f "$IMG" ] || wget -q "https://cloud.debian.org/images/cloud/bookworm/latest/$IMG"
cp "$IMG" guardian-collector.qcow2
qemu-img resize guardian-collector.qcow2 8G
virt-customize -a guardian-collector.qcow2 \
  --install python3,python3-venv,nmap,openssh-client,unattended-upgrades \
  --copy-in "$DEB":/root/ --run-command 'dpkg -i /root/guardian-collector_*_all.deb && rm /root/guardian-collector_*_all.deb' \
  --copy-in firstboot-enroll.sh:/usr/local/sbin/ --run-command 'chmod 755 /usr/local/sbin/firstboot-enroll.sh' \
  --run-command 'printf "%s\n" "[ -f /var/lib/guardian-collector/state.json ] || sudo /usr/local/sbin/firstboot-enroll.sh" >> /etc/skel/.profile' \
  --hostname guardian-collector --timezone Europe/Zurich
qemu-img convert -O vmdk guardian-collector.qcow2 guardian-collector.vmdk
echo "Built guardian-collector.qcow2 (Proxmox/KVM) and guardian-collector.vmdk (VMware); wrap the VMDK into an OVA with ovftool if needed."
