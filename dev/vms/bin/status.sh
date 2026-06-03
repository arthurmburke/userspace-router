#!/usr/bin/env bash
# Quick status for the userspace_router dev topology.
#
# Shows for each VM:
#   - libvirt state (running / shut off / missing)
#   - management interface IP (libvirt default network)
#   - hostname (mDNS via avahi if available)
set -euo pipefail

ALL_VMS=(upstream router leaf1 leaf2)
NETWORKS=(ur-wan ur-lan1 ur-lan2)

bold()  { printf '\033[1m%s\033[0m' "$*"; }
green() { printf '\033[32m%s\033[0m' "$*"; }
red()   { printf '\033[31m%s\033[0m' "$*"; }
yellow(){ printf '\033[33m%s\033[0m' "$*"; }

# Try to resolve a VM's mgmt IP via libvirt's default network DHCP leases.
mgmt_ip() {
  local name=$1
  # `virsh net-dhcp-leases default` is the canonical way once cloud-init
  # has finished and the lease landed.
  virsh net-dhcp-leases default 2>/dev/null \
    | awk -v n="$name" '$0 ~ n {print $5}' \
    | head -n1 \
    | cut -d/ -f1
}

# `virsh domifaddr` is a fallback that uses the qemu-guest-agent or
# falls back to ARP. Useful when the lease database isn't populated yet.
fallback_ip() {
  local name=$1
  virsh domifaddr "$name" --source=arp 2>/dev/null \
    | awk '/ipv4/ {print $4}' \
    | cut -d/ -f1 \
    | grep -v '^192.168.122.' >/dev/null \
    && return
  # Take the first ipv4 we see.
  virsh domifaddr "$name" --source=arp 2>/dev/null \
    | awk '/ipv4/ {print $4}' \
    | cut -d/ -f1 \
    | head -n1
}

echo "$(bold "Networks")"
for net in "${NETWORKS[@]}"; do
  if virsh net-info "$net" >/dev/null 2>&1; then
    state=$(virsh net-info "$net" | awk '/^Active:/ {print $2}')
    if [[ "$state" == "yes" ]]; then
      printf "  %-12s %s\n" "$net" "$(green up)"
    else
      printf "  %-12s %s\n" "$net" "$(yellow defined-but-inactive)"
    fi
  else
    printf "  %-12s %s\n" "$net" "$(red missing)"
  fi
done

echo
echo "$(bold "VMs")"
printf "  %-12s %-12s %-18s %s\n" "name" "state" "mgmt ip" "hint"
printf "  %-12s %-12s %-18s %s\n" "----" "-----" "-------" "----"
for vm in "${ALL_VMS[@]}"; do
  name="ur-${vm}"
  if ! virsh dominfo "$name" >/dev/null 2>&1; then
    printf "  %-12s %-12s %-18s %s\n" "$name" "$(red missing)" "-" "-"
    continue
  fi
  state=$(virsh domstate "$name")
  ip=$(mgmt_ip "$name" || true)
  [[ -z "$ip" ]] && ip=$(fallback_ip "$name" || true)
  [[ -z "$ip" ]] && ip="(pending)"

  hint=""
  case "$vm" in
    upstream) hint="dnsmasq @ 10.213.202.1/27" ;;
    router)   hint="DPDK pre-provisioned; ssh in, run bind-dpdk.sh" ;;
    leaf1)    hint="DHCPs from router on ur-lan1" ;;
    leaf2)    hint="DHCPs from router on ur-lan2" ;;
  esac

  if [[ "$state" == "running" ]]; then
    state_disp=$(green "$state")
  elif [[ "$state" == "shut off" ]]; then
    state_disp=$(yellow "$state")
  else
    state_disp=$(red "$state")
  fi

  printf "  %-12s %-21s %-18s %s\n" "$name" "$state_disp" "$ip" "$hint"
done

cat <<'EOF'

SSH:
  ssh ubuntu@<mgmt-ip>            password: ubuntu (or your ssh pubkey)
  virsh console ur-<vm>           serial; Ctrl-] to exit

Bring up DPDK on the router:
  ssh ubuntu@<router-ip> -- 'sudo /opt/router/bind-dpdk.sh'

Check that DHCP leases landed:
  ssh ubuntu@<upstream-ip> -- 'sudo journalctl -u dnsmasq -e --no-pager | grep DHCPACK'
EOF
