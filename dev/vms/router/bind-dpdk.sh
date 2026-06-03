#!/usr/bin/env bash
# Reference copy of /opt/router/bind-dpdk.sh — the real file is written into
# the router VM by cloud-init (see router/user-data). Kept here for diffing.
set -euo pipefail
log() { printf '[bind-dpdk] %s\n' "$*"; }

want=512
have=$(cat /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages)
if [[ "$have" -lt "$want" ]]; then
  log "allocating $want 2 MiB hugepages (had $have)"
  echo "$want" > /sys/kernel/mm/hugepages/hugepages-2048kB/nr_hugepages
else
  log "hugepages already at $have (>= $want)"
fi
mountpoint -q /dev/hugepages || {
  mkdir -p /dev/hugepages
  mount -t hugetlbfs nodev /dev/hugepages
}

modprobe vfio-pci
echo 1 > /sys/module/vfio/parameters/enable_unsafe_noiommu_mode

DEVS=(0000:00:03.0 0000:00:04.0 0000:00:05.0)
for d in "${DEVS[@]}"; do
  drv=$(basename "$(readlink /sys/bus/pci/devices/$d/driver 2>/dev/null || echo none)")
  if [[ "$drv" == "vfio-pci" ]]; then
    log "$d already bound to vfio-pci"
    continue
  fi
  log "binding $d to vfio-pci (was: $drv)"
  dpdk-devbind.py --bind=vfio-pci "$d"
done

log "status:"
dpdk-devbind.py --status-dev=net | sed -n '/Network devices/,/^$/p'
