#!/usr/bin/env bash
# Tear down the userspace_router dev topology.
#
# Usage:
#   destroy.sh                    # asks before nuking each VM + disks
#   destroy.sh --force            # no prompts; keeps the base image cache
#   destroy.sh --force --wipe-cache  # also remove the Ubuntu base download
#   destroy.sh upstream router    # subset
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VMS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${VMS_DIR}/build"
CACHE_DIR="${VMS_DIR}/.cache"

ALL_VMS=(upstream router leaf1 leaf2)
NETWORKS=(ur-wan ur-lan1 ur-lan2)

log()  { printf '\033[1;34m[destroy]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[destroy]\033[0m %s\n' "$*" >&2; }

FORCE=false
WIPE_CACHE=false
declare -a TARGETS=()
for arg in "$@"; do
  case "$arg" in
    -f|--force) FORCE=true ;;
    --wipe-cache) WIPE_CACHE=true ;;
    -h|--help)
      sed -n '2,/^set -e/p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    upstream|router|leaf1|leaf2) TARGETS+=("$arg") ;;
    *) echo "unknown arg: $arg" >&2; exit 1 ;;
  esac
done
[[ ${#TARGETS[@]} -eq 0 ]] && TARGETS=("${ALL_VMS[@]}")

confirm() {
  $FORCE && return 0
  read -r -p "$1 [y/N] " ans
  [[ "$ans" =~ ^[Yy]$ ]]
}

for vm in "${TARGETS[@]}"; do
  name="ur-${vm}"
  if virsh dominfo "$name" >/dev/null 2>&1; then
    if confirm "destroy + undefine $name?"; then
      state=$(virsh domstate "$name" 2>/dev/null || echo missing)
      if [[ "$state" == "running" ]]; then
        log "destroying $name"
        virsh destroy "$name" >/dev/null
      fi
      log "undefining $name"
      virsh undefine "$name" --remove-all-storage --managed-save >/dev/null \
        || virsh undefine "$name" >/dev/null
      rm -f "${BUILD_DIR}/${name}.qcow2"
      rm -f "${BUILD_DIR}/${name}-seed.iso"
      rm -rf "${BUILD_DIR}/${name}-seed"
      rm -f "${BUILD_DIR}/${name}.xml"
    fi
  else
    log "$name not defined; skipping"
  fi
done

# Only remove networks if we're taking everything down.
if [[ ${#TARGETS[@]} -eq ${#ALL_VMS[@]} ]]; then
  for net in "${NETWORKS[@]}"; do
    if virsh net-info "$net" >/dev/null 2>&1; then
      if confirm "destroy network $net?"; then
        state=$(virsh net-info "$net" | awk '/^Active:/ {print $2}')
        [[ "$state" == "yes" ]] && virsh net-destroy "$net" >/dev/null
        virsh net-undefine "$net" >/dev/null
      fi
    fi
  done
fi

if $WIPE_CACHE; then
  if confirm "wipe cache ($CACHE_DIR)?"; then
    rm -rf "$CACHE_DIR"
  fi
fi

# Clean up empty build/ if everything's gone.
rmdir "$BUILD_DIR" 2>/dev/null || true

log "done."
