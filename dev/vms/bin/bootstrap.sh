#!/usr/bin/env bash
# Bring up the 4-VM userspace_router dev topology.
#
# Usage:
#   bootstrap.sh                  # all 4 VMs + networks
#   bootstrap.sh upstream router  # subset (still defines networks)
#   bootstrap.sh --no-start       # define everything but don't `virsh start`
#
# Idempotent: re-running on an already-defined VM updates the qcow2 disk +
# seed ISO, refreshes the domain XML, and reboots only that VM.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VMS_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
BUILD_DIR="${VMS_DIR}/build"
CACHE_DIR="${VMS_DIR}/.cache"

UBUNTU_RELEASE="${UBUNTU_RELEASE:-noble}"  # 24.04 LTS — matches Dockerfile
UBUNTU_IMG_URL="https://cloud-images.ubuntu.com/${UBUNTU_RELEASE}/current/${UBUNTU_RELEASE}-server-cloudimg-amd64.img"
UBUNTU_BASE="${CACHE_DIR}/${UBUNTU_RELEASE}-server-cloudimg-amd64.qcow2"

ALL_VMS=(upstream router leaf1 leaf2)
NETWORKS=(ur-wan ur-lan1 ur-lan2)

source "${SCRIPT_DIR}/make-seed.sh"

# ---------------------------------------------------------------- helpers

log()    { printf '\033[1;34m[bootstrap]\033[0m %s\n' "$*"; }
warn()   { printf '\033[1;33m[bootstrap]\033[0m %s\n' "$*" >&2; }
die()    { printf '\033[1;31m[bootstrap]\033[0m %s\n' "$*" >&2; exit 1; }

require() {
  local missing=()
  for tool in "$@"; do
    command -v "$tool" >/dev/null 2>&1 || missing+=("$tool")
  done
  if (( ${#missing[@]} > 0 )); then
    die "missing required tools: ${missing[*]}"
  fi
}

# Build the SSH authorized_keys list to inject into cloud-init. Pulls every
# *.pub the user has lying around; falls back to "(empty)" so YAML stays
# valid even if no keys are present.
ssh_keys_block() {
  local keys=()
  shopt -s nullglob
  for f in "$HOME"/.ssh/*.pub; do
    [[ -f "$f" ]] && keys+=("$(<"$f")")
  done
  shopt -u nullglob
  if (( ${#keys[@]} == 0 )); then
    printf '""'
    return
  fi
  # Emit as a YAML inline-array. cloud-init accepts both inline and block
  # form for ssh_authorized_keys.
  local out="" sep=""
  for k in "${keys[@]}"; do
    # Escape any embedded quotes (paranoid; pubkeys shouldn't contain them).
    k=${k//\"/\\\"}
    out+="${sep}\"${k}\""
    sep=", "
  done
  printf '%s' "$out"
}

# Substitute placeholders ${DISK}, ${SEED}, __SSH_AUTHORIZED_KEYS__ into a
# template, writing to stdout.
render() {
  local tmpl=$1 disk=$2 seed=$3 keys=$4
  sed \
    -e "s|\${DISK}|${disk}|g" \
    -e "s|\${SEED}|${seed}|g" \
    -e "s|__SSH_AUTHORIZED_KEYS__|${keys}|g" \
    "$tmpl"
}

# ---------------------------------------------------------------- prereqs

require virsh qemu-img curl

[[ -d "$BUILD_DIR" ]] || mkdir -p "$BUILD_DIR"
[[ -d "$CACHE_DIR" ]] || mkdir -p "$CACHE_DIR"

# Make sure the libvirt default network is up — that's our management LAN.
if ! virsh net-info default >/dev/null 2>&1; then
  die "libvirt 'default' network missing; create one or start libvirtd"
fi
if [[ "$(virsh net-info default | awk '/^Active:/ {print $2}')" != "yes" ]]; then
  log "starting libvirt default network"
  virsh net-start default
fi

# ---------------------------------------------------------------- args

START_VMS=true
declare -a TARGETS=()
for arg in "$@"; do
  case "$arg" in
    --no-start) START_VMS=false ;;
    -h|--help)
      sed -n '2,/^set -e/p' "$0" | sed 's/^# \{0,1\}//'
      exit 0
      ;;
    upstream|router|leaf1|leaf2) TARGETS+=("$arg") ;;
    *) die "unknown arg: $arg" ;;
  esac
done
[[ ${#TARGETS[@]} -eq 0 ]] && TARGETS=("${ALL_VMS[@]}")

# ---------------------------------------------------------------- base img

if [[ ! -f "$UBUNTU_BASE" ]]; then
  log "downloading Ubuntu ${UBUNTU_RELEASE} cloud image (~600 MB)"
  curl -fL --progress-bar -o "${UBUNTU_BASE}.tmp" "$UBUNTU_IMG_URL"
  mv "${UBUNTU_BASE}.tmp" "$UBUNTU_BASE"
else
  log "base image cached: $UBUNTU_BASE"
fi

# ---------------------------------------------------------------- networks

for net in "${NETWORKS[@]}"; do
  if virsh net-info "$net" >/dev/null 2>&1; then
    log "network $net already defined"
  else
    log "defining network $net"
    virsh net-define "${VMS_DIR}/networks/${net}.xml" >/dev/null
  fi
  # Autostart so a host reboot doesn't break the topology.
  virsh net-autostart "$net" >/dev/null 2>&1 || true
  if [[ "$(virsh net-info "$net" | awk '/^Active:/ {print $2}')" != "yes" ]]; then
    log "starting network $net"
    virsh net-start "$net" >/dev/null
  fi
done

# ---------------------------------------------------------------- per-VM

KEYS=$(ssh_keys_block)
if [[ "$KEYS" == '""' ]]; then
  warn "no SSH pubkeys under ~/.ssh/*.pub — password 'ubuntu' is the only way in"
fi

for vm in "${TARGETS[@]}"; do
  name="ur-${vm}"
  vm_dir="${VMS_DIR}/${vm}"
  disk="${BUILD_DIR}/${name}.qcow2"
  seed_dir="${BUILD_DIR}/${name}-seed"
  seed_iso="${BUILD_DIR}/${name}-seed.iso"
  domain_xml="${BUILD_DIR}/${name}.xml"

  log "=== $name ==="

  # Disk: thin qcow2 over the Ubuntu base. Re-creating is cheap if we want a
  # fresh boot; we only do it on first run to preserve installed packages
  # across re-bootstraps.
  if [[ ! -f "$disk" ]]; then
    log "  creating disk $disk (20 GiB, backed by base)"
    qemu-img create -q -f qcow2 -F qcow2 -b "$UBUNTU_BASE" "$disk" 20G
  fi

  # Seed dir + ISO, regenerated every run so cloud-init edits stick.
  rm -rf "$seed_dir" && mkdir -p "$seed_dir"
  # Inject SSH keys into user-data.
  sed "s|__SSH_AUTHORIZED_KEYS__|${KEYS}|g" \
    "${vm_dir}/user-data" > "${seed_dir}/user-data"
  cp "${vm_dir}/meta-data" "${seed_dir}/meta-data"
  log "  building seed ISO"
  make_seed_iso "$seed_dir" "$seed_iso"

  # Domain XML
  render "${vm_dir}/domain.xml.tmpl" "$disk" "$seed_iso" "$KEYS" > "$domain_xml"

  # Define or redefine. Live VMs get their config refreshed without a destroy.
  if virsh dominfo "$name" >/dev/null 2>&1; then
    log "  refreshing domain definition"
    virsh define "$domain_xml" >/dev/null
  else
    log "  defining new domain"
    virsh define "$domain_xml" >/dev/null
  fi

  if $START_VMS; then
    state=$(virsh domstate "$name" 2>/dev/null || echo missing)
    case "$state" in
      "running")
        log "  $name already running"
        ;;
      *)
        log "  starting $name"
        virsh start "$name" >/dev/null
        ;;
    esac
  fi
done

# ---------------------------------------------------------------- summary

log ""
log "Topology defined. To check status:"
log "  ${SCRIPT_DIR}/status.sh"
log ""
log "First boot runs cloud-init (~1-2 min); SSH may not work until that completes."
log "Once a VM is up you can:"
log "  virsh console ur-router        # serial console"
log "  ssh ubuntu@<mgmt-ip>           # status.sh shows IPs"
log "  ssh ubuntu@ur-router.local     # if mdns works on your host"
