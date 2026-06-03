#!/usr/bin/env bash
# Build a NoCloud cloud-init seed ISO for one VM. Sourced by bootstrap.sh.
#
# Args:
#   $1 — source dir containing user-data + meta-data
#   $2 — destination ISO path
#
# Picks the first available ISO-9660 builder: xorriso, genisoimage, mkisofs,
# or macOS's built-in hdiutil. NoCloud requires volume label "cidata".
set -euo pipefail

make_seed_iso() {
  local seed_dir=$1
  local out_iso=$2

  if [[ ! -f "$seed_dir/user-data" || ! -f "$seed_dir/meta-data" ]]; then
    echo "make-seed: $seed_dir is missing user-data or meta-data" >&2
    return 1
  fi

  rm -f "$out_iso"

  if command -v xorriso >/dev/null 2>&1; then
    xorriso -as mkisofs -quiet \
      -output "$out_iso" \
      -volid cidata \
      -joliet -rock \
      "$seed_dir"
  elif command -v genisoimage >/dev/null 2>&1; then
    genisoimage -quiet -output "$out_iso" -volid cidata -joliet -rock "$seed_dir"
  elif command -v mkisofs >/dev/null 2>&1; then
    mkisofs -quiet -output "$out_iso" -volid cidata -joliet -rock "$seed_dir"
  elif command -v hdiutil >/dev/null 2>&1; then
    # macOS fallback. -default-volume-name sets the ISO9660 label.
    hdiutil makehybrid -quiet -o "$out_iso" -iso -joliet \
      -default-volume-name cidata "$seed_dir" >/dev/null
  else
    echo "make-seed: install xorriso / genisoimage / mkisofs (Linux) or use hdiutil (macOS)" >&2
    return 1
  fi
}

# If invoked directly (not sourced), expose as a one-shot.
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
  [[ $# -eq 2 ]] || { echo "usage: $0 <seed_dir> <out_iso>" >&2; exit 1; }
  make_seed_iso "$1" "$2"
fi
