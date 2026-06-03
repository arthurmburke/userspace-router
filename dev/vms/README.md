# Router dev VMs

Four-VM development topology for `userspace_router`:

```
                  10.213.202.0/27                      172.16.172.0/24
   ┌──────────┐  ┌─────────────┐  ┌─────────────┐  ┌──────────┐
   │ upstream │──│  ur-wan net │──│             │  │ ur-lan1  │──┐
   │ (dnsmasq)│  │  (isolated) │  │             │──│   net    │  │ ┌────────┐
   └──────────┘  └─────────────┘  │   router    │  └──────────┘  └─│ leaf1  │
                                  │ (DPDK x3)   │                  └────────┘
                                  │             │  ┌──────────┐  ┌────────┐
                                  │             │──│ ur-lan2  │──│ leaf2  │
                                  └─────────────┘  │   net    │  └────────┘
                                                   └──────────┘
```

- **upstream**: runs `dnsmasq` as the WAN DHCP / DNS server. Static `10.213.202.1/27`.
  Hands out leases from `10.213.202.10 → .30`.
- **router**: 1 WAN + 2 LAN virtio-net NICs bound to `vfio-pci`. Pre-provisioned
  with `libdpdk-dev`, Rust, and your `Dockerfile` package list. WAN gets DHCP'd
  from upstream; the LAN ports are bridged into a single broadcast domain by
  the router's FDB and served by its built-in DHCP server.
- **leaf1 / leaf2**: kernel netplan DHCP clients on their LAN interface; should
  land in `172.16.172.100 → .200`. One on each physical LAN port — useful for
  exercising the FDB's intra-bridge forwarding and the conntrack firewall.

Every VM also has a management NIC on libvirt's `default` NAT network, so you
can `ssh ubuntu@<vm>.local` (mDNS) or via IP from the host.

## Files

```
dev/vms/
├── README.md
├── bin/
│   ├── bootstrap.sh           # one-shot: define networks + domains, start everything
│   ├── destroy.sh             # virsh destroy + undefine + wipe build/
│   ├── status.sh              # quick `virsh list` + IP summary
│   └── make-seed.sh           # NoCloud ISO builder (called from bootstrap)
├── networks/
│   ├── ur-wan.xml             # isolated L2 — no DHCP, no NAT
│   ├── ur-lan1.xml
│   └── ur-lan2.xml
├── upstream/
│   ├── domain.xml.tmpl        # `${DISK}` / `${SEED}` filled by bootstrap
│   ├── user-data              # cloud-init: install dnsmasq + static IP
│   └── meta-data
├── router/
│   ├── domain.xml.tmpl
│   ├── user-data              # cloud-init: install DPDK build deps + Rust
│   ├── meta-data
│   ├── router.conf            # copied into router VM at /opt/router/router.conf
│   └── bind-dpdk.sh           # copied into router VM; binds NICs to vfio-pci
├── leaf1/, leaf2/
│   ├── domain.xml.tmpl
│   ├── user-data              # cloud-init: netplan DHCP on the LAN NIC
│   └── meta-data
├── build/                     # rendered XMLs, per-VM qcow2 disks, seed ISOs
└── .cache/                    # downloaded Ubuntu base image
```

## Where to run libvirtd

**Heads-up for macOS users.** These artifacts use libvirt's `<network>` element
with isolated Linux bridges, which has no native macOS equivalent. You have
three options:

1. **Linux host (recommended).** Any Linux box with `libvirt-daemon-system`,
   `qemu-system-x86`, `virtinst`. Clone the repo, run `dev/vms/bin/bootstrap.sh`,
   done. Cloud, dedicated dev box, or a beefy local VM.

2. **`colima` or a UTM Linux VM as a libvirt host.** Spin up one Linux VM with
   nested KVM enabled, install libvirt inside it, then run these scripts inside
   that VM. The nested 4 VMs are slower but functional for control-plane work.
   With UTM, enable "Use Hypervisor" + give the Linux VM access to KVM.

3. **Remote libvirt over SSH from macOS.** Install `libvirt-client` on macOS
   (`brew install libvirt`), point `LIBVIRT_DEFAULT_URI=qemu+ssh://you@linuxbox/system`,
   and run the scripts from your Mac. The actual VMs run on the Linux host.

The XMLs themselves are portable — they don't pin a hypervisor URI.

## Prerequisites on the libvirt host

```bash
# Ubuntu / Debian
sudo apt install -y qemu-system-x86 libvirt-daemon-system libvirt-clients \
                    virtinst xorriso curl
sudo usermod -aG libvirt $USER && newgrp libvirt

# Fedora / RHEL
sudo dnf install -y qemu-kvm libvirt virt-install xorriso curl
sudo systemctl enable --now libvirtd

# macOS (only useful for the SSH-to-Linux variant above)
brew install libvirt qemu xorriso
```

The bootstrap script auto-detects `xorriso`, `genisoimage`, `mkisofs`, or
macOS's built-in `hdiutil` to build NoCloud seed ISOs.

## Bringing it up

```bash
cd dev/vms
./bin/bootstrap.sh           # whole topology
./bin/bootstrap.sh upstream  # just one VM (idempotent re-run)
./bin/status.sh              # show VM IPs + ssh hints
./bin/destroy.sh             # rip it all down (asks for confirmation)
```

The first run downloads the Ubuntu 24.04 cloud image (~600 MB) into
`.cache/` and reuses it for every VM (qcow2 backing files keep per-VM disk
overhead to the delta from base).

The default user is `ubuntu`. If `~/.ssh/id_ed25519.pub` or `~/.ssh/id_rsa.pub`
exists at bootstrap time it gets baked into `authorized_keys`; the fallback
password is `ubuntu` (change it).

## Running the router

Once the four VMs are up:

```bash
# From the libvirt host
ssh ubuntu@<router-mgmt-ip>          # status.sh prints the IPs

# Inside the router VM
sudo /opt/router/bind-dpdk.sh        # hugepages + vfio-pci bind for the 3 NICs
git clone https://github.com/<you>/quicktcp ~/quicktcp   # or scp/9p in
cd ~/quicktcp
cargo build --release --features dpdk
sudo CONFIG_FILE=/opt/router/router.conf \
    ./target/release/userspace_router \
    -l 0,1 -n 1 \
    -a 0000:00:03.0 -a 0000:00:04.0 -a 0000:00:05.0
```

The PCI BDFs are pinned by the domain XML so they're stable across reboots:

| Slot | Network    | Role | DPDK name      |
|------|------------|------|----------------|
| 0x02 | `default`  | mgmt | (kernel, eth0) |
| 0x03 | `ur-wan`   | WAN  | `0000:00:03.0` |
| 0x04 | `ur-lan1`  | LAN  | `0000:00:04.0` |
| 0x05 | `ur-lan2`  | LAN  | `0000:00:05.0` |

`/opt/router/router.conf` is pre-populated with matching `[[interfaces]]`
stanzas. `bind-dpdk.sh` is idempotent and prints what changed.

## Validating the topology

From inside `leaf1` (after DHCP):

```bash
ip -4 addr show enp0s3                       # 172.16.172.<x>/24
ip route                                      # default via 172.16.172.1
ping -c 3 172.16.172.1                       # router LAN gateway
ping -c 3 10.213.202.1                       # routed via NAT through the router
ssh ubuntu@172.16.172.<leaf2-ip>             # intra-LAN, hits the FDB
```

From `upstream` you should see the router's DHCP lease in
`/var/log/syslog` (look for `DHCPACK on 10.213.202.<x>`).

## Tearing down

```bash
./bin/destroy.sh              # asks before removing disks
./bin/destroy.sh --force --wipe-cache    # also blows away the base image
```
