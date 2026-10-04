# Superid — Linux Privilege Escalation Writeup

**Category:** Linux Escalation
**Difficulty:** Easy
**Points:** 100
**Target:** `172.31.45.248:30163`

## Summary

Gained SSH access as a low-privileged user with a provided ECDSA key, enumerated the box, and found a misconfigured SGID binary (`sed`, group `ctf`) that granted read access to a flag file owned by group `ctf`.

## 1. Initial Access

Provided credentials:
- Username: `user`
- Private key: `id_ecdsa` (ECDSA OpenSSH key)

```bash
chmod 600 id_ecdsa
ssh -i id_ecdsa -p 30163 user@172.31.45.248
```

Landed on Ubuntu 20.04.1 LTS, running inside what turned out to be a Kubernetes pod (hostname pattern `ctf-akshay-superid-*`, presence of `/run/secrets/kubernetes.io/serviceaccount`).

## 2. Enumeration

Key findings from manual enumeration and `linpeas.sh`:

- `sudo` not installed, no cron jobs of interest, no writable root-owned files.
- `/etc/passwd` revealed a second user, `ctf` (uid 1001), home directory `/home/ctf`.
- `/home/ctf/flag` existed with permissions `-r-----r--` owned by `root:ctf` — readable only by root or members of group `ctf`.
- Current user (`user`) was **not** a member of group `ctf` and had no direct way to read the file.
- SGID binary list turned up the vulnerability:
  ```
  -rwxr-sr-x. 1 root ctf 119K Dec 22  2018 /usr/bin/sed
  ```
  `/usr/bin/sed` had the **setgid bit set with group `ctf`** — any user executing it runs with effective group `ctf`, regardless of their real group membership.

## 3. Exploitation

Because `sed` runs with effective GID `ctf`, it can open and read any file group-readable by `ctf` — including the flag:

```bash
sed -n '1p' /home/ctf/flag
```

Output:
```
ctf{su!d_b!n4r!es_4r3_b4d_f0r_s3cur!ty}
```

## 4. Root Cause

A non-essential utility (`sed`) was given the SGID bit for a privileged group (`ctf`) that owns sensitive data. Any user who can execute `sed` inherits that group's file-read privileges, completely bypassing the intended access control on `/home/ctf/flag`.

## 5. Remediation

- Remove the SGID bit from `/usr/bin/sed`: `chmod g-s /usr/bin/sed`.
- Audit all SGID/SUID binaries on the host (`find / -perm -2000 -o -perm -4000 -type f 2>/dev/null`) and remove unnecessary privilege bits.
- Never rely on file permissions alone to protect secrets that untrusted local users can read via commonly-installed, group-privileged utilities.

## Flag

```
ctf{su!d_b!n4r!es_4r3_b4d_f0r_s3cur!ty}
```
