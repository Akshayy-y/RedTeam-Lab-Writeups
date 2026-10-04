# CTF: Strings — Writeup

**Category:** Reversing
**Difficulty:** Easy
**Points:** 100

## Challenge Description

> A suspicious Linux executable has been recovered from a compromised system. At first glance, it appears to perform complex operations, but not every binary requires deep reverse engineering to uncover its secrets. Your task is to inspect the executable, identify any useful information embedded within it, and recover the hidden flag. Sometimes the simplest analysis techniques are all that's needed.

## Files Provided

- `strings` — a Linux ELF 64-bit executable (x86-64, dynamically linked, not stripped)

## Steps

### 1. Identify the file

```bash
file strings
```

Output confirmed it was a standard, **not stripped** ELF binary — meaning symbol names (like function/variable names) were still intact, which makes static analysis much easier.

### 2. Run `strings` on the binary

```bash
strings -n 6 strings | grep -iE "flag|CTF"
```

This immediately surfaced a suspicious line:

```
Congratulations here is your flag:
```

along with references to `/flag` and a symbol named `flag` — a strong hint that the binary reads a flag file when some condition is met.

### 3. Try running the binary

```bash
./strings
```

It prompted:

```
Enter password:
```

Entering garbage returned `Wrong password`, confirming there's a password check gating the flag.

### 4. Disassemble to understand the logic

```bash
objdump -d -M intel strings > dis.txt
```

Looking at `main()`, the logic was:

1. Print `Enter password:` and read input with `scanf("%99s", ...)`
2. Compare it via `strncmp()` against a hardcoded buffer at a fixed address (labeled `flag` in the symbol table)
3. If it matches → `open("/flag")` followed by `sendfile()` to dump the file's contents straight to stdout, prefixed with `Congratulations here is your flag:`
4. If it doesn't match → print `Wrong password`

### 5. Dump the `.data` section to recover the hardcoded password

```bash
objdump -s -j .data strings
```

This revealed the ASCII bytes of the hardcoded comparison string sitting right there in the binary's data section:

```
sup3r_s3cr3t_sup3r_s3cur3_p4ssw0rd_f0r_th3_b!n4ry
```

### 6. Verify locally

Created a fake `/flag` file and ran the binary with the recovered password to confirm the success path triggers the `sendfile()` read:

```bash
echo "CTF{fake_flag_for_testing}" > /flag
echo "sup3r_s3cr3t_sup3r_s3cur3_p4ssw0rd_f0r_th3_b!n4ry" | ./strings
```

This correctly printed the fake flag, confirming the password and mechanism.

### 7. Connect to the remote challenge instance

The actual `/flag` file lives on the remote challenge host, not in the downloaded binary. Connected via `netcat`:

```bash
nc 172.31.13.45 32427
```

Supplied the recovered password when prompted:

```
Enter password: sup3r_s3cr3t_sup3r_s3cur3_p4ssw0rd_f0r_th3_b!n4ry
```

## Flag

```
ctf{alw4ys_ch3ck_str!ngs_in_4_b!n4ry}
```

## Takeaway

The binary wasn't stripped and stored its "secret" password in plaintext inside the `.data` section. Running `strings`/`objdump` on the binary — without ever needing to step through it in a debugger — was enough to fully recover the password and understand the program's control flow. As the flag itself hints: **always check strings in a binary** before reaching for heavier reverse-engineering tools.
