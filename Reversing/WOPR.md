# WOPR — Reverse Engineering Writeup

## Challenge

A 64-bit ELF executable (`chall`) recovered from an "abandoned development
environment." It's statically linked and stripped of section headers, which
makes it look unusual to standard tools (`readelf`/`objdump` report it as a
`DYN` "shared object" with zero sections). Goal: recover the input that
satisfies its hidden verification routine and get the flag.

## 1. Initial triage

```
$ file chall
chall: ELF 64-bit LSB shared object, x86-64, version 1 (SYSV),
       statically linked, no section header

$ ./chall < /dev/null
LOGON: ACCESS DENIED.
DEFCON STATUS: MAINTAINED.
```

`readelf -h` confirms there are 0 section headers and only 3 program
headers (two `LOAD` segments + `GNU_STACK`). `objdump -d chall` finds
nothing to disassemble because it relies on section headers by default.

## 2. It's UPX-packed

Even though the section headers are gone, `strings` on the raw file still
turns up UPX's identification strings:

```
$ strings -a chall | grep -i upx
UPX!
$Info: This file is packed with the UPX executable packer http://upx.sf.net $
$Id: UPX 4.24 Copyright (C) 1996-2024 the UPX Team. All Rights Reserved. $
```

The "statically linked, no section headers" appearance is just a side
effect of UPX's stub — the real (dynamically linked, glibc-using) binary is
compressed inside. Disassembling the entry point manually (dumping the raw
bytes and feeding them to `objdump -D -b binary -m i386:x86-64`) shows the
classic UPX/NRV decompression stub: a small bit-unpacking loop that calls
through a function pointer (`call *%r11`) to pull compressed bytes apart
before jumping into the real program.

Rather than manually unrolling the stub, just ask UPX to undo its own work:

```
$ upx -d chall -o chall_unpacked
        File size         Ratio      Format      Name
   --------------------   ------   -----------   -----------
     22007 <-      6808   30.94%   linux/amd64   chall_unpacked
```

This produces a normal, section-header-intact, dynamically linked ELF that
`objdump`/`readelf` handle without any tricks.

## 3. Decoy flag

A quick string scan of the unpacked binary is a trap for the impatient:

```
$ strings -a chall_unpacked | grep flag
flag{1s_th1s_4_r34l_fl4g?!}
```

This string sits in plain `.rodata` and looks exactly like a CTF flag. It
is **not** the answer — see below.

## 4. Reversing `main()`

Disassembling `.text` (`objdump -d chall_unpacked`) reveals the program
flow:

1. **Anti-debug check** (`ptrace(PTRACE_TRACEME, 0, 1, 0)`) — exits
   immediately if the process is already being traced.
2. **Read input**: `scanf("%63s", buf)` into a stack buffer.
3. **Decoy comparison** — the input is passed through a transform:
   ```
   out[i] = (in[i] ^ 0x13) - 7
   ```
   and the result is `strcmp`'d against the literal string
   `flag{1s_th1s_4_r34l_fl4g?!}`.
   **If this matches, the program actually reports failure** (prints the
   "SHALL WE PLAY A GAME?" flavor text and then falls through to return
   0 / ACCESS DENIED). This is a deliberate anti-cheat trap for anyone who
   just greps the binary for `flag{`.
4. **Real comparison** — a second transform is applied to the raw input:
   ```
   out[i] = (in[i] ^ 0x42) + 5
   ```
   and compared via `strcmp` against a 25-byte buffer that is built
   directly on the stack out of four `movabs` immediate loads (never
   stored as a normal string constant, so it doesn't show up under
   `strings`).
5. **On a correct match**, the program takes that *same* embedded buffer
   and decodes it with the inverse transform:
   ```
   out[i] = (buf[i] - 5) ^ 0x42
   ```
   then prints the result character-by-character (with a `usleep` between
   each character, for the WarGames-style teletype effect) as
   "THE WOPR HAS A MESSAGE."

## 5. Recovering the password / flag

Both the required *password* and the *real flag* come from the same
embedded stack buffer, transformed by:

```
plaintext[i] = (encoded[i] - 5) ^ 0x42
```

Extracting the raw bytes from the four `movabs` instructions and applying
this transform in Python:

```python
buf = b')3(*>5v9v56x1*"x6"{1"{5;D'   # bytes taken from the movabs immediates

def transform(b):
    return bytes(((c - 5) & 0xff) ^ 0x42 for c in b)

print(transform(buf).decode())
```

```
flag{r3v3rs1ng_1s_4n_4rt}
```

## 6. Verification

```
$ echo "flag{r3v3rs1ng_1s_4n_4rt}" | ./chall
LOGON: GREETINGS PROFESSOR FALKEN.
THE WOPR HAS A MESSAGE:

flag{r3v3rs1ng_1s_4n_4rt}
```

Confirmed against both the UPX-unpacked binary and the original packed
`chall` executable (UPX's stub transparently decompresses it at runtime,
so the packed binary behaves identically).

## Flag

```
flag{r3v3rs1ng_1s_4n_4rt}
```

## Key takeaways

- "No section headers" doesn't mean "no structure" — packers like UPX
  strip/rewrite headers as part of obfuscation, but leave enough of their
  own signature (`UPX!`) to detect and reverse with the stock `upx -d`.
- Never trust a flag-shaped string found via `strings` at face value in a
  reversing challenge — check whether it's actually consumed as a
  correct-path constant or used as a decoy/anti-cheat trip wire.
- Stack-built strings (via chained `movabs` immediates instead of a
  `.rodata` reference) are a simple way to hide constants from static
  string scanners; extracting bytes straight from the instruction operands
  defeats this easily.
