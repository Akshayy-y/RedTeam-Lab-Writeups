# keygen_me — Reverse Engineering Writeup

**Category:** Reversing
**Difficulty:** Medium
**Points:** 200
**Flag:** `ctf{z3_f0r_l!f3}`

## Challenge

A Linux ELF binary (`keygen_me`) prompts for a registration key. If the key
passes internal validation, the program reads and prints out a `flag` file
sitting next to it via `sendfile()`. Brute force is infeasible — the key
must be derived by understanding the validation constraints.

## Static Analysis

```
file keygen_me
# ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped
```

Being unstripped, symbol names (`main`, `check`) are preserved, which made
disassembly with `objdump -d -M intel` straightforward.

### `main()`

```c
printf("Enter key: ");
n = read(0, buf, 0xff);      // read raw key from stdin
buf[n - 1] = 0;               // overwrite trailing '\n' with NUL
if (check(buf, n - 1)) {      // n-1 = key length, NUL not included
    puts("Congrats here is your flag: ");
    fd = open("./flag", O_RDONLY);
    sendfile(1, fd, NULL, 0x100);
} else {
    puts("Invalid key");
}
```

So the length passed to `check()` is the number of key characters typed
(newline stripped).

### `check(char *key, size_t len)`

**1. Character range check** — every byte of the key must satisfy:

```
0x30 <= key[i] <= 0x7a      // '0'-'9', ':;<=>?@', 'A'-'Z', '[\]^_`', 'a'-'z'
```

Any byte outside this range immediately fails.

**2. A chain of 10 arithmetic/bitwise constraints** on individual key-byte
positions (0-indexed), each of which must hold exactly, otherwise the
function returns `0`:

| # | Constraint                              | Target (hex) | Target (dec) |
|---|------------------------------------------|---------------|---------------|
| 1 | `key[0] + key[3]`                        | `0x72`        | 114 |
| 2 | `key[1] + key[18]`                       | `0xd6`        | 214 |
| 3 | `key[2] + key[4]`                        | `0xb2`        | 178 |
| 4 | `key[5] ^ key[6]`                        | `0x4c`        | 76  |
| 5 | `key[8] - key[7]`                        | `0x11`        | 17  |
| 6 | `key[10] - key[9]`                       | `0x3b`        | 59  |
| 7 | `(key[11] + key[12]) - key[13]`          | `0x47`        | 71  |
| 8 | `(key[14] + key[15]) - key[16]`          | `0x1f`        | 31  |
| 9 | `(key[17] + key[16]) - key[18]`          | `0x58`        | 88  |
| 10| `key[19] ^ key[20] ^ key[21]`            | `0x43`        | 67  |

Since position `21` is accessed, the key must be **at least 22 characters
long**.

## Solving

This is an under-determined linear/XOR system (22 unknowns, 10 equations),
so many valid keys exist — any assignment satisfying the constraints and
the `0x30`–`0x7a` byte-range restriction works. One valid solution was
picked by hand, working equation by equation and choosing byte values that
stay in-range:

```python
key = "Bnk0Gy5M^0kAB<CDhXhAB@"
k = [ord(c) for c in key]

assert all(0x30 <= c <= 0x7a for c in k)
assert k[0] + k[3]              == 0x72
assert k[1] + k[18]             == 0xd6
assert k[2] + k[4]              == 0xb2
assert k[5] ^ k[6]              == 0x4c
assert k[8] - k[7]              == 0x11
assert k[10] - k[9]             == 0x3b
assert (k[11] + k[12]) - k[13]  == 0x47
assert (k[14] + k[15]) - k[16]  == 0x1f
assert (k[17] + k[16]) - k[18]  == 0x58
assert k[19] ^ k[20] ^ k[21]    == 0x43
```

All constraints hold — no bruteforce needed, just solving 10 small
equations by substitution.

## Getting the Flag

Note: `read()` is a raw syscall (no line buffering), so the trailing
newline sent by your shell becomes the byte that `main()` overwrites with
`\0`. The key must therefore be sent **with** a trailing newline so the
actual last key character isn't clobbered:

```bash
printf 'Bnk0Gy5M^0kAB<CDhXhAB@\n' | nc <host> <port>
```

**Result:**

```
Enter key: Congrats here is your flag: ctf{z3_f0r_l!f3}
```

## Tools Used

- `objdump -d -M intel` — disassembly (binary was unstripped, so symbols
  like `main` and `check` were directly visible)
- `python3` — solving/verifying the constraint system
- Local execution of the binary to validate the derived key before hitting
  the remote server
