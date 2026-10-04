# ezpz — Reversing / Binary Exploitation Writeup

**Category:** Reversing / Machine Control
**Difficulty:** Hard (300 pts)
**Flag:** `ctf{m4k!ng_cu5t0m_vM_f0r_l!c3nc3_ch3cK!ing_!s_qU!t3_c0mm0N}`

## Challenge

> A simple Linux executable accepts user input, but a small programming mistake
> has introduced a vulnerability that can be abused. Analyze the binary,
> identify the flaw, and exploit it to reveal the hidden flag.

## Binary Overview

```
$ file ezpz
ezpz: ELF 64-bit LSB pie executable, x86-64, dynamically linked, not stripped

Protections:
  RELRO:      Partial RELRO
  Stack:      No canary found
  NX:         NX enabled
  PIE:        PIE enabled
```

`main()` doesn't do much itself — it constructs a `VM` object from a fixed
256-byte bytecode program embedded in `.data` at `0xa120`, then calls
`VM::execute()`. So the real logic to reverse is a tiny **custom bytecode
interpreter**, not `main()` directly.

## Reversing the VM

### Object layout

```
VM {
    std::stack<uint8_t> operand_stack;   // 0x00
    std::vector<uint16_t> program;       // 0x50
    iterator pc;                         // 0x68
    uint8_t* memory;                     // 0x70  (heap, new uint8_t[0x100])
}
```

### Opcode dispatch

`VM::execute_instruction(uint16_t)` splits each fetched 16-bit instruction
into a **low byte (opcode)** and **high byte (operand)**, then jumps through
a table. Recovering the jump table targets gives:

| opcode | mnemonic      | meaning                                   |
|-------:|---------------|--------------------------------------------|
| 0      | `exit`        | exit(code)                                 |
| 1      | `push`        | push immediate byte onto operand stack     |
| 2      | `pop`         | pop and discard                            |
| 3      | `jmp`         | unconditional jump                         |
| 4      | `read_memory` | pop addr/size, `read(fd, memory+addr, sz)` |
| 5      | `write_memory`| pop addr/size, `write(fd, memory+addr, sz)`|
| 6      | `stm`         | store top-of-stack → `memory[addr]`        |
| 7      | `ldm`         | load `memory[addr]` → stack                |
| 8      | `jne`         | pop two, jump if not equal                 |
| 9      | `xr`          | xor                                        |
| 10     | `add`         | add                                        |
| 11     | `open_file`   | open() a path built in `memory`            |
| 12     | `jl`          | jump if less                               |
| 13     | `jg`          | jump if greater                            |
| 14     | `je`          | jump if equal                              |

### Decoded program logic

Walking the embedded bytecode instruction-by-instruction:

1. Write `"Enter password: "` (16 bytes at `memory[0..15]`) to fd 1 (stdout).
2. `read_memory(fd=0)` — read up to 16 bytes of stdin into `memory[128..143]`.
3. Compare `memory[128..135]` byte-by-byte (`ldm` + `push` + `jne`) against
   the literal constants:

   ```
   'L' 'a' 'm' 'O' 't' '9' 'F' 'h'
   ```

   i.e. the hardcoded password is **`LamOt9Fh`**. Any mismatch jumps to the
   `"Incorrect:"` branch and `exit(1)`.
4. If the password matches: print `"Correct: "`, `open_file("/flag")`,
   `read_memory(fd=3)` up to 32 bytes into `memory[0..31]`, then
   `write_memory(fd=1)` the actual number of bytes read — printing the flag
   contents straight to stdout — then `exit(0)`.

So the "vulnerability" here isn't memory corruption at all in the intended
path — the program is effectively a **license-check-style VM** whose secret
comparison value can be fully recovered by static analysis, since the
password bytes are compiled directly into the bytecode as `push` immediates.
Reversing the interpreter is the whole challenge.

### A real (secondary) bug

`read_memory` / `write_memory` pop an address `A` and size `B` off the
operand stack and are meant to clamp `A + B` to the 256-byte `memory`
buffer. The clamp is implemented as:

```c
if (A + B > 0xff)
    B = ~A - B;   // buggy: should be B = 0xff - A
```

Because this is done in 8-bit arithmetic, `~A - B` can **underflow and wrap
around** instead of producing a safe remaining-space value, allowing an
oversized `B` and a heap buffer over-read/overflow on the `memory` array.
This is a genuine memory-corruption primitive, but it isn't needed to solve
the challenge as shipped — the password path is reachable and sufficient on
its own.

## Exploitation / Solve

No runtime exploitation was actually required — just reverse the embedded
bytecode to recover the hardcoded password, then connect and supply it:

```
$ nc <host> <port>
Enter password: LamOt9Fh
Correct: ctf{m4k!ng_cu5t0m_vM_f0r_l!c3nc3_ch3cK!ing_!s_qU!t3_c0mm0N}
```

## Flag

```
ctf{m4k!ng_cu5t0m_vM_f0r_l!c3nc3_ch3cK!ing_!s_qU!t3_c0mm0N}
```

## Tools Used

- `objdump -d -M intel` for disassembly
- `pwntools` (`ELF`, `checksec`) for binary triage
- Manual jump-table resolution to recover VM opcode semantics
- Manual bytecode decoding (Python) to recover the embedded program
