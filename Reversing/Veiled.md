# Veiled — Reverse Engineering Writeup

## Challenge

A stripped, statically-linked Linux ELF binary (`veiled`) prompts for a
"super-secret magic word" and prints a flag if the correct value is entered.

```
$ ./veiled
Enter the super-secret magic word:
Oops! Not even close. Try again, Sherlock!
```

## Recon

```
$ file veiled
veiled: ELF 64-bit LSB executable, x86-64, statically linked, stripped

$ strings -a veiled | grep -iE "secret|magic|flag|close|sherlock"
Enter the super-secret magic word:
Oops! Not even close. Try again, Sherlock!
Wow, you actually did it! Flag captured.
```

No symbols, but the prompt/success/failure strings give an anchor into the
disassembly.

## Locating the check

Static binary means no helpful symbol like `main`, so the strings were used
as a pivot. `objdump -d -Mintel veiled` was searched for references to the
string addresses (found via `strings -a -t x` giving the `.rodata` file
offset, converted to a virtual address using `.rodata`'s `Address`/`Offset`
from `readelf -S`).

```
lea rax, [rip+0x976d7]   # 0x499008  -> "Enter the super-secret magic word:"
lea rax, [rip+0x976df]   # 0x49902b  -> "%36s" (scanf format)
lea rax, [rip+0x9769e]   # 0x499030  -> "Oops! Not even close..."
lea rax, [rip+0x976a5]   # 0x499060  -> "Wow, you actually did it!..."
```

This pinpointed the validation routine at `0x4017b9`.

## The validation routine

1. Reads user input into a 37-byte stack buffer with `scanf`.
2. Fills a hard-coded array of 37 `int` constants directly on the stack,
   one `mov DWORD PTR [rbp-X], imm32` instruction per byte (no loop —
   the constants are baked into the code itself). First few bytes:
   `0x57, 0x40, 0x52, 0x6f, 0x70, 0x25, 0x70, 0x21, 0x76, ...`
3. Loops `i = 0 .. 36`, and for each byte checks:

   ```
   (input[i] XOR 0x14) == constant[i]
   ```

4. On the first mismatch it immediately prints the failure string and
   exits with status 1. If all 37 bytes match, it prints the success
   string and reveals the flag.

## Recovering the input

Since the comparison is a simple XOR, the required input byte is just:

```
input[i] = constant[i] XOR 0x14
```

```python
vals = [0x57,0x40,0x52,0x6f,0x70,0x25,0x70,0x21,0x76,0x2c,0x71,0x72,0x26,
        0x23,0x25,0x2c,0x2c,0x25,0x76,0x72,0x76,0x21,0x21,0x70,0x22,0x75,
        0x75,0x2d,0x25,0x75,0x76,0x23,0x72,0x2c,0x22,0x24,0x69]

flag = ''.join(chr(v ^ 0x14) for v in vals)
print(flag)
```

Output:

```
CTF{d1d5b8ef271881bfb55d6aa91ab7f860}
```

## Verification

```
$ echo "CTF{d1d5b8ef271881bfb55d6aa91ab7f860}" | ./veiled
Enter the super-secret magic word:Wow, you actually did it! Flag captured.
```

## Flag

```
CTF{d1d5b8ef271881bfb55d6aa91ab7f860}
```
