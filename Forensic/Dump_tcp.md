# Dump_tcp — PCAP Forensics Challenge Writeup

## Challenge Info

- **Category:** Network Forensics / Packet Capture Analysis
- **File:** `combined_capture.pcap`
- **Goal:** Analyze the provided packet capture, identify the malicious activity, and recover the flag.
- **Flag:** `flag:93`

## Tools Used

- `tshark` (Wireshark CLI) — installed via `apt-get install tshark`
- `python3` — for decoding the binary payload

## Analysis

### 1. Initial Triage

The capture is small (22 frames, ~2.2 KB) with mostly TCP handshake noise. A protocol hierarchy check narrowed things down fast:

```bash
tshark -r capture.pcap -q -z io,phs
```

This revealed only **three TCP streams**, two of which carried actual payload data:

| Stream | Ports | Protocol | Notes |
|--------|-------|----------|-------|
| 0 | 40328 → 8080 (IPv6, `::1`) | TCP | SYN immediately RST'd — decoy/noise, no data |
| 1 | 36396 → 8080 | HTTP | Full GET/response exchange |
| 2 | 39788 → 9090 | Raw TCP | Single data-bearing packet |

### 2. Following the Streams

```bash
tshark -r capture.pcap -q -z follow,tcp,ascii,1   # Stream 1 (port 8080)
tshark -r capture.pcap -q -z follow,tcp,ascii,2   # Stream 2 (port 9090)
```

**Stream 1 (port 8080) — the decoy:**

```
GET / HTTP/1.1
Host: localhost:8080
User-Agent: curl/8.8.0
Accept: */*

HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.12.6
Date: Mon, 07 Oct 2024 20:33:16 GMT
Content-type: text/html

<html><body><h1>Hello, CTF Time!</h1></body></html>
```

Just a plain `curl` request to a Python `SimpleHTTPServer` returning a harmless greeting. Red herring — no useful data.

**Stream 2 (port 9090) — the payload:**

```
Hidden flag: 01100110 01101100 01100001 01100111 01111011 01100110 01101100 01100001 01100111 00111010 00111001 00110011 01111101
```

This is a single TCP segment carrying a plaintext label followed by a space-delimited binary string — 13 groups of 8 bits, i.e. 13 ASCII characters.

### 3. Decoding the Flag

Each 8-bit group was converted from binary to its ASCII character:

```python
s = "01100110 01101100 01100001 01100111 01111011 01100110 01101100 01100001 01100111 00111010 00111001 00110011 01111101"
decoded = ''.join(chr(int(g, 2)) for g in s.split())
print(decoded)
```

**Output:**

```
flag{flag:93}
```

### 4. Submission Note

The lab's judge expected only the *inner content* of the braces, not the full `flag{...}` wrapper. The accepted flag was:

```
flag:93
```

## Summary

- The capture contained one decoy HTTP exchange (port 8080) designed to look like normal/benign traffic.
- The actual exfiltrated/hidden data was sent as plaintext-labeled binary over a raw TCP stream on port 9090.
- Decoding the binary (ASCII, 8 bits/char) revealed the flag.

**Flag:** `flag:93`
