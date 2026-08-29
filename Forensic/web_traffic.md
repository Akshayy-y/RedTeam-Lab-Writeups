# PacketCipher — Network Traffic Analysis

## Challenge

**Category:** Web Traffic / Network Forensics
**File:** `PacketCipher.pcapng`

> Security analysts intercepted a suspicious network capture during an investigation into encrypted communications between two compromised systems. While the packets themselves appear legitimate, hidden within the captured traffic is an encrypted message that holds the key to solving the incident.

**Goal:** Examine the network traffic, extract the concealed data, decrypt it if necessary, and retrieve the flag.

---

## Tools Used

- Python 3
- [Scapy](https://scapy.net/) — for parsing the `.pcapng` file and reconstructing TCP streams
- `base64` (CLI) — for decoding the final payload

---

## Analysis Walkthrough

### 1. Loading the capture

The capture contains **631 packets** using Linux "cooked capture" (`SLL`) framing. Breaking packets down by protocol stack:

| Count | Layers |
|-------|--------|
| 27  | ARP |
| 27  | ARP + Padding |
| 118 | IP → TCP → Raw (data-carrying TCP) |
| 19  | IP → TCP + Padding |
| 12  | IP → UDP → DNS |
| 12  | IP → ICMP → IP-in-ICMP → UDP-in-ICMP → DNS |
| 416 | IP → TCP (handshake/ACKs, no payload) |

### 2. Reconstructing TCP streams

TCP payload-carrying packets were grouped into **53 distinct streams** by (src IP, src port) / (dst IP, dst port) pairs, between hosts `192.168.1.9` and `192.168.1.17`.

Most streams were **decoy HTTP traffic** — ordinary-looking `GET` requests to paths like `/`, `/about`, `/services`, `/products`, `/contact`, `/search`, `/random-page`, each with a `payload=<N>` query parameter. These were noise designed to bury the real signal.

### 3. The red herring — port 12345

One stream stood out immediately: a TCP connection on **port 12345**, which repeatedly sent a taunting plaintext message along the lines of *"This isn't what you're looking for..."*. This was a deliberate distractor to send analysts down the wrong path.

### 4. The real payload

Digging through the remaining HTTP streams, one request stood apart from the decoys:

```
GET /flag.txt HTTP/1.1
Host: 192.168.1.17
User-Agent: curl/...
```

The server (`192.168.1.17:80`) responded with `Content-Type: text/plain` and a body containing a **Base64-encoded string**:

```
Q1RGe1RyYWZmaWNfQ29ucXVlcm9yX0ZsYWdfQ2xhaW1lZH0K
```

### 5. Decoding

```bash
echo "Q1RGe1RyYWZmaWNfQ29ucXVlcm9yX0ZsYWdfQ2xhaW1lZH0K" | base64 -d
```

Output:

```
CTF{Traffic_Conqueror_Flag_Claimed}
```

---

## Flag

```
CTF{Traffic_Conqueror_Flag_Claimed}
```

---

## Key Takeaways

- Not all suspicious-looking traffic (e.g. the port 12345 stream) is where the real data lives — it can be a deliberate distraction.
- Legitimate-looking HTTP requests (`/flag.txt` via `curl`) can hide the actual exfiltrated/encoded data in plain sight.
- Always fully reconstruct and inspect *every* TCP stream in a capture rather than stopping at the first "interesting" one.
