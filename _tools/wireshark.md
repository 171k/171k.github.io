---
title: "Wireshark"
date: 2024-05-01
---

# Wireshark for CTF

Sometimes Apackets is useless so lets make a quick reference for packet analysis during CTF challenges.

---

## 🧩 Basic Navigation

- **Start/Stop Capture**: Shark fin icon / red square
  
- **Open PCAP**: `File → Open`
  
- **Follow Stream**: Right‑click packet → Follow → TCP/UDP/HTTP/SSL stream
  
- **Use Display Filter Bar**: Top filter input box
  

---

## 🎯 Essential Display Filters

### 🔹 Protocol Filters

```
ip
tcp
udp
icmp
http
https
dns
ftp
smtp
ssh
```

### 🔹 Filter by IP

```
ip.addr == 10.0.0.5
ip.src == 192.168.1.10
ip.dst == 8.8.8.8
```

### 🔹 Filter by Port

```
tcp.port == 80
tcp.srcport == 443
tcp.dstport == 1337
```

### 🔹 Filter by MAC Address

```
eth.addr == AA:BB:CC:DD:EE:FF
```

### 🔹 Filter by Contains Data

```
frame contains flag
http contains "flag"
dns.qry.name contains "ctf"
```

### 🔹 Filter for Credentials

```
http.authbasic
ftp.request.command == "USER"
ftp contains PASS
```

### 🔹 Filter by Packet Type

```
tcp.flags.syn == 1
tcp.flags.fin == 1
tcp.flags.reset == 1
```

---

## 🔍 Common CTF Tasks

### ✔ Extract Credentials

1. Filter:

```
http
ftp
smtp
pop
imap
```

2. Right‑click → Follow Stream.

### ✔ Reconstruct Files (e.g., images, zip)

- `File → Export Objects → HTTP`
  
- `File → Export Objects → SMB`
  
- `File → Export Packet Bytes` (for manual carving)
  

### ✔ Find Hidden Data

- Look at **UDP/TCP payloads**
  
- Use `frame contains` to search keywords
  
- Inspect DNS TXT queries:
  

```
dns.txt
```

- Look for base64:

```
frame matches "[A-Za-z0-9+/]{20,}="
```

### ✔ Follow Streams

- TCP stream (cleartext protocols)
  
- HTTP stream (GET/POST data)
  
- UDP stream (custom protocols)
  
- SSL stream (if key available)
  

Keyboard shortcut: **Ctrl + Alt + Shift + T**

---

## 🛠 Useful Tools Inside Wireshark

### 🔹 Decode As...

Right‑click → Decode As → set protocol (useful for odd ports).

### 🔹 Packet Bytes View

- Shows raw hex
  
- Good for carving files / hidden payloads
  

### 🔹 Statistics Menu

- **Protocol Hierarchy** (what traffic exists?)
  
- **Endpoints** (active IPs, MACs)
  
- **Conversations** (pair‑wise communication)
  
- **I/O Graphs** (find bursts / anomalies)
  

---

## 🗝 Decrypting HTTPS (if key available)

`Edit → Preferences → Protocols → TLS → (Pre‑Master Secret log)`

Then apply filter:

```
http
```

---

## 🧪 Advanced Filters (Very Useful)

### Find suspicious payload sizes

```
frame.len > 500
```

### Find ASCII printable bytes

```
data-text-lines
```

### Track a single TCP session

```
tcp.stream == 5
```

### Detect port scans

```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

### Filter out noise

```
!(dns || mdns || arp)
```

---

## 💡 File Carving Tricks

### Extract everything likely to be base64

```
frame matches "[A-Za-z0-9+/]{30,}"
```

Copy payload → decode.

### Extract PNG files manually

PNG header:

```
89 50 4E 47 0D 0A 1A 0A
```

Search using:

```
frame contains 89:50:4E:47
```

Export packet bytes → save → test with `file` command.

---

## 🧰 External Tools to Pair with Wireshark

- **tshark** – CLI Wireshark
  
- **scapy** – custom packet analysis
  
- **binwalk** – file carving
  
- **foremost / bulk_extractor** – data extraction
  
- **CyberChef** – decode literally everything
  

---

## 🚀 Quick Workflow for CTF!

1. Open PCAP
  
2. Check **Statistics → Protocol Hierarchy**
  
3. Find interesting IPs → filter by them
  
4. Follow streams
  
5. Export objects
  
6. Search for keywords:
  

```
frame contains "flag"
frame contains "ctf"
frame contains "{"
```

7. Look for encoded data (base64, hex, gzip)
  
8. Extract files
  

---
