

# Velociraptor? Dinosaur?

I really am new in using velociraptor so please excuse me if I made a mistake here.

This a practical guide for DFIR, threat hunting, and detection engineering using **Velociraptor**.

---

## 🧩 What is Velociraptor?

Velociraptor is a **DFIR and threat hunting platform** that uses VQL (Velociraptor Query Language) to collect, hunt, and monitor endpoints.

Key features:

- Live forensic artifact collection
  
- Endpoint monitoring
  
- Threat hunting at scale
  
- Fast and efficient VQL query engine
  

---

## 🚀 Basic Commands

### Start/Stop Service (Linux)

```bash
systemctl start velociraptor
systemctl stop velociraptor
systemctl status velociraptor
```

### Run GUI Server

```bash
velociraptor --config server.config.yaml frontend
```

### Client Diagnostics

```bash
velociraptor --config client.config.yaml interrogate
```

---

## 🧪 VQL Basics

### Query Template

```vql
SELECT field1, field2 FROM source()
```

### Run VQL in GUI

- Notebook → New Cell → Add Query
  
- Artifacts → New Hunt → Add VQL
  

---

## 📚 Common VQL Sources

| Source | Purpose |
| --- | --- |
| `Artifact.Windows.Sysinternals.Autoruns` | Autoruns & persistence |
| `Artifact.Windows.EventLogs.*` | Windows event logs |
| `Artifact.Windows.Detection.*` | Common detections |
| `pslist()` | Processes |
| `filelist()` | Files on disk |
| `winreg_*()` | Windows registry |
| `netstat()` | Network connections |

---

## 🕵️‍♂️ Threat Hunting Queries

### List Running Processes

```vql
SELECT Name, Pid, Exe, Cmdline FROM pslist()
```

### Suspicious Processes

```vql
SELECT * FROM pslist() WHERE Cmdline =~ "(powershell|nc|base64|wget)"
```

### Network Connections

```vql
SELECT LocalAddr, RemoteAddr, Pid FROM netstat()
```

### Look for Reverse Shell Indicators

```vql
SELECT * FROM pslist() WHERE Cmdline =~ "(tcp|udp|connect|bash -i)"
```

### Search File System for IOCs

```vql
SELECT * FROM filelist(globs="**/suspect.exe")
```

### Detect Persistence via Registry Run Keys

```vql
SELECT Name, Data FROM winreg_list_keys(path="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")
```

---

## 🧰 Velociraptor Artifacts (Most Useful)

### Windows

- **Windows.System.Pslist** – Process listing
  
- **Windows.System.Netstat** – Network connections
  
- **Windows.Persistence.RegistryRun** – Run keys
  
- **Windows.Forensics.Timeline** – File/registry timeline
  
- **Windows.Anomaly.SuspiciousServices** – Suspicious services
  

### Linux

- **Linux.Sys.Processes** – Process list
  
- **Linux.Sys.NetworkConnections** – Active connections
  
- **Linux.Sys.Startup** – Startup scripts
  

### Endpoint Monitoring

- **Windows.EventLogs.Security** – Login traces
  
- **Windows.EventLogs.Sysmon** – Attack behaviors
  

---

## 📡 Live Hunt Examples

### Find Mimikatz Execution

Mimikatz is a post-exploitation tool used to extract credentials from windows system!

```vql
SELECT * FROM pslist() WHERE Exe =~ "mimikatz"
```

### Powershell Download Cradle

```vql
SELECT * FROM Windows.EventLogs.PowerShell WHERE Message =~ "DownloadString"
```

### Detect Web Shells

```vql
SELECT * FROM filelist(globs="C:/inetpub/wwwroot/**/*.aspx") WHERE Size < 2000
```

---

## 🔎 DFIR Investigation

### File System Timeline

```vql
SELECT * FROM Artifact.Windows.Forensics.Timeline()
```

### Investigate Modified System Binaries

```vql
SELECT * FROM filelist(globs="C:/Windows/System32/*.exe") WHERE Mtime > now() - 3600
```

### Saved Browser Credentials

```vql
SELECT * FROM Artifact.Windows.Forensics.CredentialManager()
```

---

## 📝 Writing Custom VQL

### Basic VQL Artifact Template

```yaml
name: Custom.Hunt.SuspiciousFiles
sources:
  - query: |
      SELECT * FROM filelist(globs="C:/Users/*/AppData/**/*.exe")
```

### Add Parameters

```yaml
params:
  - name: TargetGlob
    default: "**/*.exe"

sources:
  - query: |
      SELECT * FROM filelist(globs=TargetGlob)
```

---

## 🎯 Detection Engineering with Velociraptor

### 1. Build High-Fidelity Detections

Use VQL to:

- Chain conditions
  
- Validate parent/child processes
  
- Filter by behavior pattern
  

### 2. Example: Detection for Living-Off-The-Land (LOLBin)

```vql
SELECT * FROM pslist() WHERE Exe IN (
  "certutil.exe", "bitsadmin.exe", "wmic.exe"
)
```

### 3. Example: Detect PowerShell Obfuscation

```vql
SELECT * FROM Windows.EventLogs.PowerShell WHERE Message =~ "EncodedCommand"
```

---

## 🛡 Best Practices (by ChatGPT)

- Always test VQL in a Notebook before running Hunts.
  
- Build modular artifacts.
  
- Avoid expensive file scans; use targeted globs.
  
- Use `LIMIT 200` during testing.
  
- Validate detections against real attack tools.
  
- Document queries with comments.
  
- Keep artifacts under version control.
  

---

## 🚀 Hunting Workflow for DFIR

1. **Collect triage artifacts** (pslist, netstat, autoruns)
  
2. Build timeline
  
3. Search for suspicious processes or connections
  
4. Enumerate persistence
  
5. Extract IOCs
  
6. Hunt organization-wide
  
7. Validate and respond
  

---
