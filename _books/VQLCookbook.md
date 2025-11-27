---
title: "VQL Cookbook"
date: 2025-11-24
---

# VQL Cookbook

A practical reference for **Velociraptor VQL queries** used in DFIR and threat hunting.

---

## 🧪 VQL Basics Recap

- **VQL** = Velociraptor Query Language.

- Queries endpoints (Windows/Linux) for files, processes, registry, logs, network, etc.

- Format:

```vql
SELECT field1, field2 FROM source() WHERE condition
```

- Each query can be **an artifact** (reusable module).

---

## 📚 VQL Cookbook (Common Queries)

### 1. Process Hunting

| Query                                                  | Purpose                            |
| ------------------------------------------------------ | ---------------------------------- |
| `SELECT Name, Pid, Cmdline FROM pslist()`              | List all running processes         |
| `SELECT * FROM pslist() WHERE Cmdline =~ "powershell"` | Find PowerShell processes          |
| `SELECT * FROM pslist() WHERE Exe =~ "mimikatz"`       | Detect Mimikatz execution          |
| `SELECT * FROM pslist() WHERE Cmdline =~ "nc           | netcat                             |
| `SELECT * FROM pslist() WHERE Ppid = 4`                | Orphan processes, possible malware |

### 2. Network Connections

| Query                                                     | Purpose               |
| --------------------------------------------------------- | --------------------- |
| `SELECT LocalAddr, RemoteAddr, Pid FROM netstat()`        | List all connections  |
| `SELECT * FROM netstat() WHERE RemoteAddr != '127.0.0.1'` | External connections  |
| `SELECT * FROM netstat() WHERE Port = 1337`               | Suspicious port check |
| `SELECT * FROM netstat() WHERE State='LISTEN'`            | Open listening ports  |

### 3. File System / Persistence

| Query                                                                                                     | Purpose                           |
| --------------------------------------------------------------------------------------------------------- | --------------------------------- |
| `SELECT * FROM filelist(globs="**/autorun*.exe")`                                                         | Suspicious autorun files          |
| `SELECT Name, Data FROM winreg_list_keys(path="HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run")` | Registry run keys                 |
| `SELECT * FROM filelist(globs="C:/Windows/System32/*.exe") WHERE Mtime > now() - 3600`                    | Recently modified system binaries |
| `SELECT * FROM filelist(globs="C:/Users/*/AppData/**/*.dll")`                                             | DLL persistence                   |

### 4. Event Logs & Windows Forensics

| Query                                                                          | Purpose                     |
| ------------------------------------------------------------------------------ | --------------------------- |
| `SELECT * FROM Windows.EventLogs.Security WHERE EventID=4625`                  | Failed login attempts       |
| `SELECT * FROM Windows.EventLogs.Security WHERE EventID=4624`                  | Successful logins           |
| `SELECT * FROM Windows.EventLogs.Sysmon WHERE EventID=1`                       | Process creation monitoring |
| `SELECT * FROM Windows.EventLogs.PowerShell WHERE Message =~ "EncodedCommand"` | PowerShell obfuscation      |
| `SELECT * FROM Windows.Forensics.Timeline()`                                   | File & registry timeline    |

### 5. Browser / Credential Artifacts

| Query                                                          | Purpose                   |
| -------------------------------------------------------------- | ------------------------- |
| `SELECT * FROM Artifact.Windows.Forensics.CredentialManager()` | Saved Windows credentials |
| `SELECT * FROM Artifact.Windows.Chrome.History()`              | Browser history           |
| `SELECT * FROM Artifact.Windows.Firefox.History()`             | Firefox history           |

### 6. Linux Specific

| Query                                          | Purpose            |
| ---------------------------------------------- | ------------------ |
| `SELECT * FROM Linux.Sys.Processes()`          | Running processes  |
| `SELECT * FROM Linux.Sys.NetworkConnections()` | Active connections |
| `SELECT * FROM Linux.Sys.Startup()`            | Startup scripts    |
| `SELECT * FROM filelist(globs="/etc/cron*")`   | Scheduled jobs     |

---



