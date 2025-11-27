---
title: "Sysmon mon mon"
date: 2025-11-25
---

# Who's that Sysmon?

A practical reference for Sysmon configuration, events, and DFIR usage.

---

## 🧩 What is Sysmon?

- **Sysmon** = System Monitor from Microsoft Sysinternals.
  
- Installs as a Windows service and driver to **log detailed system activity** to the Windows Event Log.
  
- Key for **threat hunting, DFIR, and detection engineering**.
  

---

## ⚙️ Installation & Configuration

### Install Sysmon

```powershell
Sysmon64.exe -i sysmonconfig.xml -accepteula
```

- `-i` → install
  
- `-accepteula` → accept license
  

### Update Configuration

```powershell
Sysmon64.exe -c sysmonconfig.xml
```

### Uninstall Sysmon

```powershell
Sysmon64.exe -u
```

### Common Sysmon Config Files

- `sysmonconfig.xml` → defines which events to log and which to filter/exclude
  
- Recommended sources:
  
  - [SwiftOnSecurity Sysmon Config](https://github.com/SwiftOnSecurity/sysmon-config)

---

## 📄 Event IDs

Sysmon logs events to **Applications and Services Logs → Microsoft → Windows → Sysmon → Operational**

| Event ID | Description |
| --- | --- |
| 1   | Process creation |
| 2   | File creation time changed |
| 3   | Network connection |
| 4   | Sysmon service state change |
| 5   | Process terminated |
| 6   | Driver loaded |
| 7   | Image loaded |
| 8   | CreateRemoteThread |
| 9   | RawAccessRead |
| 10  | ProcessAccess |
| 11  | FileCreate |
| 12  | Registry object added/modified |
| 13  | Registry value set |
| 14  | Registry key deleted |
| 15  | Registry value deleted |
| 16  | Sysmon pipe created |
| 17  | Sysmon pipe connected |
| 18  | WMI Filter Event |
| 19  | WMI Consumer Event |
| 20  | WMI Consumer To Filter |
| 21  | FileDeleteDetected |
| 22  | DNS query |
| 23  | FileDelete |

---

## 🧰 Useful Sysmon Queries for DFIR

### 1. Process Creation (Event ID 1)

- Detect suspicious command lines

```powershell
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | Where-Object { $_.Id -eq 1 -and $_.Properties[5].Value -match 'powershell|cmd.exe|wscript' }
```

### 2. Network Connections (Event ID 3)

- Detect external connections

```powershell
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | Where-Object { $_.Id -eq 3 -and $_.Properties[1].Value -notlike '192.168.*' }
```

### 3. File Creation Time Changes (Event ID 2)

```powershell
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | Where-Object { $_.Id -eq 2 }
```

### 4. Driver & DLL Load Monitoring (Event ID 6 & 7)

- Detect suspicious DLL injection / driver load

```powershell
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | Where-Object { $_.Id -in 6,7 -and $_.Properties[1].Value -match 'malicious.dll|unknown.sys' }
```

### 5. Registry Monitoring (Event IDs 12–15)

- Detect persistence mechanisms

```powershell
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | Where-Object { $_.Id -in 12,13,14,15 }
```

### 6. Detect WMI-based Attacks (Event IDs 18–20)

```powershell
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | Where-Object { $_.Id -in 18,19,20 }
```

### 7. DNS Query Monitoring (Event ID 22)

```powershell
Get-WinEvent -LogName Microsoft-Windows-Sysmon/Operational | Where-Object { $_.Id -eq 22 -and $_.Properties[0].Value -match 'suspicious.com' }
```

---

## 🎯 Detection Engineering Tips by ChatGPT!

- Always combine **Event IDs** to correlate behaviors (e.g., process creation + network connection).
  
- Filter out known-safe binaries using `ImageLoaded` or `ProcessCreate` filters.
  
- Use **Sysmon hashes** for file integrity monitoring.
  
- Regularly update your **Sysmon config** for new threats.
  
- Map events to **MITRE ATT&CK techniques** for structured detection.
  

---
