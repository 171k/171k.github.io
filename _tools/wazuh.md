---
title: "Wazuh Startup!"
date: 2024-11-20
---

# Wazuh!

Quick reference for using Wazuh for security monitoring and SIEM!

---

## 📦 Wazuh Components Overview

- **Wazuh Manager** — Processes logs, runs rules, decoders.
  
- **Wazuh Agent** — Installed on endpoints; sends logs to manager.
  
- **Filebeat** — Sends alerts to Elasticsearch.
  
- **Elasticsearch** — Stores and indexes alerts.
  
- **Wazuh Dashboard** — GUI for searching/log analysis.
  

---

## 🚀 Basic Commands (Manager)

### Start / Stop / Restart

```bash
systemctl start wazuh-manager
systemctl stop wazuh-manager
systemctl restart wazuh-manager
```

### Check Status

```bash
systemctl status wazuh-manager
```

### View Logs

```bash
tail -f /var/ossec/logs/ossec.log
```

---

## 📝 Agent Management

### List All Agents

```bash
/var/ossec/bin/agent_control -l
```

### Check Agent Status

```bash
/var/ossec/bin/agent_control -i ID
```

### Restart Agent (Linux)

```bash
systemctl restart wazuh-agent
```

---

## 🔍 Log Locations

| Component | Log File |
| --- | --- |
| Manager main log | `/var/ossec/logs/ossec.log` |
| Alerts | `/var/ossec/logs/alerts/alerts.json` |
| Agent logs | `/var/ossec/logs/ossec.log` |
| Decoders | `/var/ossec/etc/decoders/` |
| Rules | `/var/ossec/etc/rules/` |

---

## 🎯 Searching Alerts (CTF Useful)

### Using Linux CLI (alerts.json)

Search keywords:

```bash
grep -i "failed" /var/ossec/logs/alerts/alerts.json
```

Search for IPs:

```bash
grep "192.168.1.10" alerts.json
```

Search for specific rule ID:

```bash
grep "rule":.*"5710" alerts.json
```

Pretty-print JSON alerts:

```bash
jq . /var/ossec/logs/alerts/alerts.json
```

---

## 📊 Dashboard (Kibana/Wazuh UI)

### Common Searches

- **Failed logins**
  
  ```
  rule.id: 5710 OR rule.id: 5720
  ```
  
- **SSH brute force**
  
  ```
  rule.groups: ssh AND rule.level >= 5
  ```
  
- **Malware alerts**
  
  ```
  rule.groups: malware
  ```
  
- **File Integrity Monitoring (FIM)**
  
  ```
  rule.groups: fim
  ```
  
- **Agent errors**
  
  ```
  rule.groups: ossec AND rule.level >= 3
  ```
  

---

## 🕵️‍♂️ CTF Analysis Cheatsheet

### Find Suspicious Commands

```bash
grep -i "sudo" alerts.json
grep -i "nc " alerts.json
grep -i "curl" alerts.json
grep -i "wget" alerts.json
grep -i "python" alerts.json
```

### Detect Reverse Shells

Rule group example:

```bash
rule.groups: "shell_command"
```

Stress match for suspicious characters:

```bash
grep -E "(;|&&|\|)" alerts.json
```

### Look for Credential Theft Attempts

```bash
rule.groups: authentication AND rule.level >= 5
```

### Filter by MITRE ATT&CK ID

```bash
mitre.id: T1059
```

---

## 🛠 Writing Custom Rules

Rules live in:

```
/var/ossec/etc/rules/local_rules.xml
```

### Example custom rule

```xml
<group name="custom,syslog,">
  <rule id="600001" level="7">
    <match>unauthorized access detected</match>
    <description>Custom alert: Unauthorized access string found</description>
  </rule>
</group>
```

Reload rules:

```bash
systemctl restart wazuh-manager
```

---

## 🔎 Writing Custom Decoders

Decoder location:

```
/var/ossec/etc/decoders/local_decoder.xml
```

Example:

```xml
<decoder name="custom-app">
  <program_name>myapp</program_name>
</decoder>

<decoder name="custom-app-msg">
  <parent>custom-app</parent>
  <regex>action: (\w+), user: (\w+)</regex>
  <order>action,user</order>
</decoder>
```

---

## 🧪 Debug Mode

Useful for troubleshooting rule/decoder issues.

```bash
/var/ossec/bin/ossec-logtest
```

Paste a log entry → see which rules match.

---

## 🧰 Useful Linux Commands (Forensics)

### Check system modifications (FIM)

```bash
grep -i "fim" alerts.json
```

### List triggered rules sorted by frequency

```bash
grep "rule.id" alerts.json | sort | uniq -c | sort -nr
```

---

## 🚀 Quick Workflow for CTF hehe

1. Open Dashboard → view **Security Events**
  
2. Sort by **Level** (high first)
  
3. Identify suspicious activity (commands, IPs)
  
4. Correlate with timestamps
  
5. Inspect FIM alerts → check modified files
  
6. Extract Indicators of Compromise (IOCs)
  

---

This is just part of the things I learnt maybe I'll add more in the future!

