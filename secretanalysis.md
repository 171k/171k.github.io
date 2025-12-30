# Memory Analysis ITT593

by 171k

## Executive Summary

This report presents the findings from a memory forensics analysis of a compromised Windows system. The analysis reveals the presence of the **Zeus/Zbot banking trojan**, a sophisticated malware designed for financial fraud through web injection attacks. Veri denjeres indeed

---

## i. Machine Operating System

### Volatility Command:

```bash
# Identify OS profile, version, and architecture
volatility -f malware.vmem imageinfo

# Alternative: More detailed profile detection
volatility -f malware.vmem kdbgscan
```

| Property                 | Value                    |
| ------------------------ | ------------------------ |
| **Operating System**     | Microsoft Windows XP     |
| **Service Pack**         | Service Pack 3           |
| **Architecture**         | x86 (32-bit) with PAE    |
| **Number of Processors** | 1                        |
| **Suggested Profile**    | WinXPSP2x86, WinXPSP3x86 |
| **Image Date/Time**      | 2012-07-22 02:45:08 UTC  |

**Volatility imageinfo Output:**

```
Volatility Foundation Volatility Framework 2.6.1
INFO    : volatility.debug    : Determining profile based on KDBG search...
          Suggested Profile(s) : WinXPSP2x86, WinXPSP3x86 (Instantiated with WinXPSP2x86)
                     AS Layer1 : IA32PagedMemoryPae (Kernel AS)
                     AS Layer2 : FileAddressSpace
                      PAE type : PAE
                           DTB : 0x2fe000L
                          KDBG : 0x80545ae0L
          Number of Processors : 1
     Image Type (Service Pack) : 3
                KPCR for CPU 0 : 0xffdff000L
             KUSER_SHARED_DATA : 0xffdf0000L
           Image date and time : 2012-07-22 02:45:08 UTC+0000
     Image local date and time : 2012-07-21 22:45:08 -0400
```

**Additional evidence from memory strings:**

```
Microsoft (R) Windows (R) Version 5.1 (Build 2600: Service Pack 3)
1 System Processor [512 MB Memory]
processorArchitecture="x86"
```

---

## ii. Infected Process

### Volatility Commands:

```bash
# List all running processes
volatility -f malware.vmem --profile=WinXPSP3x86 pslist

# View process tree (parent-child relationships)
volatility -f malware.vmem --profile=WinXPSP3x86 pstree

# Scan for hidden/terminated processes
volatility -f malware.vmem --profile=WinXPSP3x86 psscan

# Detect code injection in processes
volatility -f malware.vmem --profile=WinXPSP3x86 malfind

# Check specific process for injection
volatility -f malware.vmem --profile=WinXPSP3x86 malfind -p 1640
```

| Property              | Value                                               |
| --------------------- | --------------------------------------------------- |
| **Process Name**      | `reader_sl.exe`                                     |
| **PID**               | 1640                                                |
| **Parent PID**        | 1484 (explorer.exe)                                 |
| **Start Time**        | 2012-07-22 02:42:36 UTC                             |
| **Threads**           | 5                                                   |
| **Handles**           | 39                                                  |
| **Injection Address** | 0x3d0000                                            |
| **Description**       | Adobe Reader Speed Launcher (Injected with malware) |

### Volatility pslist Output:

```
Offset(V)  Name                    PID   PPID   Thds     Hnds   Sess  Wow64 Start                          
---------- -------------------- ------ ------ ------ -------- ------ ------ ------------------------------
0x823c89c8 System                    4      0     53      240 ------      0                                
0x822f1020 smss.exe                368      4      3       19 ------      0 2012-07-22 02:42:31 UTC+0000   
0x822a0598 csrss.exe               584    368      9      326      0      0 2012-07-22 02:42:32 UTC+0000   
0x82298700 winlogon.exe            608    368     23      519      0      0 2012-07-22 02:42:32 UTC+0000   
0x81e2ab28 services.exe            652    608     16      243      0      0 2012-07-22 02:42:32 UTC+0000   
0x81e2a3b8 lsass.exe               664    608     24      330      0      0 2012-07-22 02:42:32 UTC+0000   
0x82311360 svchost.exe             824    652     20      194      0      0 2012-07-22 02:42:33 UTC+0000   
0x81e29ab8 svchost.exe             908    652      9      226      0      0 2012-07-22 02:42:33 UTC+0000   
0x823001d0 svchost.exe            1004    652     64     1118      0      0 2012-07-22 02:42:33 UTC+0000   
0x821dfda0 svchost.exe            1056    652      5       60      0      0 2012-07-22 02:42:33 UTC+0000   
0x82295650 svchost.exe            1220    652     15      197      0      0 2012-07-22 02:42:35 UTC+0000   
0x821dea70 explorer.exe           1484   1464     17      415      0      0 2012-07-22 02:42:36 UTC+0000   
0x81eb17b8 spoolsv.exe            1512    652     14      113      0      0 2012-07-22 02:42:36 UTC+0000   
0x81e7bda0 reader_sl.exe          1640   1484      5       39      0      0 2012-07-22 02:42:36 UTC+0000   
0x820e8da0 alg.exe                 788    652      7      104      0      0 2012-07-22 02:43:01 UTC+0000   
0x821fcda0 wuauclt.exe            1136   1004      8      173      0      0 2012-07-22 02:43:46 UTC+0000   
0x8205bda0 wuauclt.exe            1588   1004      5      132      0      0 2012-07-22 02:44:01 UTC+0000   
```

### Volatility pstree Output:

```
Name                                                  Pid   PPid   Thds   Hnds Time
-------------------------------------------------- ------ ------ ------ ------ ----
 0x823c89c8:System                                      4      0     53    240 1970-01-01 00:00:00 UTC+0000
. 0x822f1020:smss.exe                                 368      4      3     19 2012-07-22 02:42:31 UTC+0000
.. 0x82298700:winlogon.exe                            608    368     23    519 2012-07-22 02:42:32 UTC+0000
... 0x81e2ab28:services.exe                           652    608     16    243 2012-07-22 02:42:32 UTC+0000
.... 0x821dfda0:svchost.exe                          1056    652      5     60 2012-07-22 02:42:33 UTC+0000
.... 0x81eb17b8:spoolsv.exe                          1512    652     14    113 2012-07-22 02:42:36 UTC+0000
.... 0x81e29ab8:svchost.exe                           908    652      9    226 2012-07-22 02:42:33 UTC+0000
.... 0x823001d0:svchost.exe                          1004    652     64   1118 2012-07-22 02:42:33 UTC+0000
..... 0x8205bda0:wuauclt.exe                         1588   1004      5    132 2012-07-22 02:44:01 UTC+0000
..... 0x821fcda0:wuauclt.exe                         1136   1004      8    173 2012-07-22 02:43:46 UTC+0000
.... 0x82311360:svchost.exe                           824    652     20    194 2012-07-22 02:42:33 UTC+0000
.... 0x820e8da0:alg.exe                               788    652      7    104 2012-07-22 02:43:01 UTC+0000
.... 0x82295650:svchost.exe                          1220    652     15    197 2012-07-22 02:42:35 UTC+0000
... 0x81e2a3b8:lsass.exe                              664    608     24    330 2012-07-22 02:42:32 UTC+0000
.. 0x822a0598:csrss.exe                               584    368      9    326 2012-07-22 02:42:32 UTC+0000
 0x821dea70:explorer.exe                             1484   1464     17    415 2012-07-22 02:42:36 UTC+0000
. 0x81e7bda0:reader_sl.exe                           1640   1484      5     39 2012-07-22 02:42:36 UTC+0000
```

### Volatility malfind Output (Code Injection Evidence):

**Infected Process: reader_sl.exe (PID 1640)** - Contains injected PE executable:

```
Process: reader_sl.exe Pid: 1640 Address: 0x3d0000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 33, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x00000000003d0000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
0x00000000003d0010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
0x00000000003d0020  00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00   ................
0x00000000003d0030  00 00 00 00 00 00 00 00 00 00 00 00 e0 00 00 00   ................
```

**Infected Process: explorer.exe (PID 1484)** - Also contains injected PE executable:

```
Process: explorer.exe Pid: 1484 Address: 0x1460000
Vad Tag: VadS Protection: PAGE_EXECUTE_READWRITE
Flags: CommitCharge: 33, MemCommit: 1, PrivateMemory: 1, Protection: 6

0x0000000001460000  4d 5a 90 00 03 00 00 00 04 00 00 00 ff ff 00 00   MZ..............
0x0000000001460010  b8 00 00 00 00 00 00 00 40 00 00 00 00 00 00 00   ........@.......
```

### Analysis

The **malfind** output reveals critical evidence of malware injection:

1. **MZ Header (4d 5a)**: Both `reader_sl.exe` and `explorer.exe` contain injected PE executables (indicated by the "MZ" magic bytes at the start of the memory region)

2. **PAGE_EXECUTE_READWRITE**: The memory protection flag indicates writable and executable memory - a strong indicator of code injection

3. **Multiple Infected Processes**:
   
   | Process         | PID  | Injection Address  | Evidence                 |
   | --------------- | ---- | ------------------ | ------------------------ |
   | `reader_sl.exe` | 1640 | 0x3d0000           | MZ header (PE injection) |
   | `explorer.exe`  | 1484 | 0x1460000          | MZ header (PE injection) |
   | `winlogon.exe`  | 608  | Multiple addresses | Suspicious RWX memory    |
   | `csrss.exe`     | 584  | 0x7f6f0000         | Suspicious RWX memory    |

4. **Primary Target**: `reader_sl.exe` (Adobe Reader Speed Launcher) is the main infected process, spawned by `explorer.exe` which is also compromised

---

## iii. Suspicious Connection Made

### Volatility Commands:

```bash
# List active TCP connections (Windows XP)
volatility -f malware.vmem --profile=WinXPSP3x86 connections

# Scan for connection artifacts (including closed/terminated)
volatility -f malware.vmem --profile=WinXPSP3x86 connscan

# List open sockets
volatility -f malware.vmem --profile=WinXPSP3x86 sockets

# Scan for socket objects
volatility -f malware.vmem --profile=WinXPSP3x86 sockscan
```

### Command & Control (C2) Servers

| #   | Local Address       | Remote Address (C2)     | PID  | Process      |
| --- | ------------------- | ----------------------- | ---- | ------------ |
| 1   | 172.16.112.128:1038 | **41.168.5.140:8080**   | 1484 | explorer.exe |
| 2   | 172.16.112.128:1037 | **125.19.103.198:8080** | 1484 | explorer.exe |

### Volatility connections Output:

```
Offset(V)  Local Address             Remote Address            Pid
---------- ------------------------- ------------------------- ---
0x81e87620 172.16.112.128:1038       41.168.5.140:8080         1484
```

### Volatility connscan Output:

```
Offset(P)  Local Address             Remote Address            Pid
---------- ------------------------- ------------------------- ---
0x02087620 172.16.112.128:1038       41.168.5.140:8080         1484
0x023a8008 172.16.112.128:1037       125.19.103.198:8080       1484
```

### Volatility sockets Output:

```
Offset(V)       PID   Port  Proto Protocol        Address         Create Time
---------- -------- ------ ------ --------------- --------------- -----------
0x81ddb780      664    500     17 UDP             0.0.0.0         2012-07-22 02:42:53 UTC+0000
0x82240d08     1484   1038      6 TCP             0.0.0.0         2012-07-22 02:44:45 UTC+0000
0x81dd7618     1220   1900     17 UDP             172.16.112.128  2012-07-22 02:43:01 UTC+0000
0x82125610      788   1028      6 TCP             127.0.0.1       2012-07-22 02:43:01 UTC+0000
0x8219cc08        4    445      6 TCP             0.0.0.0         2012-07-22 02:42:31 UTC+0000
0x81ec23b0      908    135      6 TCP             0.0.0.0         2012-07-22 02:42:33 UTC+0000
0x82276878        4    139      6 TCP             172.16.112.128  2012-07-22 02:42:38 UTC+0000
0x82277460        4    137     17 UDP             172.16.112.128  2012-07-22 02:42:38 UTC+0000
0x81e76620     1004    123     17 UDP             127.0.0.1       2012-07-22 02:43:01 UTC+0000
0x82172808      664      0    255 Reserved        0.0.0.0         2012-07-22 02:42:53 UTC+0000
0x81e3f460        4    138     17 UDP             172.16.112.128  2012-07-22 02:42:38 UTC+0000
0x821f0630     1004    123     17 UDP             172.16.112.128  2012-07-22 02:43:01 UTC+0000
0x822cd2b0     1220   1900     17 UDP             127.0.0.1       2012-07-22 02:43:01 UTC+0000
0x82172c50      664   4500     17 UDP             0.0.0.0         2012-07-22 02:42:53 UTC+0000
0x821f0d00        4    445     17 UDP             0.0.0.0         2012-07-22 02:42:31 UTC+0000
```

### Analysis

**Active C2 Connections from Infected explorer.exe (PID 1484):**

| C2 Server IP       | Port | Connection Time         | Status        |
| ------------------ | ---- | ----------------------- | ------------- |
| **41.168.5.140**   | 8080 | 2012-07-22 02:44:45 UTC | Active        |
| **125.19.103.198** | 8080 | Earlier                 | Found in scan |

**Key Findings:**

1. Both malicious connections originate from **explorer.exe (PID 1484)** - the infected process
2. Both C2 servers use **port 8080** - common for Zeus to disguise as web traffic
3. The victim machine IP is **172.16.112.128** (internal network)
4. Socket created at **2012-07-22 02:44:45 UTC** - approximately 2 minutes after system boot

### C2 Communication Pattern

- Port **8080** is used to mimic legitimate HTTP proxy traffic
- Multiple C2 servers provide redundancy for the botnet
- Connections established from infected explorer.exe process

---

## iv. Other Characteristics of the Malware

### Volatility Commands:

```bash
volatility -f malware.vmem --profile=WinXPSP3x86 dlllist -p 1640
volatility -f malware.vmem --profile=WinXPSP3x86 handles -p 1640
volatility -f malware.vmem --profile=WinXPSP3x86 procdump -p 1640 -D dump/
volatility -f malware.vmem --profile=WinXPSP3x86 memdump -p 1640 -D dump/
strings malware.vmem | grep -i "bank\|chase\|paypal"
volatility -f malware.vmem --profile=WinXPSP3x86 printkey -K "Software\\Microsoft\\Windows\\CurrentVersion\\Run"
volatility -f malware.vmem --profile=WinXPSP3x86 mutantscan
```

### Command Justification:

| Command                                                     | Purpose                                     | Description and Findings                                                                                                                                                                                                         |
| ----------------------------------------------------------- | ------------------------------------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **`dlllist -p 1640`**                                       | Lists DLLs loaded by infected process       | **Identifies network capabilities**: Reveals if malware loaded networking DLLs (WS2_32.dll) for C2 communication. Helps understand malware functionality without reverse engineering.                                            |
| **`handles -p 1640`**                                       | Lists open handles (mutexes, events, files) | **Detects Zeus mutexes**: Zeus/Zbot creates specific mutexes (XMM, XME, XMR prefixes) to prevent multiple instances. These are signature indicators of Zeus malware family.                                                      |
| **`procdump -p 1640 -D dump/`**                             | Extracts process executable from memory     | **Preserves evidence**: Creates a copy of the infected process for further analysis, hash calculation, and potential submission to antivirus vendors.                                                                            |
| **`memdump -p 1640 -D dump/`**                              | Dumps entire process memory space           | **Extracts configuration data**: Malware configs (banking targets, C2 URLs, injection code) are often stored in process memory. Allows string extraction to find targeted institutions.                                          |
| **`strings malware.vmem \| grep -i "bank\|chase\|paypal"`** | Extracts readable strings from memory       | **Identifies targets**: Banking trojans embed target URLs/domains in memory. This reveals which financial institutions the malware is configured to attack.                                                                      |
| **`printkey -K "...\\Run"`**                                | Examines Windows Run registry keys          | **Finds persistence**: Malware often uses Run keys for persistence. This reveals how the malware survives reboots and identifies the actual malware executable name/location.                                                    |
| **`mutantscan`**                                            | Scans entire memory for mutex objects       | **System-wide mutex detection**: Unlike `handles` (process-specific), this finds all mutexes system-wide, including those from terminated processes. Critical for identifying Zeus mutex patterns across all infected processes. |

**Command Selection Strategy:**

1. **Process-focused analysis** (`dlllist`, `handles`) - Understand what the infected process is doing
2. **Evidence extraction** (`procdump`, `memdump`) - Preserve artifacts for analysis
3. **Pattern matching** (`strings`, `mutantscan`) - Find malware signatures and configurations
4. **Persistence discovery** (`printkey`) - Understand how malware maintains access

This combination provides a comprehensive view of malware characteristics without requiring binary reverse engineering.

---

### Volatility dlllist Output (reader_sl.exe PID 1640):

```
reader_sl.exe pid:   1640
Command line : "C:\Program Files\Adobe\Reader 9.0\Reader\Reader_sl.exe"

Base             Size  LoadCount Path
---------- ---------- ---------- ----
0x00400000     0xa000     0xffff C:\Program Files\Adobe\Reader 9.0\Reader\Reader_sl.exe
0x7c900000    0xaf000     0xffff C:\WINDOWS\system32\ntdll.dll
0x7c800000    0xf6000     0xffff C:\WINDOWS\system32\kernel32.dll
0x71ab0000    0x17000        0x1 C:\WINDOWS\system32\WS2_32.dll
0x71aa0000     0x8000        0x1 C:\WINDOWS\system32\WS2HELP.dll
```

**Note:** WS2_32.dll = Windows Sockets (network capability for C2 communication)

### Volatility handles Output (Zeus Mutexes Found):

```
Offset(V)     Pid     Handle     Access Type             Details
---------- ------ ---------- ---------- ---------------- -------
0x822fdb00   1640       0x88   0x1f0001 Mutant           XMM00000668
0x822d0d98   1640       0x8c   0x1f0003 Event            XME00000668
0x81e9d708   1640       0x98   0x1f0001 Mutant           XMR8149A9A8
```

**XMM, XME, XMR prefixed mutexes are Zeus/Zbot signatures!!!!!**

### Volatility printkey Output (PERSISTENCE MECHANISM FOUND):

```
Registry: \Device\HarddiskVolume1\Documents and Settings\Robert\NTUSER.DAT
Key name: Run (S)
Last updated: 2012-07-22 02:31:51 UTC+0000

Values:
REG_SZ  KB00207877.exe : (S) "C:\Documents and Settings\Robert\Application Data\KB00207877.exe"
```

| Property                 | Value                                                |
| ------------------------ | ---------------------------------------------------- |
| **Malware Executable**   | `KB00207877.exe`                                     |
| **Persistence Location** | `C:\Documents and Settings\Robert\Application Data\` |
| **Registry Key**         | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| **Infected User**        | Robert                                               |
| **Timestamp**            | 2012-07-22 02:31:51 UTC                              |

### Volatility mutantscan Output (Zeus Mutex Pattern):

```
Offset(P)          #Ptr #Hnd Signal Thread        CID  Name
------------------ ---- ---- ------ ---------- ------ ----
0x0000000001fd6030    2    1      1 0x00000000        746bbf3569adEncrypt
0x000000000209d708    3    2      1 0x00000000        XMR8149A9A8
0x000000000236ee30    2    1      0 0x82334da8 1484:1472 XMS8149A9A8
0x000000000236efb0    2    1      0 0x82249440 1484:1444 XMM000005CC
0x00000000024403c8    2    1      0 0x821c0798 1484:1476 XMQ8149A9A8
0x00000000024fdb00    2    1      0 0x822ffd80 1640:1448 XMM00000668
```

| Mutex Name            | PID  | Process       | Purpose         |
| --------------------- | ---- | ------------- | --------------- |
| `746bbf3569adEncrypt` | -    | -             | Data encryption |
| `XMR8149A9A8`         | -    | -             | Zeus mutex      |
| `XMS8149A9A8`         | 1484 | explorer.exe  | Zeus instance   |
| `XMM000005CC`         | 1484 | explorer.exe  | Zeus instance   |
| `XMQ8149A9A8`         | 1484 | explorer.exe  | Zeus instance   |
| `XMM00000668`         | 1640 | reader_sl.exe | Zeus instance   |

### Strings Output - Targeted Banks (100+ institutions):

**Major US Banks:**

- Bank of America (`cashproonline.bankofamerica.com`)
- Chase Bank (`chase.com`, `chaseonline.chase.com`)
- Citibank (`online.citibank.com`, `businessaccess.citibank.citigroup.com`)
- US Bank (`singlepoint.usbank.com`)
- PNC Bank (`treasury.pncbank.com`)
- TD Bank (`businessonline.tdbank.com`, `onlinebanking.tdbank.com`)
- Capital One (`towernet.capitalonebank.com`)
- Citizens Bank (`achieveaccess.citizensbank.com`)
- Wells Fargo, Union Bank, First Tennessee, and many more...

**International Banks:**

- Royal Bank of Canada (`royalbank.com`)
- Scotiabank (`scotiaonline.scotiabank.com`)
- CIBC (`businessbanking.cibc.com`)
- PayPal (`paypal.com`)
- European banks: Swedbank, Eurobank, Bank of Cyprus, etc.

### Web Injection Technique

The malware uses web injection to display fake security verification pages on banking websites. Based on strings extraction from memory, the malware is configured to inject fake forms that request:

- Credit card information
- Identity confirmation details
- Social Security Numbers
- Other sensitive financial data

**Note:** Banking target domains were identified through `strings malware.vmem | grep -i "bank\|chase\|paypal"` command.

### Malware Classification

| Property             | Value                            |
| -------------------- | -------------------------------- |
| **Malware Family**   | Zeus / Zbot                      |
| **Type**             | Banking Trojan                   |
| **Primary Function** | Web Injection & Credential Theft |
| **Attack Vector**    | Man-in-the-Browser (MitB)        |

### Targeted Financial Institutions (100+ Banks)

The malware contains web injection configurations targeting major financial institutions:

**United States Banks:**

- Bank of America (`cashproonline.bankofamerica.com`)
- Chase Bank (`chase.com`, `chaseonline.chase.com`)
- Citibank (`online.citibank.com`, `businessaccess.citibank.citigroup.com`)
- Wells Fargo (`wellsoffice.wellsfargo.com`)
- US Bank (`singlepoint.usbank.com`)
- PNC Bank (`treasury.pncbank.com`)
- Capital One (`towernet.capitalonebank.com`)
- TD Bank (`businessonline.tdbank.com`)
- Citizens Bank (`achieveaccess.citizensbank.com`)
- First Tennessee Bank (`banking.firsttennessee.biz`)
- Huntington Bank (`businessonline.huntington.com`)
- M&T Bank (`webbankingforbusiness.mandtbank.com`)
- Associated Bank (`bolb-east.associatedbank.com`)
- Compass Bank (`businessclassonline.compassbank.com`)
- Fifth Third Bank (`express.53.com`)
- Frost Bank (`treas-mgt.frostbank.com`)
- Union Bank (`sso.unionbank.com`)
- Silicon Valley Bank (`svbconnect.com`)

**Canadian Banks:**

- Royal Bank of Canada (`royalbank.com`)
- Scotiabank (`scotiaonline.scotiabank.com`, `scotiaconnect.scotiabank.com`)
- CIBC (`businessbanking.cibc.com`, `cibconline.cibc.com`)
- TD Canada (`easywebcpo.td.com`)
- BMO Harris (`bmoharrisprivatebankingonline.com`)

**Payment Processors:**

- Authorize.net (`account.authorize.net`)
- JPMorgan Access (`access.jpmorgan.com`)

### Data Exfiltration Targets

The malware is configured to steal the following personally identifiable information (PII) and financial data:

| Data Type                        | Evidence                                                     |
| -------------------------------- | ------------------------------------------------------------ |
| **Social Security Number (SSN)** | `<input type="text" name="ssn" id="ssn" maxlength="11">`     |
| **Company Tax ID**               | `<input type="text" name="taxid" id="taxid" maxlength="10">` |
| **Credit/Debit Card Numbers**    | `<input type="text" id="card1" name="ccnumber1">`            |
| **CVV/Security Codes**           | `inject_cvv` fields identified                               |
| **ATM PIN Numbers**              | `inject_pin` fields identified                               |
| **Date of Birth**                | `inject_dob_mm`, `inject_dob_dd`, `inject_dob_yy`            |
| **Mother's Maiden Name**         | `inject_mmn` field identified                                |
| **Driver's License Number**      | `inject_dl` field identified                                 |

### Web Injection Technique

The malware uses sophisticated JavaScript-based web injection:

1. **jQuery Integration**: Leverages jQuery UI library for creating convincing fake dialogs
2. **Modal Overlay**: Creates modal dialogs that block page interaction
3. **Hidden Original Content**: Sets `body { visibility: hidden; }` to hide legitimate page
4. **Social Engineering**: Displays fake "security update" messages to trick users
5. **Form Hijacking**: Intercepts and exfiltrates form submissions
6. **Cookie-based Tracking**: Uses `stopseQ` cookie marker to avoid re-injection on same session

### Persistence Mechanisms

1. **Registry Run Key**: Malware executable `KB00207877.exe` registered in `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` to execute on user login
2. **Process Injection**: Injected into legitimate processes (`reader_sl.exe`, `explorer.exe`) to hide execution
3. **Cookie-based Tracking**: Uses `stopseQ` cookie to avoid re-injecting fake forms on the same session
4. **Process Selection**: Targets processes that start automatically with Windows (explorer.exe) for persistence
5. **User Profile Location**: Installed in user's Application Data folder to avoid detection

### Indicators of Compromise (IOCs)

#### Network IOCs

| Type                | Value                 | Source                             |
| ------------------- | --------------------- | ---------------------------------- |
| **C2 IP Address 1** | `41.168.5.140:8080`   | `connections`, `connscan` (Active) |
| **C2 IP Address 2** | `125.19.103.198:8080` | `connscan` (Found in scan)         |
| **Victim IP**       | `172.16.112.128`      | Network connections                |
| **C2 Port**         | `8080`                | All C2 connections                 |

#### Process IOCs

| Type                                  | Value           | PID  | Source                   |
| ------------------------------------- | --------------- | ---- | ------------------------ |
| **Primary Infected Process**          | `reader_sl.exe` | 1640 | `pslist`, `malfind`      |
| **Secondary Infected Process**        | `explorer.exe`  | 1484 | `malfind`, `connections` |
| **Injection Address (reader_sl.exe)** | `0x3d0000`      | 1640 | `malfind`                |
| **Injection Address (explorer.exe)**  | `0x1460000`     | 1484 | `malfind`                |
| **Parent Process**                    | `explorer.exe`  | 1484 | `pstree`                 |

#### Persistence IOCs

| Type                     | Value                                                              | Source              |
| ------------------------ | ------------------------------------------------------------------ | ------------------- |
| **Malware Executable**   | `KB00207877.exe`                                                   | Registry `printkey` |
| **Persistence Location** | `C:\Documents and Settings\Robert\Application Data\KB00207877.exe` | Registry `printkey` |
| **Registry Key**         | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`               | Registry `printkey` |
| **Registry Value**       | `KB00207877.exe`                                                   | Registry `printkey` |
| **Infected User**        | `Robert`                                                           | Registry path       |
| **Registry Timestamp**   | `2012-07-22 02:31:51 UTC`                                          | Registry `printkey` |

#### Mutex IOCs (Zeus/Zbot Signatures)

| Mutex Name            | PID  | Process       | Source                  |
| --------------------- | ---- | ------------- | ----------------------- |
| `XMM00000668`         | 1640 | reader_sl.exe | `handles`, `mutantscan` |
| `XME00000668`         | 1640 | reader_sl.exe | `handles`               |
| `XMR8149A9A8`         | 1640 | reader_sl.exe | `handles`, `mutantscan` |
| `XMS8149A9A8`         | 1484 | explorer.exe  | `mutantscan`            |
| `XMM000005CC`         | 1484 | explorer.exe  | `mutantscan`            |
| `XMQ8149A9A8`         | 1484 | explorer.exe  | `mutantscan`            |
| `746bbf3569adEncrypt` | -    | -             | `mutantscan`            |

#### Behavioral IOCs

| Type                     | Value                            | Source                             |
| ------------------------ | -------------------------------- | ---------------------------------- |
| **Malware Family**       | Zeus/Zbot Banking Trojan         | Mutex patterns, C2 path            |
| **Injection Method**     | Process Hollowing/Code Injection | `malfind` (MZ headers)             |
| **Memory Protection**    | PAGE_EXECUTE_READWRITE           | `malfind`                          |
| **Network DLL**          | WS2_32.dll loaded                | `dlllist`                          |
| **Cookie Marker**        | `stopseQ`                        | Memory strings (injection control) |
| **Web Injection Target** | 100+ banking institutions        | Memory strings                     |

#### File System IOCs

| Type                        | Value                                                              |
| --------------------------- | ------------------------------------------------------------------ |
| **Legitimate Process Path** | `C:\Program Files\Adobe\Reader 9.0\Reader\Reader_sl.exe`           |
| **Malware Path**            | `C:\Documents and Settings\Robert\Application Data\KB00207877.exe` |
| **System Path**             | `C:\WINDOWS\Explorer.EXE`                                          |

---

Conclusion is.. be careful dont click click casually la grrr.

Thank you for reading!

