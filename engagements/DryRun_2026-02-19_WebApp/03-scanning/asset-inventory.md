# Asset Inventory: 10.1.1.25 (Metasploitable 2)
## PTES Phase 2b: Active Reconnaissance Complete

**Scan Date**: 2026-02-19 01:19 UTC
**Scanner**: Nmap 7.98 with Service Detection (-sV -sC -O)
**Target**: 10.1.1.25 (metasploitable.localdomain)
**Status**: COMPREHENSIVE DISCOVERY

---

## Host Information

| Property | Value |
|----------|-------|
| IPv4 Address | 10.1.1.25 |
| Hostname | antlet25.bblv / metasploitable.localdomain |
| MAC Address | B2:61:6E:73:6C:19 |
| Network Distance | 1 hop (local LAN) |
| Response Time | 0.5ms |
| Operating System | Linux 2.6.9 - 2.6.33 |
| System Type | General Purpose |
| **Total Open Ports** | **30** |
| **Closed Ports** | 65505 |

### SMB/NetBIOS Information
- Computer Name: `metasploitable`
- NetBIOS Name: `METASPLOITABLE`
- Domain: `localdomain`
- Samba Version: `3.0.20-Debian`
- Message Signing: **DISABLED** (security risk)

---

## Critical Services (IMMEDIATE EXPLOITATION RISK)

### 1. **Port 1524/tcp - BINDSHELL (ROOT ACCESS)**
```
Service: Metasploitable root shell
Severity: CRITICAL
Description: Direct shell access with root privileges
Exploitation: Trivial - netcat connection provides root shell
Evidence: Service identified by nmap
```

### 2. **Port 512-514/tcp - REMOTE SHELL SERVICES**
```
Port 512: rsh exec (netkit-rsh rexecd)
Port 513: rsh login (OpenBSD/Solaris rlogind)
Port 514: tcpwrapped
Severity: CRITICAL
Description: Cleartext remote shell services
Exploitation: Common for lateral movement and privilege escalation
Evidence: Nmap service detection
```

### 3. **Port 2049/tcp - NFS WITHOUT AUTH**
```
Service: NFS 2-4 (RPC #100003)
Severity: CRITICAL
Description: Network File System without strong authentication
Mounted Systems: Check with `showmount -e 10.1.1.25`
Exploitation: File system access, privilege escalation
Evidence: RPC service enumeration
```

### 4. **Port 3306/tcp - MYSQL (NO PASSWORD)**
```
Service: MySQL 5.0.51a-3ubuntu5
Severity: CRITICAL
Description: Database server, often accessible without credentials
Default Credentials: root user typically has no password
Exploitation: Full database access, data exfiltration
Evidence: MySQL info script detected version and capabilities
```

### 5. **Port 5900/tcp - VNC (NO AUTH)**
```
Service: VNC Protocol 3.3
Severity: CRITICAL
Description: Remote desktop access without authentication
Exploitation: Full remote desktop control
Evidence: VNC info script shows no password required
```

---

## Web Application Services

### HTTP Web Servers

#### Port 80 - Apache 2.2.8
```
Service: Apache httpd 2.2.8 (Ubuntu) with DAV/2 support
Version: 2.2.8 (Outdated - Released 2008)
Known CVEs: Multiple vulnerability versions
Title: Metasploitable2 - Linux (default page)
Modules: DAV (WebDAV support - potential for remote file operations)
Risk: Directory traversal, arbitrary file upload via WebDAV
```

#### Port 8180 - Apache Tomcat
```
Service: Apache Tomcat/Coyote JSP engine 1.1
Version: Tomcat 5.5 (Outdated - End of Life)
Server: Apache-Coyote/1.1
Risk: JSP application vulnerabilities, remote code execution
```

#### Port 8009 - AJP13 (Apache Jserv)
```
Service: Apache Jserv Protocol v1.3
Purpose: Communication between Apache and Tomcat
Risk: Potential for protocol bypass vulnerabilities
```

---

## Database Services

### Port 3306 - MySQL 5.0.51a
```
Protocol Version: 10
Version: 5.0.51a-3ubuntu5
Thread ID: 11
Capabilities: Support41Auth, ConnectWithDatabase, Speaks41ProtocolNew, LongColumnFlag
Status: Autocommit enabled
Risk: Weak/no authentication, SQL injection vulnerabilities
```

### Port 5432 - PostgreSQL 8.3.0-8.3.7
```
Service: PostgreSQL Database
Version Range: 8.3.0 - 8.3.7
SSL: Certificate present (expired: 2010-04-16)
Risk: Weak password policies, SQL injection
```

---

## FTP Services

### Port 21 - vsftpd 2.3.4
```
Service: Very Secure FTP Daemon
Version: 2.3.4
Authentication: ANONYMOUS FTP LOGIN ALLOWED
Status: Connected as 'ftp' user
Session Timeout: 300 seconds
Control: Plain text (no encryption)
Data: Plain text transfer
Risk: CRITICAL - Anonymous upload/download capability
```

### Port 2121 - ProFTPD 1.3.1
```
Service: ProFTPD
Version: 1.3.1
Risk: Alternative FTP service, potential for elevation
```

---

## Remote Access Services

### Port 22 - OpenSSH
```
Service: OpenSSH
Version: 4.7p1 Debian 8ubuntu1
Protocol: SSH-2.0
Keys: DSA (1024-bit), RSA (2048-bit)
Risk: Old version, known vulnerabilities
```

### Port 23 - Telnet
```
Service: Linux telnetd
Risk: CRITICAL - Cleartext authentication and communication
```

---

## DNS & RPC Services

### Port 53 - ISC BIND 9.4.2
```
Service: ISC BIND DNS Server
Version: 9.4.2
Risk: Zone transfer possible, DNS spoofing
```

### Port 111 - RPC Bind
```
Service: RPC Portmapper (RPC #100000)
Exported Services:
  - NFS (100003) on port 2049
  - Mount Daemon (100005) on port 53921
  - NFS Lock Manager (100021) on port 55943
  - RPC Status (100024) on port 60171
Risk: Information disclosure, service enumeration
```

---

## Mail Service

### Port 25 - SMTP (Postfix)
```
Service: Postfix Mail Transfer Agent
Version: smtpd
SSL: Supported (SSLv2 - deprecated)
Features: PIPELINING, VRFY enabled (email enumeration), STARTTLS
Certificate: Expired (2010-04-16)
Risk: SMTP enumeration, mail injection
```

---

## IRC Service

### Ports 6667, 6697 - UnrealIRCd
```
Service: UnrealIRCd IRC Server
Ports: 6667 (standard), 6697 (SSL)
Risk: Backdoor vulnerability in certain versions
```

---

## Compiler Service

### Port 3632 - distcc
```
Service: Distributed C/C++ Compiler
Version: v1 (GNU 4.2.4 Ubuntu 4.2.4-1ubuntu4)
Risk: Remote code execution via compiler commands
```

---

## Java & RMI Services

### Port 1099 - Java RMI Registry
```
Service: GNU Classpath grmiregistry
Purpose: Java RMI service registry
Risk: Deserialization vulnerabilities, RMI exploitation
```

### Port 8787 - Ruby DRb
```
Service: Ruby Distributed Ruby (RMI)
Version: Ruby 1.8
Risk: Ruby-specific deserialization attacks
```

---

## X11 Graphics Service

### Port 6000 - X11
```
Service: X Window System Display Server
Status: Access Denied
Risk: Potential for privilege escalation if accessible
```

---

## Summary Statistics

| Category | Count |
|----------|-------|
| **Total Open Ports** | 30 |
| **Critical Services** | 5 (bindshell, rsh, NFS, MySQL, VNC) |
| **High Risk Services** | 12+ (outdated versions across stack) |
| **Web Services** | 3 (Apache, Tomcat, Jserv) |
| **Database Services** | 2 (MySQL, PostgreSQL) |
| **Remote Access** | 4 (SSH, Telnet, RSH, VNC) |
| **File Services** | 3 (FTP, NFS, WebDAV) |
| **RPC Services** | 4+ (Port mapper, Mount, NLockMgr) |
| **Information Leak Services** | 8+ (DNS, BIND, RPC, SMTP VRFY) |

---

## Exploitation Priority Matrix

| Priority | Service | Port | Reason |
|----------|---------|------|--------|
| **P0-IMMEDIATE** | Bindshell | 1524 | Direct root access |
| **P0-IMMEDIATE** | VNC | 5900 | Remote desktop, no auth |
| **P1-CRITICAL** | MySQL | 3306 | Database, no password |
| **P1-CRITICAL** | NFS | 2049 | File system access |
| **P1-CRITICAL** | RSH | 512-514 | Remote shell |
| **P2-HIGH** | Anonymous FTP | 21 | File upload/download |
| **P2-HIGH** | Apache 2.2.8 | 80 | Old version, CVEs |
| **P2-HIGH** | Tomcat 5.5 | 8180 | JSP exploitation |
| **P2-HIGH** | Samba 3.0.20 | 445 | SMB vulnerabilities |
| **P3-MEDIUM** | PostgreSQL | 5432 | Database access |
| **P3-MEDIUM** | BIND 9.4.2 | 53 | Zone transfer |
| **P3-MEDIUM** | Telnet | 23 | Cleartext shells |

---

## Next Steps

1. **Vulnerability Scanning**: Nuclei scan for known CVEs
2. **Web Application Testing**: Enumerate Apache/Tomcat applications
3. **RPC Service Enumeration**: Detailed NFS/Mount service analysis
4. **Database Exploration**: MySQL/PostgreSQL default credentials test
5. **Service Exploitation**: Non-destructive POC for critical findings

---

**Status**: Asset inventory complete. Ready for Phase 3 (Vulnerability Analysis) and Phase 4 (Exploitation Validation).
