# Remediation Roadmap
## DryRun_2026-02-19_WebApp

**Prepared by**: ATHENA Security Platform
**Date**: 2026-02-19
**Target**: 10.1.1.25 (Metasploitable 2)
**Total Findings**: 10 (5 Critical, 5 High)

---

## Remediation Priority Framework

| Priority | Label | Criteria | Timeframe |
|----------|-------|----------|-----------|
| P0 | IMMEDIATE | Active backdoors, unauthenticated root access, no auth required | Within 24 hours |
| P1 | SHORT-TERM | Exploitable CVEs, weak authentication, dangerous misconfigurations | Within 1–2 weeks |
| P2 | LONG-TERM | Outdated software requiring replacement, architectural improvements | Within 1–3 months |

---

## P0 — IMMEDIATE Actions (Within 24 Hours)

These items require no significant engineering effort. They represent active, trivially exploitable risks that can be resolved with simple administrative actions.

---

### P0-1: Isolate 10.1.1.25 from All Non-Lab Networks

**Addresses**: All findings (VULN-001 through VULN-010)
**Effort**: Low (network/VLAN configuration change)

Metasploitable 2 is an intentionally vulnerable training platform. It must never be reachable from production networks, corporate LAN, or the internet.

**Actions**:
- Move 10.1.1.25 to an isolated VLAN with no routing to production segments
- Block all inbound traffic from outside the designated lab network at the perimeter firewall
- Verify isolation with a connectivity test from a production host

**Validation**: `ping 10.1.1.25` from a production host should time out.

---

### P0-2: Kill the Root Bindshell on Port 1524

**Addresses**: VULN-002 (CVSS 10.0)
**Effort**: Low (kill process, disable service)

Port 1524/tcp is an open root shell — the highest possible severity. Any host that can reach 10.1.1.25 can issue commands as root with zero authentication.

**Actions**:
```bash
# Identify and kill the bindshell process
fuser -k 1524/tcp
# Or identify the process and kill it
lsof -i :1524
kill -9 <PID>
# Prevent restart: check init scripts
grep -r "1524" /etc/inetd.conf /etc/xinetd.d/ /etc/init.d/
# Comment out or remove any entry launching this service
```

**Validation**: `nc 10.1.1.25 1524` should return "Connection refused."

---

### P0-3: Set MySQL Root Password and Disable Remote Root Login

**Addresses**: VULN-004 (CVSS 9.8)
**Effort**: Low (SQL commands)

MySQL is accessible from the network with no root password. This exposes all 7 databases and provides a path to OS-level file access.

**Actions**:
```sql
-- Connect locally: mysql -u root
ALTER USER 'root'@'%' IDENTIFIED BY 'StrongMySQLPass!2026';
DELETE FROM mysql.user WHERE User='root' AND Host != 'localhost';
FLUSH PRIVILEGES;
```

Additionally, bind MySQL to localhost in `/etc/mysql/my.cnf`:
```ini
[mysqld]
bind-address = 127.0.0.1
```

**Validation**: `mysql -h 10.1.1.25 -u root --skip-ssl` should return "Access denied."

---

### P0-4: Set Strong VNC Password

**Addresses**: VULN-003 (CVSS 9.8)
**Effort**: Low (VNC configuration)

VNC is accepting connections with the trivially guessable password `password`, providing root graphical desktop access to any attacker.

**Actions**:
```bash
# Update VNC password (minimum 12 characters, complex)
vncpasswd
# Restart VNC service
service vncserver restart
```

Alternatively, if VNC is not required, disable it:
```bash
service vncserver stop
update-rc.d vncserver disable
```

**Validation**: Attempt `vncviewer 10.1.1.25:5900` with password `password` — should be rejected.

---

## P1 — SHORT-TERM Actions (Within 1–2 Weeks)

These items require more deliberate action — software removal/replacement, configuration changes, or service hardening.

---

### P1-1: Remove vsftpd 2.3.4 (Backdoored Binary)

**Addresses**: VULN-001 (CVE-2011-2523, CVSS 9.8)
**Effort**: Medium (uninstall, replace)

vsftpd 2.3.4 contains a known backdoor. The binary must be replaced, not just patched.

**Actions**:
```bash
# Remove backdoored vsftpd
apt-get remove --purge vsftpd
# Install current vsftpd from trusted repository
apt-get update && apt-get install vsftpd
# Or use OpenSSH SFTP subsystem instead of FTP:
# Add to /etc/ssh/sshd_config:
# Subsystem sftp /usr/lib/openssh/sftp-server
```

**Validation**: `nmap --script ftp-vsftpd-backdoor -p 21 10.1.1.25` should report "NOT VULNERABLE."

---

### P1-2: Remove UnrealIRCd 3.2.8.1 (Backdoored Binary)

**Addresses**: VULN-006 (CVE-2010-2075, CVSS 9.8)
**Effort**: Medium (uninstall, replace)

UnrealIRCd 3.2.8.1 contains a known backdoor introduced via a compromised source mirror. The binary must be replaced entirely.

**Actions**:
```bash
# Stop and remove the backdoored IRCd
service unrealircd stop
apt-get remove --purge unrealircd
# If IRC is required, install a trusted alternative:
apt-get install inspircd
```

**Validation**: `nmap --script irc-unrealircd-backdoor -p 6667 10.1.1.25` should not return the backdoor detection message.

---

### P1-3: Restrict NFS Exports

**Addresses**: VULN-005 (CVSS 9.8)
**Effort**: Low-Medium (edit /etc/exports)

NFS exports the entire root filesystem to all hosts without authentication.

**Actions**:
Edit `/etc/exports` — remove `/ *` and replace with only what is required, restricted to specific IPs:
```
# Remove this:
# / *

# Replace with (example — only if NFS is genuinely required):
/srv/nfs 10.1.1.0/24(ro,no_subtree_check,sec=sys)
```

Apply changes:
```bash
exportfs -ra
```

If NFS is not required:
```bash
service nfs-kernel-server stop
update-rc.d nfs-kernel-server disable
```

**Validation**: `showmount -e 10.1.1.25` should show only restricted exports or "no exports."

---

### P1-4: Restrict or Disable distccd

**Addresses**: VULN-007 (CVE-2004-2687, CVSS 9.3)
**Effort**: Low (configuration or disable)

distccd allows unauthenticated remote code execution via the distcc protocol.

**Actions**:
If distccd is not required for active builds:
```bash
service distccd stop
update-rc.d distccd disable
```

If required, restrict to trusted IP addresses:
```bash
# Edit /etc/default/distccd
STARTDISTCC="true"
ALLOWEDNETS="127.0.0.1"  # Only localhost, or specific build server IPs
LISTENER="127.0.0.1"
```

**Validation**: `nmap --script distcc-cve2004-2687 -p 3632 10.1.1.25` should return "NOT VULNERABLE" or "filtered/closed."

---

### P1-5: Harden Samba Configuration

**Addresses**: VULN-008 (CVE-2007-2447, CVSS 9.8)
**Effort**: Medium (Samba upgrade + config)

Three issues: known RCE CVE, anonymous access, and signing disabled.

**Actions**:
1. Upgrade Samba to a currently supported version (3.0.20 is severely outdated):
   ```bash
   apt-get update && apt-get install samba
   ```
2. Disable anonymous/guest access in `smb.conf`:
   ```ini
   [global]
   map to guest = Never
   guest ok = No
   ```
3. Enable SMB signing:
   ```ini
   [global]
   server signing = mandatory
   client signing = mandatory
   ```
4. Restrict share access to authenticated users only.

**Validation**: `smbclient -L //10.1.1.25 -N` should return "NT_STATUS_ACCESS_DENIED."

---

### P1-6: Disable AJP Connector on Tomcat 5.5

**Addresses**: VULN-009 (CVE-2020-1938 Ghostcat, CVSS 9.8)
**Effort**: Low (Tomcat config change)

The AJP connector is the attack vector for Ghostcat. Most deployments do not require it.

**Actions**:
In `$CATALINA_HOME/conf/server.xml`, comment out or remove the AJP connector:
```xml
<!-- Comment out this line: -->
<!-- <Connector port="8009" protocol="AJP/1.3" redirectPort="8443" /> -->
```

Restart Tomcat:
```bash
$CATALINA_HOME/bin/shutdown.sh && $CATALINA_HOME/bin/startup.sh
```

If AJP is required, upgrade to Tomcat 9.0.31+ and configure `requiredSecret`.

**Validation**: `nmap -p 8009 10.1.1.25` should show port as closed/filtered.

---

### P1-7: Disable PHP-CGI Mode / Patch CVE-2012-1823

**Addresses**: VULN-010 (CVE-2012-1823, CVSS 7.5)
**Effort**: Medium (PHP reconfiguration)

PHP-CGI mode enables argument injection leading to source disclosure and RCE.

**Actions**:
Switch from PHP-CGI to PHP-FPM:
```bash
apt-get install php-fpm
a2enmod proxy_fcgi
a2dismod php5 cgi
# Configure Apache to use PHP-FPM socket
```

Alternatively, as a temporary mitigation, add a WAF rule or Apache rewrite rule to block query strings starting with `-`:
```apache
RewriteEngine On
RewriteCond %{QUERY_STRING} ^-
RewriteRule .* - [F]
```

**Validation**: `curl "http://10.1.1.25/?-s"` should return a 403 or execute PHP rather than disclosing source.

---

## P2 — LONG-TERM Actions (Within 1–3 Months)

These items require architectural work — full software stack replacement, hardening frameworks, and network security controls.

---

### P2-1: Replace Entire Software Stack with Supported Versions

**Addresses**: All findings (underlying root cause)
**Effort**: High (full system rebuild)

The entire software stack on 10.1.1.25 is severely outdated. All services are running versions that are end-of-life with no security support.

**Target State**:
| Current | Replace With |
|---------|-------------|
| vsftpd 2.3.4 (2011) | OpenSSH SFTP subsystem (current) |
| OpenSSH 4.7p1 (2008) | OpenSSH 9.x (current) |
| Apache 2.2.8 (2008) | Apache 2.4.x (current) or Nginx |
| PHP-CGI (old) | PHP 8.x + PHP-FPM |
| MySQL 5.0.51a (2008) | MySQL 8.x or MariaDB 11.x |
| PostgreSQL 8.3.x (2008) | PostgreSQL 16.x |
| Samba 3.0.20 (2006) | Samba 4.x (current) |
| Apache Tomcat 5.5 (EOL 2012) | Tomcat 10.x (current) |
| UnrealIRCd 3.2.8.1 (backdoored) | Remove entirely |
| Linux 2.6.x kernel | Linux 6.x (current LTS) |

**Recommended approach**: Provision a new system with a current Ubuntu LTS (22.04 or 24.04) and migrate required services with hardened configurations.

---

### P2-2: Implement Host-Based Firewall (iptables/nftables)

**Addresses**: All findings (defense-in-depth)
**Effort**: Medium

Even after patching, 30 open ports is an unnecessarily large attack surface. Implement a host-based firewall restricting each service to only its required source IPs.

**Example iptables policy**:
```bash
# Default deny inbound
iptables -P INPUT DROP
iptables -P FORWARD DROP
iptables -P OUTPUT ACCEPT
# Allow established/related
iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
# Allow loopback
iptables -A INPUT -i lo -j ACCEPT
# Allow SSH from management network only
iptables -A INPUT -p tcp --dport 22 -s 10.1.1.0/24 -j ACCEPT
# Allow HTTP/HTTPS
iptables -A INPUT -p tcp --dport 80 -j ACCEPT
iptables -A INPUT -p tcp --dport 443 -j ACCEPT
# Block everything else
iptables -A INPUT -j DROP
```

---

### P2-3: Implement Centralized Log Management and Alerting

**Addresses**: Detection and response capability (architectural)
**Effort**: Medium

The current system has no alerting or monitoring. Implement centralized log collection to detect:
- Failed and successful authentication events
- Unusual network connections
- File integrity changes
- Privilege escalation events

**Recommended**: Ship logs to a SIEM (Splunk, Elastic/Kibana, Graylog) and configure alerts for authentication anomalies.

---

### P2-3a: Rotate All Credentials — Assume Full Compromise

**Addresses**: Post-exploitation scenarios 1–4 (credential harvest from VULN-004, VULN-005, VULN-010)
**Effort**: Medium

Post-exploitation simulation shows an attacker harvests all credential material from `/etc/shadow`, MySQL, and web app config files within the first minute of access. If this system was ever connected to a broader network, treat all credentials as compromised.

**Actions**:
- Rotate all 33 OS user passwords
- Rotate MySQL, PostgreSQL, and all application database passwords
- Revoke and reissue any SSH private keys stored on the system (`/root/.ssh/`, `/home/*/.ssh/`)
- Invalidate and regenerate any API keys or secrets in `/var/www/*/config/`
- Audit all other systems that share credentials with this host (especially `msfadmin/msfadmin`)

---

### P2-3b: Audit for Pre-Installed Persistence

**Addresses**: VULN-002 (bindshell), post-exploitation persistence simulation
**Effort**: Low-Medium

Beyond the known bindshell on port 1524, conduct a full persistence audit before trusting this system.

**Actions**:
```bash
# Check all listening processes
ss -tlnp
# Check crontab entries
cat /etc/crontab; crontab -l -u root
# Check authorized_keys for all users
find /root /home -name authorized_keys -exec cat {} \;
# Check for unexpected root-uid accounts
awk -F: '$3 == 0' /etc/passwd
# Check world-writable SUID binaries
find / -perm -4000 -writable 2>/dev/null
# Audit init scripts for unexpected services
ls /etc/init.d/ && ls /etc/rc*.d/
```

---

### P2-4: Conduct Post-Remediation Retest

**Addresses**: Validation of all remediations
**Effort**: Low-Medium (schedule a retest engagement)

After implementing P0, P1, and P2 remediations, schedule a retest engagement using the same PTES methodology to validate that all 10 findings have been resolved. The retest should be conducted from the same network position (10.1.1.13) using the same tool set.

**Retest scope**: All 10 VULN-IDs from this report.
**Pass criteria**: Zero findings in severity categories Critical or High.

---

## Remediation Tracking Summary

| VULN-ID | Priority | Action Summary | Effort | Owner | Status |
|---------|----------|---------------|--------|-------|--------|
| VULN-002 | P0-2 | Kill bindshell on port 1524 | Low | SysAdmin | Open |
| VULN-003 | P0-4 | Set strong VNC password or disable | Low | SysAdmin | Open |
| VULN-004 | P0-3 | Set MySQL root password, disable remote root | Low | DBA | Open |
| All | P0-1 | Isolate to lab VLAN only | Low | NetAdmin | Open |
| VULN-001 | P1-1 | Remove backdoored vsftpd 2.3.4 | Medium | SysAdmin | Open |
| VULN-005 | P1-3 | Restrict NFS exports | Low-Med | SysAdmin | Open |
| VULN-006 | P1-2 | Remove backdoored UnrealIRCd 3.2.8.1 | Medium | SysAdmin | Open |
| VULN-007 | P1-4 | Restrict/disable distccd | Low | SysAdmin | Open |
| VULN-008 | P1-5 | Upgrade Samba, disable anonymous access, enable signing | Medium | SysAdmin | Open |
| VULN-009 | P1-6 | Disable AJP connector on Tomcat 5.5 | Low | AppAdmin | Open |
| VULN-010 | P1-7 | Disable PHP-CGI, block -arg queries | Medium | AppAdmin | Open |
| All | P2-1 | Full software stack replacement | High | Engineering | Open |
| All | P2-2 | Host-based firewall implementation | Medium | NetAdmin | Open |
| All | P2-3 | Centralized logging and alerting | Medium | SecOps | Open |
| All | P2-3a | Rotate all credentials — assume full compromise | Medium | SysAdmin/DBA | Open |
| All | P2-3b | Audit for pre-installed persistence (cron, SSH keys, SUID, init scripts) | Low-Med | SysAdmin | Open |
| All | P2-4 | Schedule post-remediation retest | Low-Med | Engagement Lead | Open |

---

*Remediation Roadmap generated by ATHENA Security Platform — 2026-02-19*
*For questions about specific remediations, reference the corresponding VULN-ID in technical-report.md*
