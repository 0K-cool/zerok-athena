# ATHENA Network Scanning Techniques Playbook

**Version:** 1.0.0
**Created:** 2026-03-18
**Platform:** ATHENA AI Pentesting Platform (ZeroK Labs)
**Scope:** Network reconnaissance — host discovery, port scanning, service detection, OS fingerprinting
**Audience:** ATHENA AI agents executing authorized penetration tests
**MITRE ATT&CK Tactic:** TA0043 (Reconnaissance), TA0007 (Discovery)
**Agent Assignment:** AR (Autonomous Recon)
**PTES Phase:** Intelligence Gathering / Scanning

---

## Brief Summary (Agent Context Window)

This playbook covers the full network scanning lifecycle from initial host discovery through service
fingerprinting and OS detection. Use it in order: discover live hosts first, then scan ports, then
identify services and operating systems. Each section includes the exact flags and when to use them.

Key decision tree:
- Internal LAN with root access → ARP for host discovery (fastest, no false negatives on /24)
- External/routed network → ICMP + TCP SYN probe combo
- Firewall suspected → ACK scan to map stateful vs stateless rules before port scanning
- Stealth required → SYN scan, T2 timing, avoid ICMP
- Speed required (e.g., full /16) → Naabu first pass, then nmap targeted
- UDP services needed → always run separate UDP scan; never rely on TCP-only results

MITRE techniques covered: T1595.001 (Active Scanning: Scanning IP Blocks), T1595.002
(Vulnerability Scanning), T1046 (Network Service Discovery).

Tool requirements: nmap 7.94+, naabu 2.3+, hping3, masscan 1.3+, httpx 1.6+, netcat,
udp-proto-scanner (optional). All available on Kali Linux 2024.x.

---

## Variable Reference

| Variable | Description | Example |
|---|---|---|
| `$TARGET` | Single IP, CIDR, or hostname | `192.168.1.0/24` |
| `$TARGET_IP` | Single IP address | `192.168.1.50` |
| `$ATTACKER_IP` | Attacker/ATHENA machine IP | `10.0.0.99` |
| `$IFACE` | Network interface | `eth0` |
| `$LOOT_DIR` | Local directory for output files | `/tmp/athena-loot` |
| `$PORTS` | Port list or range | `22,80,443,8080` |
| `$RATE` | Packets per second | `1000` |

---

## Section 1: Host Discovery

**MITRE:** T1595.001 (Active Scanning: Scanning IP Blocks)
**Agent:** AR
**Objective:** Identify which hosts are alive on the target network before port scanning.

### 1.1 ICMP Probes

ICMP echo (ping) is the default but firewalls frequently block it. Use timestamp and netmask
requests as fallbacks when echo is filtered.

```bash
# ICMP Echo Request (Type 8) — standard ping sweep
nmap -sn -PE $TARGET -oN $LOOT_DIR/hosts-icmp-echo.txt

# ICMP Timestamp Request (Type 13) — bypasses some ICMP echo filters
nmap -sn -PP $TARGET -oN $LOOT_DIR/hosts-icmp-timestamp.txt

# ICMP Address Mask Request (Type 17) — older, but still useful on legacy networks
nmap -sn -PM $TARGET -oN $LOOT_DIR/hosts-icmp-mask.txt

# All three ICMP probes combined
nmap -sn -PE -PP -PM $TARGET -oN $LOOT_DIR/hosts-icmp-all.txt
```

### 1.2 TCP SYN and ACK Probes

Use when ICMP is blocked. TCP SYN to port 80/443 hits webservers; ACK to port 80 can bypass
stateless firewalls that don't track TCP state.

```bash
# TCP SYN probe to port 80 (default when ICMP blocked)
nmap -sn -PS80,443 $TARGET -oN $LOOT_DIR/hosts-tcp-syn.txt

# TCP SYN to common service ports
nmap -sn -PS22,23,25,80,443,3389,8080 $TARGET -oN $LOOT_DIR/hosts-tcp-syn-wide.txt

# TCP ACK probe to port 80 — host appears up if RST received (stateless FW bypass)
nmap -sn -PA80,443 $TARGET -oN $LOOT_DIR/hosts-tcp-ack.txt

# Combined SYN + ACK probe
nmap -sn -PS80,443 -PA80,443 $TARGET -oN $LOOT_DIR/hosts-tcp-combined.txt
```

### 1.3 UDP Probes

UDP discovery hits hosts that may not respond to TCP probes (printers, SNMP devices, VoIP).

```bash
# UDP probe to port 53 (DNS) and 161 (SNMP)
nmap -sn -PU53,161 $TARGET -oN $LOOT_DIR/hosts-udp.txt

# UDP probe to common UDP services
nmap -sn -PU53,67,68,69,123,161,500 $TARGET -oN $LOOT_DIR/hosts-udp-wide.txt
```

### 1.4 ARP Discovery (Layer 2 — LAN only)

Most reliable method on local subnet. No false negatives; ARP cannot be blocked by host firewalls.
Requires root and must be on the same broadcast domain.

```bash
# ARP sweep — fastest and most reliable on LAN
nmap -sn -PR $TARGET -oN $LOOT_DIR/hosts-arp.txt

# ARP with Nmap (auto-selects ARP on LAN, need root)
sudo nmap -sn $TARGET -oN $LOOT_DIR/hosts-arp-auto.txt

# Masscan ARP sweep (faster on large subnets)
sudo masscan --ping $TARGET -oL $LOOT_DIR/hosts-masscan-arp.txt

# hping3 ARP probe to specific host
sudo hping3 --icmp $TARGET_IP -c 3
```

### 1.5 SCTP Probes

SCTP is used in VoIP and telecoms. Hosts running SCTP may not respond to TCP/ICMP probes.

```bash
# SCTP INIT probe — sends INIT chunk; INIT-ACK = host up, ABORT = port closed
nmap -sn -PY80,132 $TARGET -oN $LOOT_DIR/hosts-sctp.txt
```

### 1.6 Full Probe Combination (Production Use)

When unsure which probes the network allows, run all probe types simultaneously.

```bash
# All probe types — most thorough host discovery (requires root)
sudo nmap -sn -PE -PP -PM -PS22,80,443 -PA80,443 -PU53,161 $TARGET \
  -oN $LOOT_DIR/hosts-full.txt

# Extract live IPs into a target list for subsequent scans
grep "Nmap scan report" $LOOT_DIR/hosts-full.txt | awk '{print $NF}' > $LOOT_DIR/live-hosts.txt
```

---

## Section 2: TCP Port Scanning

**MITRE:** T1046 (Network Service Discovery)
**Agent:** AR
**Objective:** Map open TCP ports on live hosts identified in Section 1.

### 2.1 SYN Scan (Half-Open)

Default scan when running as root. Sends SYN, waits for SYN/ACK (open) or RST (closed). Never
completes the handshake — lower chance of logging by the application layer (not zero).

**When to use:** Default choice for most assessments. Requires root. Faster than Connect scan.

```bash
# SYN scan on top 1000 ports
sudo nmap -sS $TARGET_IP -oN $LOOT_DIR/tcp-syn.txt

# SYN scan with service version detection
sudo nmap -sS -sV $TARGET_IP -oN $LOOT_DIR/tcp-syn-versions.txt

# SYN scan on all 65535 ports
sudo nmap -sS -p- $TARGET_IP -oN $LOOT_DIR/tcp-syn-full.txt

# SYN scan on specific ports
sudo nmap -sS -p $PORTS $TARGET_IP -oN $LOOT_DIR/tcp-syn-ports.txt
```

### 2.2 Connect Scan (Full TCP Handshake)

Completes the full three-way handshake. Does not require root. Will appear in application logs.

**When to use:** When running without root privileges, or when the target OS logs half-open
connections (some Windows servers log SYN without completing handshake).

```bash
# Connect scan (no root required)
nmap -sT $TARGET_IP -oN $LOOT_DIR/tcp-connect.txt

# Full port range connect scan
nmap -sT -p- $TARGET_IP -oN $LOOT_DIR/tcp-connect-full.txt
```

### 2.3 ACK Scan

Sends ACK packets. An RST from the target means the port is unfiltered (no firewall in the way);
no response or ICMP unreachable means filtered. Does NOT determine if a port is open or closed —
only whether it is filtered by a firewall.

**When to use:** Map firewall rulesets before the main scan. Identify which ports a stateless
packet filter blocks vs passes. Combine with SYN scan results.

```bash
# ACK scan to detect firewall filtering
sudo nmap -sA $TARGET_IP -oN $LOOT_DIR/tcp-ack.txt

# ACK scan on common ports to build firewall map
sudo nmap -sA -p 22,25,80,443,3389 $TARGET_IP -oN $LOOT_DIR/tcp-ack-common.txt
```

### 2.4 FIN Scan

Sends a FIN packet. Closed ports respond with RST per RFC 793; open ports silently drop the
packet. Bypasses some simple packet filters that only block SYN.

**When to use:** When SYN scan is blocked but FIN packets pass. Works reliably against BSD-based
TCP stacks. NOT reliable against Windows (Windows RSTs all FIN probes regardless of port state).

```bash
# FIN scan
sudo nmap -sF $TARGET_IP -oN $LOOT_DIR/tcp-fin.txt

# FIN scan on top ports
sudo nmap -sF --top-ports 1000 $TARGET_IP -oN $LOOT_DIR/tcp-fin-top1000.txt
```

### 2.5 NULL Scan

Sends a packet with no TCP flags set. Same response logic as FIN: closed ports RST, open ports
drop silently.

**When to use:** Same scenarios as FIN scan. Useful when a firewall is configured to block FIN but
pass packets with no flags. Unreliable against Windows targets.

```bash
# NULL scan
sudo nmap -sN $TARGET_IP -oN $LOOT_DIR/tcp-null.txt
```

### 2.6 Xmas Scan

Sets FIN, PSH, and URG flags simultaneously (the packet "lights up like a Christmas tree"). Same
RFC 793 response logic: open = silent drop, closed = RST.

**When to use:** Same scenarios as FIN and NULL. Some IDS signatures catch Xmas; use when
targeting non-Windows hosts and when IDS evasion is not the primary concern.

```bash
# Xmas scan
sudo nmap -sX $TARGET_IP -oN $LOOT_DIR/tcp-xmas.txt
```

### 2.7 Fast Wide-Range Scanning with Masscan

Masscan achieves multi-million PPS rates. Use for rapid full-range sweeps, then feed results into
nmap for service detection.

```bash
# Full 65535-port scan at 10k PPS (adjust $RATE to network tolerance)
sudo masscan $TARGET -p0-65535 --rate=$RATE -oL $LOOT_DIR/masscan-full.txt

# Extract open ports for nmap follow-up
grep "open" $LOOT_DIR/masscan-full.txt | awk '{print $3}' | sort -u | \
  tr '\n' ',' | sed 's/,$//' > $LOOT_DIR/masscan-ports.txt

# Nmap targeted scan on masscan-discovered ports
sudo nmap -sS -sV -sC -p $(cat $LOOT_DIR/masscan-ports.txt) $TARGET_IP \
  -oN $LOOT_DIR/nmap-targeted.txt
```

---

## Section 3: UDP Scanning

**MITRE:** T1046 (Network Service Discovery)
**Agent:** AR
**Objective:** Discover open UDP services. UDP scanning is slower and requires different techniques
than TCP due to the connectionless nature of UDP.

### 3.1 Nmap UDP Scan

Sends empty UDP packets to each port. Port is open|filtered if no response; closed if ICMP port
unreachable received; open if application response received. Protocol-specific payloads improve
accuracy.

```bash
# UDP scan on top 1000 UDP ports (requires root)
sudo nmap -sU $TARGET_IP -oN $LOOT_DIR/udp-top1000.txt

# UDP scan with version detection (sends protocol-specific payloads)
sudo nmap -sU -sV $TARGET_IP -oN $LOOT_DIR/udp-versions.txt

# UDP scan on all 65535 ports (slow — rate limit to avoid overwhelming target)
sudo nmap -sU -p- --max-rate 500 $TARGET_IP -oN $LOOT_DIR/udp-full.txt

# UDP + TCP combined scan (efficient — one command)
sudo nmap -sU -sS $TARGET_IP -oN $LOOT_DIR/udp-tcp-combined.txt
```

### 3.2 Top UDP Services (Always Scan These)

These 20 UDP ports cover 90%+ of exposures found on internal and external assessments:

```bash
# Top UDP services targeted scan
sudo nmap -sU -sV -p 53,67,68,69,111,123,135,137,138,139,161,162,177,445,500,514,520,1900,4500,49152 \
  $TARGET_IP -oN $LOOT_DIR/udp-top-services.txt
```

| Port | Service | Notes |
|---|---|---|
| 53 | DNS | Zone transfer, cache poisoning |
| 67/68 | DHCP | Rogue server attacks |
| 69 | TFTP | Unauthenticated file read/write |
| 111 | RPC | Portmapper enumeration |
| 123 | NTP | Amplification, time manipulation |
| 161/162 | SNMP | Community string enumeration |
| 500 | IKE/IPsec | VPN fingerprinting |
| 1900 | UPnP | SSDP amplification, local network exposure |

### 3.3 Protocol-Specific UDP Payloads with hping3

```bash
# DNS query over UDP
hping3 --udp -p 53 -d 50 $TARGET_IP -c 3

# NTP version request
hping3 --udp -p 123 $TARGET_IP -c 3

# SNMP GetRequest (v1, community "public")
echo -ne "\x30\x26\x02\x01\x00\x04\x06\x70\x75\x62\x6c\x69\x63\xa0\x19\x02\x04\x00\x00\x00\x00\x02\x01\x00\x02\x01\x00\x30\x0b\x30\x09\x06\x05\x2b\x06\x01\x02\x01\x05\x00" | \
  nc -u -w 3 $TARGET_IP 161
```

### 3.4 udp-proto-scanner (Protocol-Aware UDP Scanning)

udp-proto-scanner sends protocol-correct payloads and is more accurate than nmap for UDP
fingerprinting. Install: `apt-get install udp-proto-scanner` or clone from GitHub.

```bash
# Scan with all protocol payloads
udp-proto-scanner.pl $TARGET_IP

# Scan specific protocol
udp-proto-scanner.pl --probe DNS $TARGET_IP

# Scan multiple hosts from file
udp-proto-scanner.pl --ip-list $LOOT_DIR/live-hosts.txt
```

---

## Section 4: Naabu Fast Scanning

**MITRE:** T1595.001 (Active Scanning)
**Agent:** AR
**Objective:** Fast port discovery using Naabu before detailed nmap fingerprinting. Naabu is
optimized for large-scale reconnaissance — use it for initial port discovery, then nmap for
service details.

### 4.1 Basic Naabu Usage

```bash
# Scan single host — top ports
naabu -host $TARGET_IP

# Scan with output to file
naabu -host $TARGET_IP -o $LOOT_DIR/naabu-results.txt

# Scan from target list
naabu -list $LOOT_DIR/live-hosts.txt -o $LOOT_DIR/naabu-results.txt

# JSON output for pipeline processing
naabu -host $TARGET_IP -json -o $LOOT_DIR/naabu-results.json
```

### 4.2 Full Range and Rate Control

```bash
# Full 65535-port scan
naabu -host $TARGET_IP -p - -o $LOOT_DIR/naabu-full.txt

# Rate limiting — reduce PPS to avoid detection/drops
naabu -host $TARGET -rate 1000 -o $LOOT_DIR/naabu-rate-limited.txt

# Rate limit to 500 PPS for stealth
naabu -host $TARGET -rate 500 -o $LOOT_DIR/naabu-stealth.txt

# Retries for dropped packets
naabu -host $TARGET -retries 3 -o $LOOT_DIR/naabu-retries.txt

# Timeout per host (milliseconds)
naabu -host $TARGET -timeout 3000 -o $LOOT_DIR/naabu-timeout.txt
```

### 4.3 Verification Mode

Naabu's verification mode performs a second pass using connect scan to confirm ports found by SYN
scan, reducing false positives.

```bash
# Enable verification pass (recommended for production scans)
naabu -host $TARGET_IP -verify -o $LOOT_DIR/naabu-verified.txt

# Full range with verification
naabu -host $TARGET_IP -p - -verify -o $LOOT_DIR/naabu-full-verified.txt
```

### 4.4 Naabu Pipeline to Nmap + httpx

Naabu outputs raw port/host pairs that feed directly into nmap and httpx for service detection.

```bash
# Naabu → httpx for web service discovery
naabu -host $TARGET -silent | httpx -silent -o $LOOT_DIR/web-services.txt

# Naabu full range → extract ports → nmap targeted
naabu -host $TARGET_IP -p - -silent -o $LOOT_DIR/naabu-ports.txt
OPEN_PORTS=$(cat $LOOT_DIR/naabu-ports.txt | cut -d: -f2 | tr '\n' ',')
sudo nmap -sV -sC -p $OPEN_PORTS $TARGET_IP -oN $LOOT_DIR/nmap-naabu-targeted.txt

# Naabu CIDR scan → httpx web probe
naabu -host $TARGET -p 80,443,8080,8443,8888 -silent | httpx -title -status-code \
  -o $LOOT_DIR/web-probe.txt

# Naabu with specific ports
naabu -host $TARGET_IP -p 22,80,443,3306,5432,6379,27017 -o $LOOT_DIR/naabu-services.txt
```

### 4.5 Naabu Flags Reference

| Flag | Purpose | Example |
|---|---|---|
| `-host` | Target IP/CIDR | `-host 10.0.0.0/24` |
| `-list` | Target file | `-list hosts.txt` |
| `-p` | Port list (`-` for all) | `-p 80,443` or `-p -` |
| `-rate` | Packets per second | `-rate 1000` |
| `-retries` | Retry count | `-retries 3` |
| `-timeout` | Timeout ms | `-timeout 3000` |
| `-verify` | Connect verification pass | `-verify` |
| `-silent` | Suppress banner | `-silent` |
| `-json` | JSON output | `-json` |
| `-o` | Output file | `-o results.txt` |
| `-c` | Concurrent goroutines | `-c 25` |
| `-top-ports` | Top N ports | `-top-ports 100` |

---

## Section 5: Service Detection

**MITRE:** T1595.002 (Active Scanning: Vulnerability Scanning), T1046
**Agent:** AR
**Objective:** Identify exact service versions running on open ports for vulnerability mapping.

### 5.1 Nmap Version Probing

```bash
# Version detection on open ports
sudo nmap -sV $TARGET_IP -oN $LOOT_DIR/service-versions.txt

# Aggressive version detection (more probes, slower, more accurate)
sudo nmap -sV --version-intensity 9 $TARGET_IP -oN $LOOT_DIR/service-versions-aggressive.txt

# Light version detection (faster, fewer probes)
sudo nmap -sV --version-intensity 2 $TARGET_IP -oN $LOOT_DIR/service-versions-light.txt

# Version detection on specific ports
sudo nmap -sV -p $PORTS $TARGET_IP -oN $LOOT_DIR/service-versions-ports.txt

# Version + default scripts combined
sudo nmap -sV -sC $TARGET_IP -oN $LOOT_DIR/service-versions-scripts.txt
```

### 5.2 NSE Scripts (Nmap Scripting Engine)

```bash
# Default safe scripts
sudo nmap -sC $TARGET_IP -oN $LOOT_DIR/nse-default.txt

# Run specific NSE script
sudo nmap --script=banner $TARGET_IP -oN $LOOT_DIR/nse-banner.txt

# Run script category
sudo nmap --script=default,safe $TARGET_IP -oN $LOOT_DIR/nse-safe.txt

# HTTP enumeration scripts
sudo nmap --script=http-headers,http-methods,http-title,http-server-header \
  -p 80,443,8080,8443 $TARGET_IP -oN $LOOT_DIR/nse-http.txt

# SMB enumeration
sudo nmap --script=smb-os-discovery,smb-security-mode,smb-enum-shares \
  -p 445 $TARGET_IP -oN $LOOT_DIR/nse-smb.txt

# SSH version and algorithms
sudo nmap --script=ssh2-enum-algos,ssh-hostkey -p 22 $TARGET_IP -oN $LOOT_DIR/nse-ssh.txt

# FTP anonymous access check
sudo nmap --script=ftp-anon,ftp-bounce -p 21 $TARGET_IP -oN $LOOT_DIR/nse-ftp.txt

# SNMP enumeration
sudo nmap --script=snmp-info,snmp-sysdescr,snmp-interfaces \
  -sU -p 161 $TARGET_IP -oN $LOOT_DIR/nse-snmp.txt

# Database detection
sudo nmap --script=mysql-info,mysql-empty-password -p 3306 $TARGET_IP -oN $LOOT_DIR/nse-mysql.txt
sudo nmap --script=ms-sql-info,ms-sql-empty-password -p 1433 $TARGET_IP -oN $LOOT_DIR/nse-mssql.txt

# Full aggressive scan (warning: noisy)
sudo nmap -A $TARGET_IP -oN $LOOT_DIR/nse-aggressive.txt
```

### 5.3 Banner Grabbing

Banner grabbing retrieves raw service banners without nmap's interpretation layer.

```bash
# Netcat banner grab
nc -w 3 $TARGET_IP 80
nc -w 3 $TARGET_IP 22
nc -w 3 $TARGET_IP 25

# Netcat with HTTP GET
echo -e "HEAD / HTTP/1.0\r\n\r\n" | nc -w 3 $TARGET_IP 80

# OpenSSL for TLS banner
echo "QUIT" | openssl s_client -connect $TARGET_IP:443 2>/dev/null | head -20

# Curl for HTTP headers
curl -s -I -m 5 http://$TARGET_IP/
curl -s -I -m 5 https://$TARGET_IP/ --insecure

# httpx for bulk web service fingerprinting
echo $TARGET_IP | httpx -title -status-code -tech-detect -web-server \
  -o $LOOT_DIR/httpx-fingerprint.txt

# httpx on list of hosts
httpx -list $LOOT_DIR/live-hosts.txt -title -status-code -tech-detect -web-server \
  -o $LOOT_DIR/httpx-bulk.txt
```

### 5.4 Service-Specific Probes

```bash
# SSH version check
ssh -o BatchMode=yes -o ConnectTimeout=5 $TARGET_IP 2>&1 | head -5

# SMTP banner
nc -w 3 $TARGET_IP 25 <<< "EHLO test.com"

# FTP banner
nc -w 3 $TARGET_IP 21

# RDP version (check for NLA requirement)
sudo nmap --script=rdp-enum-encryption -p 3389 $TARGET_IP -oN $LOOT_DIR/rdp-encryption.txt

# Redis version
redis-cli -h $TARGET_IP -p 6379 INFO server 2>/dev/null | head -10

# MongoDB detection
nc -w 3 $TARGET_IP 27017 </dev/null 2>/dev/null | strings | head
```

---

## Section 6: OS Fingerprinting

**MITRE:** T1592.002 (Gather Victim Host Information: Software)
**Agent:** AR
**Objective:** Determine the operating system of target hosts to inform exploitation decisions.

### 6.1 Active OS Fingerprinting with Nmap

Nmap sends a series of unusual TCP/UDP/ICMP probes and analyzes responses against a database of
known OS fingerprints. Requires at least one open and one closed port for accuracy.

```bash
# OS detection (requires root)
sudo nmap -O $TARGET_IP -oN $LOOT_DIR/os-fingerprint.txt

# OS detection with version — combined command
sudo nmap -O -sV $TARGET_IP -oN $LOOT_DIR/os-service.txt

# Aggressive OS detection (sends more probes if initial guess confidence is low)
sudo nmap -O --osscan-guess $TARGET_IP -oN $LOOT_DIR/os-guess.txt

# Limit OS detection to targets with high confidence possible
sudo nmap -O --osscan-limit $TARGET_IP -oN $LOOT_DIR/os-limit.txt

# Full detection: OS + services + default scripts + traceroute
sudo nmap -A $TARGET_IP -oN $LOOT_DIR/os-full.txt

# OS fingerprinting on multiple hosts
sudo nmap -O $LOOT_DIR/live-hosts.txt -oN $LOOT_DIR/os-bulk.txt
```

### 6.2 hping3 Active Fingerprinting

hping3 allows manual TTL and TCP window analysis which reveals OS family information.

```bash
# Check TTL (Linux ~64, Windows ~128, Cisco ~255)
hping3 -S -p 80 -c 3 $TARGET_IP | grep "ttl="

# Probe with SYN and analyze TCP window size
sudo hping3 -S -p 80 -c 5 $TARGET_IP

# ICMP echo with TTL analysis
sudo hping3 --icmp -c 5 $TARGET_IP | grep ttl

# RST response analysis (check window size in RST)
sudo hping3 -A -p 80 -c 3 $TARGET_IP
```

**TTL Reference:**
| TTL Value | Likely OS |
|---|---|
| 64 | Linux, FreeBSD, macOS |
| 128 | Windows |
| 255 | Cisco IOS, Solaris |
| 254 | Cisco IOS (some versions) |

**TCP Window Size Reference:**
| Window Size | Likely OS |
|---|---|
| 65535 | BSD, macOS |
| 8192 | Windows XP/2003 |
| 65535 | Windows 10/2016+ |
| 5840 | Linux 2.6 |

### 6.3 Passive OS Fingerprinting

Passive fingerprinting identifies OS without sending any additional probes — it analyzes traffic
already passing the network. Use p0f when active probing is too risky.

```bash
# p0f passive fingerprinting on live interface
sudo p0f -i $IFACE -o $LOOT_DIR/p0f-output.txt

# p0f on captured PCAP file
sudo p0f -r /path/to/capture.pcap -o $LOOT_DIR/p0f-pcap.txt

# Zeek OS fingerprinting (if Zeek is deployed on sensor)
# Outputs to notice.log with OS details when hosts connect
```

### 6.4 TTL-Based Quick Check

Fast, non-intrusive OS estimation using a single ping.

```bash
# Single ping TTL check
ping -c 1 $TARGET_IP | grep ttl

# Batch TTL check on live hosts
while read ip; do
  ttl=$(ping -c 1 -W 1 $ip 2>/dev/null | grep ttl | grep -oP 'ttl=\K[0-9]+')
  if [ -n "$ttl" ]; then
    if [ "$ttl" -le 64 ]; then os="Linux/macOS"
    elif [ "$ttl" -le 128 ]; then os="Windows"
    else os="Network Device"
    fi
    echo "$ip | TTL=$ttl | $os"
  fi
done < $LOOT_DIR/live-hosts.txt | tee $LOOT_DIR/ttl-os-map.txt
```

---

## Output Files Reference

| File | Contents |
|---|---|
| `$LOOT_DIR/live-hosts.txt` | Confirmed live IPs (one per line) |
| `$LOOT_DIR/naabu-verified.txt` | Naabu-confirmed open ports |
| `$LOOT_DIR/nmap-targeted.txt` | Nmap service scan on open ports |
| `$LOOT_DIR/service-versions.txt` | Full service version details |
| `$LOOT_DIR/os-fingerprint.txt` | OS detection results |
| `$LOOT_DIR/httpx-fingerprint.txt` | Web service fingerprints |
| `$LOOT_DIR/udp-top-services.txt` | UDP service results |

---

## Recommended Workflow

```
1. Host Discovery
   └── LAN: ARP (-PR) → fast, reliable
   └── WAN: ICMP + TCP SYN/ACK probes → extract live-hosts.txt

2. Fast Port Discovery
   └── Naabu full range with -verify → naabu-verified.txt
   └── Extract ports for nmap targeting

3. Detailed TCP Scan
   └── SYN scan on verified ports → tcp-syn-versions.txt
   └── Service version detection + default scripts

4. UDP Scan (parallel with TCP)
   └── Top 20 UDP ports → udp-top-services.txt

5. Service Fingerprinting
   └── httpx on web ports → httpx-fingerprint.txt
   └── Banner grab key services

6. OS Fingerprinting
   └── Nmap -O on live hosts → os-fingerprint.txt
   └── TTL quick check for confirmation
```
