# ATHENA Advanced Scanning & Firewall Evasion Playbook

**Version:** 1.0.0
**Created:** 2026-03-18
**Platform:** ATHENA AI Pentesting Platform (ZeroK Labs)
**Scope:** Firewall detection, IDS/IPS evasion, tarpit detection, CDN/NAT bypass, alternative discovery
**Audience:** ATHENA AI agents executing authorized penetration tests
**MITRE ATT&CK Tactic:** TA0043 (Reconnaissance), TA0005 (Defense Evasion)
**Agent Assignment:** AR (Autonomous Recon), EX (Exploitation — for evasion during active phases)
**PTES Phase:** Scanning / Intelligence Gathering

---

## Brief Summary (Agent Context Window)

This playbook covers advanced scanning techniques for environments with active network defenses.
Use it after basic host/port discovery (see network-scanning-techniques.md) when results are
incomplete, inconsistent, or when stealth is required.

Key decision tree:
- Inconsistent port results → run ACK scan to identify firewall filtering vs stateless blocks
- All ports filtered on external scan → test source port spoofing (-g 53/80/443)
- Scan triggering alerts → reduce timing template to T1/T2, add decoys
- Hosts appear unreachable → test IPv6, SCTP, or alternate protocols
- Target is behind CDN → identify origin via SSL cert, DNS history, direct IP brute-force
- Latency doubles mid-scan → tarpit detected; avoid that host or use very slow timing

MITRE techniques covered: T1595 (Active Scanning), T1040 (Network Sniffing for passive FP),
T1205 (Traffic Signaling), T1599 (Network Boundary Bridging).

Tool requirements: nmap 7.94+, hping3, masscan 1.3+, naabu 2.3+, p0f (passive FP), scapy,
iputils-arping. All available on Kali Linux 2024.x.

Warning: Some techniques in this playbook (decoys, idle scan, fragmentation) may be illegal
without written authorization even in penetration testing contexts. Always verify scope.

---

## Variable Reference

| Variable | Description | Example |
|---|---|---|
| `$TARGET` | Single IP, CIDR, or hostname | `192.168.1.0/24` |
| `$TARGET_IP` | Single IP address | `192.168.1.50` |
| `$ATTACKER_IP` | Attacker/ATHENA machine IP | `10.0.0.99` |
| `$ZOMBIE_IP` | Idle scan zombie host IP | `192.168.1.20` |
| `$DECOY_IPS` | Comma-separated decoy IPs | `10.0.0.1,10.0.0.2,ME` |
| `$IFACE` | Network interface | `eth0` |
| `$LOOT_DIR` | Local directory for output files | `/tmp/athena-loot` |
| `$PORTS` | Port list or range | `22,80,443,8080` |
| `$RATE` | Packets per second | `500` |

---

## Section 1: Firewall Detection

**MITRE:** T1595.001 (Active Scanning: Scanning IP Blocks)
**Agent:** AR
**Objective:** Determine whether a firewall is present, whether it is stateful or stateless, and
which ports it filters. This informs bypass strategy selection.

### 1.1 ACK Scan to Map Firewall Rules

The ACK scan is the primary firewall detection technique. An RST response means the packet
reached the target (port is unfiltered). No response or ICMP unreachable means the firewall
dropped or rejected the packet (filtered).

```bash
# ACK scan — maps filtered vs unfiltered ports
sudo nmap -sA $TARGET_IP -oN $LOOT_DIR/firewall-ack-map.txt

# ACK scan on specific ports to test firewall rules
sudo nmap -sA -p 22,25,53,80,443,8080,3389 $TARGET_IP -oN $LOOT_DIR/firewall-ack-ports.txt

# ACK scan full range (slow — use targeted first)
sudo nmap -sA -p- $TARGET_IP -oN $LOOT_DIR/firewall-ack-full.txt
```

**Interpreting ACK results:**
- RST received → `unfiltered` → packet reached host, firewall passed it
- No response / ICMP unreachable → `filtered` → firewall blocked it

### 1.2 Stateful vs Stateless Firewall Identification

A stateful firewall tracks TCP connection state — it will block ACK packets for connections that
were never established. A stateless (packet filter) firewall acts on individual packets without
state — ACK packets pass if allowed by the ruleset.

```bash
# Test for stateful vs stateless:
# Step 1: ACK scan — if all ports show "filtered", likely stateful (blocking unsolicited ACKs)
sudo nmap -sA -p 80,443 $TARGET_IP

# Step 2: SYN scan — if ports show "open" that were "filtered" in ACK scan, firewall is stateful
sudo nmap -sS -p 80,443 $TARGET_IP

# Interpretation:
# Port 80: ACK=filtered, SYN=open → stateful firewall (allowed the SYN, blocked the ACK)
# Port 80: ACK=unfiltered, SYN=open → stateless packet filter (passes ACKs)
# Port 80: ACK=filtered, SYN=filtered → both filtered — strong stateful FW or host-based FW

# hping3 stateful test — send ACK without prior SYN
sudo hping3 -A -p 80 -c 5 $TARGET_IP
# RST back = port reachable (stateless or no FW)
# No response = stateful FW blocking unsolicited ACK
```

### 1.3 Window Scan for Firewall Bypass Potential

The Window scan is like ACK scan but examines the TCP window field in RST responses. Some systems
(primarily AIX and BSD variants) set a non-zero window in RST for open ports, allowing open/closed
distinction even through some firewalls.

```bash
# Window scan
sudo nmap -sW $TARGET_IP -oN $LOOT_DIR/firewall-window.txt

# Window scan on common ports
sudo nmap -sW -p 22,80,443,3389 $TARGET_IP -oN $LOOT_DIR/firewall-window-ports.txt
```

### 1.4 Maimon Scan

Sends FIN/ACK probe. Certain BSD-derived systems drop the packet for open ports instead of RST,
allowing firewall bypass detection.

```bash
# Maimon scan
sudo nmap -sM $TARGET_IP -oN $LOOT_DIR/firewall-maimon.txt
```

---

## Section 2: Firewall Bypass Techniques

**MITRE:** T1562.001 (Impair Defenses: Disable or Modify Tools — conceptual mapping)
**Agent:** AR, EX
**Objective:** Bypass packet-filtering firewalls to reach ports and services that appear filtered.

### 2.1 Source Port Manipulation

Many firewalls allow inbound traffic from trusted source ports (DNS=53, HTTP=80, HTTPS=443) to
support replies to outbound connections. Spoofing the source port can bypass stateless rules.

```bash
# Source port 53 (DNS) — often allowed through firewalls
sudo nmap -sS -g 53 $TARGET_IP -oN $LOOT_DIR/bypass-sport53.txt

# Source port 80 — allowed by many corporate firewalls
sudo nmap -sS -g 80 $TARGET_IP -oN $LOOT_DIR/bypass-sport80.txt

# Source port 443
sudo nmap -sS -g 443 $TARGET_IP -oN $LOOT_DIR/bypass-sport443.txt

# UDP with source port 53
sudo nmap -sU -g 53 $TARGET_IP -oN $LOOT_DIR/bypass-udp-sport53.txt

# hping3 source port manipulation
sudo hping3 -S -s 53 -p 80 $TARGET_IP -c 5
sudo hping3 -S -s 80 -p $PORTS $TARGET_IP -c 5
```

### 2.2 IP Fragmentation

Splitting TCP headers across multiple IP fragments can bypass older packet filters and some IDS
systems that do not reassemble fragments before inspection.

```bash
# 8-byte fragments (minimum)
sudo nmap -sS -f $TARGET_IP -oN $LOOT_DIR/bypass-frag8.txt

# 16-byte fragments (double -f)
sudo nmap -sS -ff $TARGET_IP -oN $LOOT_DIR/bypass-frag16.txt

# Custom MTU fragmentation (must be multiple of 8)
sudo nmap -sS --mtu 16 $TARGET_IP -oN $LOOT_DIR/bypass-mtu16.txt
sudo nmap -sS --mtu 24 $TARGET_IP -oN $LOOT_DIR/bypass-mtu24.txt

# Fragmentation combined with source port spoof
sudo nmap -sS -f -g 53 $TARGET_IP -oN $LOOT_DIR/bypass-frag-sport.txt

# hping3 fragmentation
sudo hping3 -S -p 80 -f $TARGET_IP -c 5
```

**When fragmentation fails:** Modern stateful firewalls and NGFW reassemble fragments before
inspection. Fragment attacks are most effective against legacy ACLs and some embedded devices.

### 2.3 Bad Checksum Probe

Sends packets with intentionally invalid checksums. Some firewalls pass these without inspection;
the target host will drop them (no open port response). If you get RST back, the firewall did not
inspect checksums.

```bash
# Bad checksum test
sudo nmap --badsum $TARGET_IP -oN $LOOT_DIR/bypass-badsum.txt
# All responses with --badsum indicate firewall not inspecting checksums
```

### 2.4 Data Length Padding

Appends random data to packets, changing their size to confuse IDS signatures that match on
specific packet lengths.

```bash
# Append 200 bytes of random data
sudo nmap -sS --data-length 200 $TARGET_IP -oN $LOOT_DIR/bypass-datalength.txt

# Custom data length
sudo nmap -sS --data-length 100 $TARGET_IP -oN $LOOT_DIR/bypass-datalength100.txt
```

### 2.5 IP Spoofing and Source Address Manipulation

Source IP spoofing for firewall bypass (requires being on the same network segment or specific
routing conditions). Primarily useful for testing egress filtering and firewall rule validation.

```bash
# Spoof source IP address
sudo nmap -S $ATTACKER_IP $TARGET_IP -e $IFACE -oN $LOOT_DIR/bypass-spoof.txt

# hping3 source IP spoof
sudo hping3 -S -a 192.168.1.1 -p 80 $TARGET_IP -c 5
```

---

## Section 3: IDS/IPS Evasion

**MITRE:** T1562 (Impair Defenses), T1595 (Active Scanning)
**Agent:** AR, EX
**Objective:** Conduct scanning and reconnaissance without triggering IDS/IPS signatures or alert
thresholds. Apply timing, decoys, and packet manipulation to reduce detection probability.

### 3.1 Timing Templates

Nmap timing templates control probe rate, timeout, and parallelism. Slower timing generates less
traffic per unit time and is harder to detect via threshold-based alerting.

```bash
# T0 - Paranoid (1 probe every 5 minutes — extremely slow, near-impossible to detect)
sudo nmap -T0 $TARGET_IP -oN $LOOT_DIR/ids-t0.txt

# T1 - Sneaky (15 second delay between probes)
sudo nmap -T1 $TARGET_IP -oN $LOOT_DIR/ids-t1.txt

# T2 - Polite (400ms between probes — slow but not extreme)
sudo nmap -T2 $TARGET_IP -oN $LOOT_DIR/ids-t2.txt

# T3 - Normal (default, no explicit flag needed)
sudo nmap -T3 $TARGET_IP -oN $LOOT_DIR/ids-t3.txt

# Manual timing control (fine-grained)
sudo nmap --scan-delay 2s --max-scan-delay 5s $TARGET_IP -oN $LOOT_DIR/ids-manual-delay.txt

# Randomize host order to avoid sequential scan signatures
sudo nmap --randomize-hosts $TARGET_IP -oN $LOOT_DIR/ids-randomized.txt
```

**Practical guidance:**
- External assessments with active SOC: start at T2, drop to T1 if alerts are confirmed
- Stealth required: T1 or manual scan-delay of 2-5 seconds
- Never use T4/T5 when stealth matters — these generate high PPS rates

### 3.2 Decoys

Decoy scanning makes the probe appear to originate from multiple IPs simultaneously, making it
harder for defenders to identify the true source.

```bash
# Use 3 decoys plus your real IP (ME)
sudo nmap -sS -D 10.0.0.1,10.0.0.2,10.0.0.3,ME $TARGET_IP -oN $LOOT_DIR/ids-decoy.txt

# Use random decoys (RND generates random IPs)
sudo nmap -sS -D RND:5 $TARGET_IP -oN $LOOT_DIR/ids-decoy-rnd.txt

# Use 10 random decoys
sudo nmap -sS -D RND:10 $TARGET_IP -oN $LOOT_DIR/ids-decoy-rnd10.txt

# Decoys with source port and fragmentation
sudo nmap -sS -D RND:5 -g 53 -f $TARGET_IP -oN $LOOT_DIR/ids-decoy-combined.txt
```

**Note:** Decoys must be live hosts or the packets will be dropped at routers. RND generates
random IPs that may not be routable — use known-live IPs from network scans for reliable decoys.

### 3.3 Zombie / Idle Scan

The idle scan is the stealthiest TCP port scanning technique. It routes probes through an "idle"
host (zombie) whose IP ID increments predictably. The attacker's IP never appears in the
target's connection logs.

**Prerequisites:** The zombie host must be idle (very little network activity) and use sequential
IP ID incrementation (check: `nmap -sV -O --script ipidseq $ZOMBIE_IP`).

```bash
# Step 1: Find a suitable zombie (needs predictable IP ID sequence)
sudo nmap -sV -O --script ipidseq $ZOMBIE_IP -oN $LOOT_DIR/zombie-check.txt
# Look for "Incremental" or "Broken little-endian incremental" in ipidseq output

# Step 2: Idle scan using zombie
sudo nmap -sI $ZOMBIE_IP $TARGET_IP -oN $LOOT_DIR/idle-scan.txt

# Step 3: Idle scan on specific ports
sudo nmap -sI $ZOMBIE_IP -p $PORTS $TARGET_IP -oN $LOOT_DIR/idle-scan-ports.txt

# Step 4: Idle scan with zombie port specified (if zombie filters some ports)
sudo nmap -sI $ZOMBIE_IP:80 $TARGET_IP -oN $LOOT_DIR/idle-scan-port80.txt
```

**Finding zombie candidates:**
```bash
# Scan network for hosts with sequential IP ID
sudo nmap -iL $LOOT_DIR/live-hosts.txt --script ipidseq -oN $LOOT_DIR/zombie-candidates.txt
grep -i "incremental" $LOOT_DIR/zombie-candidates.txt
```

### 3.4 Packet Manipulation with Scapy

Scapy allows crafting packets with arbitrary flags and values for IDS evasion scenarios that
nmap cannot handle directly.

```bash
# Scapy interactive — send custom SYN with unusual TCP options
python3 -c "
from scapy.all import *
pkt = IP(dst='$TARGET_IP')/TCP(dport=80, flags='S', options=[('MSS', 1460)])
resp = sr1(pkt, timeout=3, verbose=0)
if resp:
    print(f'Port 80: {resp[TCP].flags}')
"

# Send FIN/PSH/URG (Xmas) manually
python3 -c "
from scapy.all import *
pkt = IP(dst='$TARGET_IP')/TCP(dport=80, flags='FPU')
send(pkt, verbose=0)
print('Xmas probe sent')
"

# Fragment a packet manually
python3 -c "
from scapy.all import *
pkt = IP(dst='$TARGET_IP', flags='MF')/TCP(dport=80, flags='S')
frags = fragment(pkt, fragsize=8)
send(frags, verbose=0)
"
```

### 3.5 nmap Options for Evasion Combination

```bash
# Maximum evasion combination: slow timing + decoys + source port + fragmentation
sudo nmap -sS -T1 -D RND:5 -g 53 -f --data-length 150 --randomize-hosts \
  $TARGET_IP -oN $LOOT_DIR/ids-max-evasion.txt

# Spoof MAC address (requires same LAN segment)
sudo nmap -sS --spoof-mac 0 $TARGET_IP    # Random MAC
sudo nmap -sS --spoof-mac Apple $TARGET_IP # Apple vendor prefix

# IPv6 to bypass IPv4-only IDS
sudo nmap -6 -sS $TARGET_IP6 -oN $LOOT_DIR/ids-ipv6.txt
```

---

## Section 4: Rate Limiting Detection

**MITRE:** T1595 (Active Scanning)
**Agent:** AR
**Objective:** Identify when the target or upstream network device is throttling scan probes,
which causes false negatives and incomplete port maps. Adapt scan rate accordingly.

### 4.1 Signs of Rate Limiting

```bash
# Baseline test — scan 100 ports at normal rate
sudo nmap -sS -p 1-100 --stats-every 5s $TARGET_IP 2>&1 | grep -E "rate|done|timing"

# Signs of throttling in nmap output:
# - "Reducing parallelism to 1"
# - "Increasing send delay for $TARGET_IP"
# - Scan rate dropping mid-scan (watch --stats-every output)
# - Same ports consistently showing "filtered" in repeated scans

# Rate probe test — send 1000 probes at increasing rates and watch for drops
sudo nmap -sS --min-rate 100 --max-rate 100 -p 1-1000 --stats-every 2s $TARGET_IP
sudo nmap -sS --min-rate 500 --max-rate 500 -p 1-1000 --stats-every 2s $TARGET_IP
sudo nmap -sS --min-rate 1000 --max-rate 1000 -p 1-1000 --stats-every 2s $TARGET_IP
# Compare: if open port count drops as rate increases, throttling is occurring
```

### 4.2 Adaptive Rate Strategies

```bash
# Conservative rate — less likely to trigger rate limiting
sudo nmap -sS --max-rate 200 $TARGET_IP -oN $LOOT_DIR/rate-conservative.txt

# Very conservative for sensitive environments
sudo nmap -sS --max-rate 50 --scan-delay 100ms $TARGET_IP -oN $LOOT_DIR/rate-very-conservative.txt

# Naabu rate control
naabu -host $TARGET_IP -rate 200 -verify -o $LOOT_DIR/naabu-rate200.txt
naabu -host $TARGET_IP -rate 100 -verify -o $LOOT_DIR/naabu-rate100.txt

# Masscan rate reduction
sudo masscan $TARGET -p0-65535 --rate 500 -oL $LOOT_DIR/masscan-rate500.txt

# Split scan into chunks to stay under per-source rate limits
# Chunk 1: ports 1-10000
sudo nmap -sS -p 1-10000 --max-rate 200 $TARGET_IP -oN $LOOT_DIR/chunk1.txt
# Chunk 2: ports 10001-30000
sudo nmap -sS -p 10001-30000 --max-rate 200 $TARGET_IP -oN $LOOT_DIR/chunk2.txt
# Chunk 3: ports 30001-65535
sudo nmap -sS -p 30001-65535 --max-rate 200 $TARGET_IP -oN $LOOT_DIR/chunk3.txt
```

### 4.3 Detecting ICMP Rate Limiting

Many firewalls and hosts rate-limit ICMP replies. This manifests as hosts appearing unreachable
during host discovery when they are actually live.

```bash
# Slow ICMP sweep to detect rate-limited hosts
sudo nmap -sn -PE --scan-delay 500ms $TARGET -oN $LOOT_DIR/icmp-rate-slow.txt

# Compare with TCP probe sweep
sudo nmap -sn -PS80,443 $TARGET -oN $LOOT_DIR/tcp-probe-hosts.txt

# Hosts in tcp-probe but not icmp-rate indicate ICMP rate limiting
diff <(grep "Nmap scan report" $LOOT_DIR/icmp-rate-slow.txt | awk '{print $NF}' | sort) \
     <(grep "Nmap scan report" $LOOT_DIR/tcp-probe-hosts.txt | awk '{print $NF}' | sort)
```

---

## Section 5: Tarpit Detection

**MITRE:** T1595 (Active Scanning — defended environment)
**Agent:** AR
**Objective:** Identify hosts or ports that implement TCP tarpits (LaBrea-style) to trap
scanners. Tarpits respond to SYN with SYN/ACK but then use TCP ZeroWindow to hold the
connection indefinitely, wasting scanner resources.

### 5.1 Identifying Tarpit Behavior

```bash
# Sign 1: Nmap scan takes extremely long on a specific host
# Sign 2: All ports show "open" on a host (every SYN gets SYN/ACK)
# Sign 3: TCP handshake completes but then hangs with Window=0

# Test for tarpit: connect and check window size
sudo hping3 -S -p 80 $TARGET_IP -c 3 -V
# Look for: flags=SA (SYN/ACK) followed by win=0 or very small window

# Connect scan with timeout to detect tarpit
nc -w 2 -zv $TARGET_IP 80 2>&1
# Tarpit: connection "succeeds" but then nothing happens

# Python tarpit probe
python3 -c "
import socket, time
s = socket.socket()
s.settimeout(2)
try:
    s.connect(('$TARGET_IP', 80))
    print('Connected — check window size')
    time.sleep(2)
    s.send(b'GET / HTTP/1.0\r\n\r\n')
    data = s.recv(100)
    print(f'Got data: {data[:50]}')
except socket.timeout:
    print('Timeout after connect — possible tarpit')
except Exception as e:
    print(f'Error: {e}')
finally:
    s.close()
"
```

### 5.2 Tarpit Handling Strategies

```bash
# Strategy 1: Reduce max connect time aggressively
sudo nmap -sT --host-timeout 5s --max-rtt-timeout 500ms $TARGET_IP -oN $LOOT_DIR/anti-tarpit.txt

# Strategy 2: Use SYN scan (half-open) instead of Connect scan
# SYN scan sends RST after SYN/ACK — does not get trapped
sudo nmap -sS $TARGET_IP -oN $LOOT_DIR/syn-scan-tarpit.txt

# Strategy 3: Limit max retries
sudo nmap -sS --max-retries 1 $TARGET_IP -oN $LOOT_DIR/no-retry.txt

# Strategy 4: Aggressive timeouts
sudo nmap -sS --max-rtt-timeout 200ms --initial-rtt-timeout 100ms \
  --max-retries 1 $TARGET_IP -oN $LOOT_DIR/fast-timeout.txt

# Strategy 5: naabu (ignores tarpit by design — uses SYN by default)
naabu -host $TARGET_IP -timeout 2000 -retries 1 -o $LOOT_DIR/naabu-anti-tarpit.txt
```

### 5.3 Known Tarpit IPs

```bash
# Build tarpit list during scan — flag hosts where all ports return SYN/ACK
# (LaBrea tarpits respond to everything)
# If a host shows 65000+ open ports, it's a tarpit

# Check nmap for suspicious all-open responses
grep -c "open" $LOOT_DIR/tcp-syn-full.txt | awk -F: '{if($2>1000) print "TARPIT SUSPECTED: "$1}'
```

---

## Section 6: Alternative Discovery Techniques

**MITRE:** T1595.001 (Active Scanning: Scanning IP Blocks)
**Agent:** AR
**Objective:** Discover hosts that appear unreachable via standard TCP/ICMP probes due to
firewall rules, host-based filtering, or protocol restrictions.

### 6.1 IPv6 Discovery

Many environments have IPv6 enabled but unmonitored. IPv6 hosts may respond when IPv4 is blocked.

```bash
# Discover IPv6 hosts on local link (link-local addresses)
sudo nmap -6 -sn -PE ff02::1 -oN $LOOT_DIR/ipv6-local.txt

# Ping6 to all-nodes multicast
ping6 -c 3 ff02::1%$IFACE

# Discover IPv6 addresses from DNS
nmap --script=dns-ip6-arpa-scan --script-args='dns-ip6-arpa-scan.prefix=2001:db8::/32' \
  -6 -oN $LOOT_DIR/ipv6-dns.txt

# Scan IPv6 address of a known host
sudo nmap -6 -sS -sV $TARGET_IP -oN $LOOT_DIR/ipv6-scan.txt

# Use naabu for IPv6
naabu -host $TARGET_IP -o $LOOT_DIR/naabu-ipv6.txt
```

### 6.2 SCTP Discovery and Scanning

SCTP is used in VoIP infrastructure (SS7 gateways), carrier networks, and some Linux kernel
services. Standard TCP scanners miss SCTP services.

```bash
# SCTP INIT scan — primary SCTP scanning method
sudo nmap -sY $TARGET_IP -oN $LOOT_DIR/sctp-init.txt

# SCTP COOKIE ECHO scan — alternative when INIT is blocked
sudo nmap -sZ $TARGET_IP -oN $LOOT_DIR/sctp-cookie.txt

# SCTP on common ports
sudo nmap -sY -p 36422,36412,2905,2904,9900 $TARGET_IP -oN $LOOT_DIR/sctp-ports.txt

# hping3 SCTP probe
sudo hping3 --sctp -p 36422 $TARGET_IP -c 5
```

### 6.3 When Hosts Appear Down But Aren't

```bash
# Host appears down — try alternative probes before giving up

# Step 1: TCP SYN to common ports (bypasses ICMP block)
sudo nmap -sn -PS22,80,443,3389,8080 $TARGET_IP

# Step 2: TCP ACK probe (catches hosts that only respond to established connections)
sudo nmap -sn -PA80,443 $TARGET_IP

# Step 3: UDP probe (catches SNMP/DNS-only hosts)
sudo nmap -sn -PU53,161,1194 $TARGET_IP

# Step 4: SCTP probe
sudo nmap -sn -PY80 $TARGET_IP

# Step 5: Force skip host discovery and scan anyway
sudo nmap -sS -Pn $TARGET_IP -oN $LOOT_DIR/pn-scan.txt

# Step 6: hping3 with different TTL values (bypass TTL-based filtering)
sudo hping3 -S -p 80 -T 64 $TARGET_IP -c 3
sudo hping3 -S -p 80 -T 128 $TARGET_IP -c 3
sudo hping3 -S -p 80 -T 255 $TARGET_IP -c 3
```

---

## Section 7: CDN and Load Balancer Detection

**MITRE:** T1592 (Gather Victim Host Information)
**Agent:** AR
**Objective:** Identify whether the target is behind a CDN or load balancer, and discover the
real origin server IP. Penetration testing should target origin servers, not CDN edge nodes.

### 7.1 Detecting CDN Presence

```bash
# Step 1: Check if IPs from DNS resolve to CDN ranges
host $TARGET_IP
nslookup $TARGET_IP

# Step 2: Reverse DNS lookup (CDN nodes often have CDN-branded hostnames)
host $TARGET_IP
dig -x $TARGET_IP +short

# Step 3: HTTP response headers (CDNs inject identifying headers)
curl -s -I https://$TARGET_IP/ --insecure | grep -i -E "cf-ray|x-cache|x-amz|x-cdn|via|server"

# Step 4: ASN lookup to identify CDN ranges
curl -s "https://ipinfo.io/$TARGET_IP/org" 2>/dev/null
# Cloudflare: AS13335, AWS CloudFront: AS16509, Akamai: AS20940, Fastly: AS54113

# Step 5: Nmap CDN detection scripts
sudo nmap --script=http-headers,http-server-header -p 80,443 $TARGET_IP
```

### 7.2 Origin Server Discovery

```bash
# Method 1: SSL certificate SAN enumeration (origin IP in cert)
openssl s_client -connect $TARGET_IP:443 -servername $TARGET_IP 2>/dev/null | \
  openssl x509 -noout -text | grep -A 2 "Subject Alternative Name"

# Method 2: Historical DNS records (origin IP before CDN migration)
# Use online tools or local DNS history
dig $TARGET_IP any +short
host -a $TARGET_IP

# Method 3: Common origin subdomain patterns
for sub in origin direct backend api-origin www-origin staging; do
  host $sub.$TARGET_IP 2>/dev/null | grep "has address"
done

# Method 4: SPF record may contain origin IP
dig TXT $TARGET_IP | grep "spf1"

# Method 5: httpx probe on origin IP candidates
echo $TARGET_IP | httpx -title -status-code -web-server -vhost $TARGET_IP \
  -o $LOOT_DIR/origin-probe.txt

# Method 6: Virtual host brute-force on origin IP
# Try connecting directly to IP with Host header set to target domain
curl -H "Host: target.com" http://$TARGET_IP/ -s -o /dev/null -w "%{http_code}"
```

### 7.3 Load Balancer Detection

```bash
# Method 1: Multiple requests — watch for different response headers or server IDs
for i in {1..5}; do
  curl -s -I http://$TARGET_IP/ | grep -i "x-node\|x-backend\|x-server\|set-cookie"
done

# Method 2: TTL variation (different backend servers have different TTLs)
for i in {1..5}; do
  ping -c 1 $TARGET_IP | grep ttl
done
# Multiple TTL values = load balanced (different backends)

# Method 3: Nmap SSL cert variation (different certs = different backends)
for i in {1..3}; do
  echo | openssl s_client -connect $TARGET_IP:443 2>/dev/null | openssl x509 -noout -serial
done

# Method 4: hping3 IP ID tracking across requests
sudo hping3 -S -p 80 -c 10 $TARGET_IP | grep "id="
# Consistent IP ID increments = single host; jumbled values = load balanced pool
```

---

## Section 8: NAT Detection

**MITRE:** T1592.002 (Gather Victim Host Information: Software)
**Agent:** AR
**Objective:** Detect NAT gateways to understand actual network topology, identify hidden hosts
behind the NAT, and adjust scanning strategy.

### 8.1 OS Fingerprint Inconsistency Detection

If multiple hosts behind NAT share the same public IP, OS fingerprints may be inconsistent across
scans.

```bash
# Multiple OS fingerprint probes at intervals
sudo nmap -O $TARGET_IP -oN $LOOT_DIR/nat-os-probe1.txt
sleep 30
sudo nmap -O $TARGET_IP -oN $LOOT_DIR/nat-os-probe2.txt
sleep 30
sudo nmap -O $TARGET_IP -oN $LOOT_DIR/nat-os-probe3.txt

# Compare OS detection results
grep "OS details\|Running:" $LOOT_DIR/nat-os-probe*.txt
# Different OS across probes = NAT with multiple hosts
```

### 8.2 TCP Timestamp Analysis

NAT devices sometimes translate packets from multiple internal hosts. TCP timestamps from
different hosts will show different clock offsets and rates.

```bash
# hping3 timestamp probe — compare across connection attempts
sudo hping3 -S -p 80 --tcp-timestamp $TARGET_IP -c 10

# Nmap timestamp script
sudo nmap --script=clock-skew $TARGET_IP -oN $LOOT_DIR/nat-timestamp.txt

# tcptrace / wireshark analysis on captured packets
# Look for non-monotonic timestamp sequences
tcpdump -i $IFACE -w $LOOT_DIR/nat-capture.pcap host $TARGET_IP &
sudo nmap -sS -p 80,443 $TARGET_IP
kill %1
tcpdump -r $LOOT_DIR/nat-capture.pcap -nn | grep "seq\|ack" | head -30
```

### 8.3 IP ID Sequence Analysis

Different hosts behind NAT generate different IP ID sequences. Repeated probes that show
non-sequential IP IDs indicate NAT with multiple backends.

```bash
# hping3 IP ID sequence check
sudo hping3 -S -p 80 -c 20 --id 0 $TARGET_IP | grep "id="
# Sequential IDs = single host; multiple sequences interleaved = multiple hosts behind NAT

# Nmap IP ID sequence probe
sudo nmap --script=ipidseq $TARGET_IP -oN $LOOT_DIR/nat-ipid.txt

# Scapy IP ID tracking
python3 -c "
from scapy.all import *
results = []
for i in range(10):
    pkt = IP(dst='$TARGET_IP')/TCP(dport=80, flags='S')
    resp = sr1(pkt, timeout=2, verbose=0)
    if resp:
        results.append(resp.id)
        print(f'Probe {i+1}: IP ID = {resp.id}')
if len(set(results)) > 1:
    deltas = [results[i+1]-results[i] for i in range(len(results)-1)]
    print(f'Deltas: {deltas}')
    print('WARNING: Non-sequential IPs may indicate NAT with multiple hosts' if max(deltas) > 10 else 'Sequential — single host likely')
"
```

### 8.4 TTL Hop Count Analysis

Different internal hosts behind NAT may have different actual TTLs to the attacker, suggesting
different physical paths (even if they share a public IP).

```bash
# Traceroute to detect hop count consistency
traceroute -T -p 80 $TARGET_IP | tail -5

# Multiple traceroutes — compare hop counts
for i in {1..5}; do
  traceroute -T -p 80 $TARGET_IP 2>/dev/null | tail -3
  sleep 5
done

# hping3 traceroute
sudo hping3 --traceroute -S -p 80 $TARGET_IP

# Compare TTL values across probes
for i in {1..5}; do
  ping -c 1 $TARGET_IP | grep "ttl="
  sleep 5
done
# TTL variation across probes suggests different hosts responding (NAT pool)
```

---

## Evasion Decision Matrix

| Situation | Primary Technique | Command |
|---|---|---|
| All ports filtered on ACK scan | Stateful firewall present | Use SYN scan with source port `-g 53` |
| SYN scan triggering IDS alerts | Slow timing | `-T1 --scan-delay 2s` |
| Scan rate dropping mid-scan | Rate limiting | `--max-rate 200` |
| All ports show open | Tarpit | Use `-sS` (SYN), `--max-rtt-timeout 200ms` |
| Host appears down (ICMP blocked) | Alternative probes | `-Pn -sS` or `-PS22,80,443` |
| Need to hide scanner identity | Idle/Zombie scan | `-sI $ZOMBIE_IP $TARGET_IP` |
| IPv4 scan gives no results | IPv6 possible | `-6 -sS` on IPv6 address |
| Target behind CDN | Origin discovery | SSL cert SAN, historical DNS, subdomain patterns |
| Inconsistent port results | NAT detection | OS fingerprint comparison, IP ID analysis |

---

## Tool Quick Reference

| Tool | Primary Use | Install |
|---|---|---|
| `nmap` | Primary scanner, OS/service detection, NSE | Pre-installed Kali |
| `hping3` | Packet crafting, manual probes, TTL/IP ID analysis | `apt install hping3` |
| `masscan` | High-speed port scanning | Pre-installed Kali |
| `naabu` | Fast port discovery with verification | `go install github.com/projectdiscovery/naabu/v2/cmd/naabu@latest` |
| `scapy` | Custom packet crafting, Python automation | `pip3 install scapy` |
| `p0f` | Passive OS fingerprinting | `apt install p0f` |
| `httpx` | HTTP/HTTPS probing, header analysis | `go install github.com/projectdiscovery/httpx/cmd/httpx@latest` |
| `netcat` | Banner grabbing, port connectivity tests | Pre-installed Kali |
| `openssl` | TLS cert inspection, SSL banner grab | Pre-installed Kali |
