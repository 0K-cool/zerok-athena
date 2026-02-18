# ATHENA Tool Gap Analysis: RedAmon + Kali Linux Book

**Date:** February 17, 2026
**Purpose:** Identify tools ATHENA should add based on RedAmon's architecture and the Ultimate Kali Linux Book (3rd Edition, indexed in RAG)

---

## Current ATHENA Tool Inventory

### Kali MCP Tools (Active)
| Tool | Category | Status |
|------|----------|--------|
| Nmap | Network scanning, service detection | Active |
| Gobuster | Directory/DNS brute-forcing | Active |
| Dirb | Web content scanner | Active |
| Nikto | Web vulnerability scanner | Active |
| WPScan | WordPress scanner | Active |
| SQLmap | SQL injection testing | Active |
| Metasploit | Exploitation framework | Active |
| Hydra | Password brute-forcing | Active |
| John the Ripper | Password hash cracking | Active |
| Enum4linux | SMB/Samba enumeration | Active |

### Other Integrations (Active)
| Tool | Category | Status |
|------|----------|--------|
| Playwright | SPA/modern web app testing | Active |
| OSINT API Wrapper | Shodan, Censys, Hunter.io, GitHub, VirusTotal | Active |
| EyeWitness | Website profiling/screenshots | Referenced in Kali book (not integrated) |
| ATHENA Monitor | Engagement tracking dashboard | Active |

---

## RedAmon Tool Inventory (Reference)

### Reconnaissance
| Tool | Purpose | In ATHENA? |
|------|---------|------------|
| **Naabu** (ProjectDiscovery) | Fast port scanning (SYN/CONNECT) | NO |
| **Nuclei** (ProjectDiscovery) | Vuln scanning, 9,000+ templates, DAST fuzzing | NO |
| **Httpx** (ProjectDiscovery) | HTTP probing, TLS/JARM fingerprinting | NO |
| **Katana** (ProjectDiscovery) | Web crawler, JS rendering, depth 1-10 | NO |
| **GAU** (tomnomnom) | Passive URL discovery (Wayback, CommonCrawl, OTX, URLScan) | NO |
| **Kiterunner** (Assetnote) | API endpoint brute-forcing (Swagger wordlists) | NO |
| **Knockpy** | Subdomain brute-forcing | NO |
| **Wappalyzer** | Technology fingerprinting (6,000+ signatures) | NO |
| crt.sh / HackerTarget | Certificate transparency subdomain enum | Partial (OSINT wrapper) |
| Shodan InternetDB | Passive port data | Partial (OSINT wrapper) |

### Vulnerability Assessment
| Tool | Purpose | In ATHENA? |
|------|---------|------------|
| **GVM/OpenVAS** | 170,000+ NVTs, protocol-level probes | NO |
| Nmap NSE | Vulnerability detection scripts | YES (via nmap) |

### Exploitation
| Tool | Purpose | In ATHENA? |
|------|---------|------------|
| Metasploit | Full exploitation framework | YES |
| Curl | HTTP probing, API testing | YES (via Bash) |
| Nmap | Fallback scanning, NSE scripts | YES |

### Intelligence
| Tool | Purpose | In ATHENA? |
|------|---------|------------|
| **Neo4j** | Graph database for attack surface intelligence | NO |
| **MITRE CVE/CAPEC/CWE DB** | Offline vuln correlation | NO (manual lookup) |
| **GitHub Secret Hunter** | Repo secret scanning (40+ patterns) | Partial (OSINT wrapper) |
| Tavily | Web search for exploit intelligence | NO (use Vex instead) |

---

## Kali Linux Book Additional Tools (from RAG)

| Tool | Chapter | Purpose | In ATHENA? |
|------|---------|---------|------------|
| **EyeWitness** | Ch. 6 | Website profiling, automated screenshots | NO |
| **S3Scanner** | Ch. 6 | AWS S3 bucket enumeration | NO |
| **WhatWeb** | Ch. 7 | Web technology fingerprinting | NO |
| **GVM/OpenVAS** | Ch. 7 | Enterprise vulnerability scanning | NO |
| **WMAP** (Metasploit) | Ch. 7 | Web vulnerability scanning via MSF | YES (via Metasploit) |
| **PacketWhisper** | Ch. 10 | Data exfiltration via DNS | NO (post-exploit) |
| **Meterpreter** | Ch. 10 | Post-exploitation framework | YES |
| **xFreeRDP** | Ch. 10 | Remote desktop for pass-the-hash | NO |
| **FreeRADIUS** | Ch. 3 | RADIUS for wireless testing | NO (wireless scope) |
| **Impacket** | Referenced | SMB/AD attack tools | NO |
| **CrackMapExec** | Referenced | AD enumeration/exploitation | NO |
| **BloodHound** | Referenced | AD attack path visualization | NO |

---

## Recommended Additions (Prioritized)

### Tier 1: HIGH Priority (Install on Mini-PC Day 1)

These fill the biggest gaps and integrate with ATHENA's existing workflow.

#### 1. ProjectDiscovery Suite
**Install:** `go install -v github.com/projectdiscovery/{naabu,nuclei,httpx,katana}/v2/cmd/...@latest`

| Tool | Why | ATHENA Integration |
|------|-----|-------------------|
| **Naabu** | 10-100x faster port scanning than Nmap for discovery. Use Naabu for breadth, Nmap for depth. | New `/scan-fast` command. Feed Naabu results into Nmap `-sV` for service fingerprinting. |
| **Nuclei** | 9,000+ vulnerability templates. Covers CVEs, misconfigs, exposures, DAST (XSS, SQLi, RCE, LFI, SSRF, SSTI). Auto-updates templates. | New `/vuln-scan` command. Replaces/supplements Nikto for modern targets. Templates auto-update via `nuclei -ut`. |
| **Httpx** | HTTP probing with tech detection, TLS info, JARM fingerprinting, status codes, titles. Filters live hosts from Naabu output. | Pipeline: `naabu → httpx → nuclei`. Httpx filters alive web services before deep scanning. |
| **Katana** | Web crawler with JS rendering. Discovers endpoints Gobuster/Dirb miss on modern SPAs. Configurable depth. | Supplement to Playwright for URL/endpoint discovery. Feed discovered URLs to Nuclei. |

**Combined recon pipeline:**
```
Naabu (ports) → Httpx (alive web) → Katana (crawl) → Nuclei (vuln scan)
                                   → Nmap -sV (service versions on Naabu ports)
```

**Why this matters:** This is the modern recon pipeline that RedAmon uses. It's significantly faster and more comprehensive than Nmap-only scanning for large internal networks.

#### 2. GAU (GetAllUrls)
**Install:** `go install github.com/lc/gau/v2/cmd/gau@latest`

- Passive URL discovery from Wayback Machine, Common Crawl, AlienVault OTX, URLScan.io
- Zero packets sent to target — pure passive recon
- Feed discovered URLs into Nuclei for vulnerability scanning
- **ATHENA integration:** Add to `/scan` passive phase before active scanning

#### 3. GVM/OpenVAS
**Install:** `sudo apt install gvm && sudo gvm-setup` (on Kali)

- 170,000+ Network Vulnerability Tests (NVTs)
- Protocol-level probes (SSH ciphers, SMB enumeration, TLS analysis)
- Enterprise-grade vulnerability assessment
- 7 scan profiles from quick host discovery to deep comprehensive
- **ATHENA integration:** New `/vuln-assess` command for comprehensive assessments
- **Note:** First run requires ~30 min feed sync. Plan ahead.

#### 4. EyeWitness
**Install:** Pre-installed on Kali or `apt install eyewitness`

- Automated website screenshots + tech fingerprinting
- Processes Nmap/Naabu output directly
- Generates HTML report with all discovered web services
- Referenced in Kali book Ch. 6 (Active Reconnaissance)
- **ATHENA integration:** Auto-run after Naabu/Httpx to generate visual recon report

---

### Tier 2: MEDIUM Priority (Install Week 1)

#### 5. Kiterunner
**Install:** Download from https://github.com/assetnote/kiterunner/releases

- API endpoint discovery using Swagger/OpenAPI-derived wordlists (20K or 100K routes)
- Finds REST API endpoints that Gobuster/Dirb miss
- Essential for modern API-first applications
- **ATHENA integration:** New option in `/scan` for API-focused targets

#### 6. Wappalyzer CLI
**Install:** `npm install -g wappalyzer`

- Technology fingerprinting (6,000+ signatures)
- Identifies frameworks, CMS, server software, JS libraries
- More comprehensive than WhatWeb
- **ATHENA integration:** Run early in recon to inform scanning strategy

#### 7. WhatWeb
**Install:** Pre-installed on Kali

- Web technology fingerprinting (lighter than Wappalyzer)
- Referenced in Kali book Ch. 7
- Quick profiling before deep scanning
- **ATHENA integration:** Part of initial target profiling

#### 8. Knockpy
**Install:** `pip install knockpy`

- Active subdomain brute-forcing
- Complements passive subdomain enum from crt.sh/OSINT
- **ATHENA integration:** Add to subdomain discovery workflow

#### 9. S3Scanner
**Install:** `pip install s3scanner`

- AWS S3 bucket enumeration and permission testing
- Referenced in Kali book Ch. 6
- Finds misconfigured public buckets
- **ATHENA integration:** Add to cloud pentest workflow (`/cloud-pentest`)

---

### Tier 3: LOW Priority (Install When Needed)

#### 10. Active Directory Tools (for internal pentests)

| Tool | Purpose | Install |
|------|---------|---------|
| **BloodHound** | AD attack path visualization | `apt install bloodhound` |
| **CrackMapExec / NetExec** | AD enumeration, credential testing | `apt install crackmapexec` |
| **Impacket** | SMB/AD protocol tools (secretsdump, psexec, wmiexec) | `pip install impacket` |
| **Responder** | LLMNR/NBT-NS/MDNS poisoning | Pre-installed on Kali |
| **Kerbrute** | Kerberos brute-force/enumeration | Go binary |

**ATHENA integration:** New `/scan-ad` command for Active Directory engagements. The Kali book covers AD lab setup extensively (Ch. 3).

#### 11. Neo4j (Graph Intelligence)
- See separate proposal: `ATHENA-GRAPH-INTELLIGENCE-PROPOSAL.md`
- Transforms flat SQLite tracking into graph-based attack surface intelligence
- Enables queries like "show all paths from DMZ to domain admin"

#### 12. MITRE CVE/CAPEC/CWE Offline Database
- RedAmon maintains a local mirror with 24-hour TTL auto-updates
- CVE-to-CAPEC correlation for attack pattern mapping
- **ATHENA integration:** Enrich findings with CAPEC attack patterns automatically

---

## Updated Recon Pipeline (After Additions)

```
Phase 1: Passive Recon (zero packets)
├── OSINT API Wrapper (Shodan, Censys, Hunter.io, VirusTotal)
├── GAU (Wayback, CommonCrawl, OTX, URLScan)
├── crt.sh (Certificate Transparency subdomains)
└── S3Scanner (if cloud in scope)

Phase 2: Active Discovery (fast sweep)
├── Naabu (fast port discovery across ranges)
├── Httpx (filter alive web services, tech fingerprinting)
├── Knockpy (subdomain brute-forcing)
├── EyeWitness (visual recon report)
└── Wappalyzer/WhatWeb (technology profiling)

Phase 3: Deep Scanning (targeted)
├── Nmap -sV -sC (service versions + NSE on Naabu ports)
├── Katana (web crawling with JS rendering)
├── Nuclei (9,000+ vuln templates on discovered URLs)
├── Nikto (web server vulns)
├── Gobuster/Dirb (directory brute-forcing)
├── WPScan (if WordPress detected)
├── SQLmap (if injection points found)
└── Kiterunner (API endpoint discovery)

Phase 4: Vulnerability Assessment (comprehensive)
├── GVM/OpenVAS (enterprise-grade NVT scanning)
├── Nmap NSE vuln scripts
└── Metasploit auxiliary scanners (WMAP, etc.)

Phase 5: Exploitation (HITL approved)
├── Metasploit (module-based exploitation)
├── SQLmap (SQL injection exploitation)
├── Hydra (credential brute-forcing)
└── Playwright (authenticated web app testing)

Phase 6: Post-Exploitation (if authorized)
├── Meterpreter (session management)
├── Impacket (AD protocol attacks)
├── CrackMapExec (lateral movement)
├── BloodHound (attack path visualization)
└── John the Ripper (hash cracking)
```

---

## Installation Script (for Mini-PC)

```bash
#!/bin/bash
# ATHENA Tool Enhancement - Install on Kali Linux mini-PC
# Run as root or with sudo

echo "[*] Updating system..."
sudo apt update && sudo apt upgrade -y

echo "[*] Installing Go (for ProjectDiscovery tools)..."
sudo apt install -y golang

echo "[*] Tier 1: ProjectDiscovery Suite..."
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest

echo "[*] Tier 1: GAU..."
go install github.com/lc/gau/v2/cmd/gau@latest

echo "[*] Tier 1: GVM/OpenVAS..."
sudo apt install -y gvm
sudo gvm-setup  # Takes ~30 minutes for feed sync

echo "[*] Tier 1: EyeWitness..."
sudo apt install -y eyewitness

echo "[*] Tier 2: Supporting tools..."
sudo apt install -y whatweb
pip install knockpy s3scanner
npm install -g wappalyzer

echo "[*] Tier 3: AD Tools..."
sudo apt install -y bloodhound crackmapexec responder
pip install impacket

echo "[*] Updating Nuclei templates..."
nuclei -ut

echo "[*] Adding Go bin to PATH..."
echo 'export PATH=$PATH:$(go env GOPATH)/bin' >> ~/.bashrc
source ~/.bashrc

echo "[+] Installation complete. Verify with:"
echo "    naabu -version"
echo "    nuclei -version"
echo "    httpx -version"
echo "    katana -version"
echo "    gau -version"
```

---

## Kali Linux MCP Server Updates Needed

To integrate these new tools with ATHENA via the Kali MCP server, new tool handlers are needed:

| New MCP Tool | Wraps | Priority |
|-------------|-------|----------|
| `naabu_scan` | Naabu port scanner | HIGH |
| `nuclei_scan` | Nuclei vulnerability scanner | HIGH |
| `httpx_probe` | Httpx HTTP probing | HIGH |
| `katana_crawl` | Katana web crawler | MEDIUM |
| `gau_discover` | GAU passive URL discovery | MEDIUM |
| `eyewitness_capture` | EyeWitness screenshots | MEDIUM |
| `gvm_scan` | OpenVAS vulnerability scan | MEDIUM |
| `kiterunner_scan` | API endpoint discovery | LOW |
| `bloodhound_collect` | AD data collection | LOW |

These would be added as new endpoints in the Kali MCP server running on the mini-PC.

---

## Summary

| Category | Current Tools | After Enhancement |
|----------|--------------|-------------------|
| Port Scanning | 1 (Nmap) | 2 (+Naabu) |
| Web Scanning | 4 (Gobuster, Dirb, Nikto, WPScan) | 7 (+Nuclei, Katana, Kiterunner) |
| Vuln Assessment | 1 (Nmap NSE) | 3 (+GVM/OpenVAS, Nuclei) |
| Recon/OSINT | 1 (OSINT wrapper) | 6 (+GAU, EyeWitness, Wappalyzer, WhatWeb, Knockpy) |
| Exploitation | 3 (Metasploit, SQLmap, Hydra) | 3 (unchanged) |
| Post-Exploitation | 2 (Meterpreter, John) | 6 (+Impacket, CrackMapExec, BloodHound, Responder) |
| Cloud | 1 (/cloud-pentest) | 2 (+S3Scanner) |
| Web App (SPA) | 1 (Playwright) | 1 (unchanged) |
| Intelligence | 1 (SQLite tracker) | 3 (+Neo4j, MITRE offline DB) |
| **Total** | **~15 tools** | **~33 tools** |

---

**Next Steps:**
1. Set up mini-PC with Kali Linux + ZeroTier (see MINI-PC-KALI-ZEROTIER-SETUP.md)
2. Run installation script for Tier 1 tools
3. Update Kali MCP server with new tool handlers
4. Create new ATHENA slash commands (`/scan-fast`, `/vuln-scan`, `/vuln-assess`, `/scan-ad`)
5. Implement Neo4j graph intelligence (see ATHENA-GRAPH-INTELLIGENCE-PROPOSAL.md)

---

**References:**
- RedAmon GitHub: https://github.com/samugit83/redamon
- ProjectDiscovery: https://projectdiscovery.io
- Ultimate Kali Linux Book (3rd Edition) - indexed in Vex RAG
- ATHENA CLAUDE.md and README.md
