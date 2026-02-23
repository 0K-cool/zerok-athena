# Scope & Rules of Engagement

## Engagement: DryRun_2026-02-19_WebApp
**Date**: 2026-02-19
**Authorization**: Internal test target — authorized for security assessment

---

## In-Scope Assets

| Asset | Type | Notes |
|-------|------|-------|
| 10.1.1.25 | IPv4 Host | Vulnerable web application (local test target) |

**Ports/Services**: All ports and services on 10.1.1.25 are in scope.
**Web Applications**: All web applications hosted on 10.1.1.25 are in scope.

---

## Out-of-Scope Assets

- **All IP addresses other than 10.1.1.25** — including 10.1.1.0/24 subnet hosts, except 10.1.1.25
- All external/internet-facing systems
- Any cloud infrastructure not hosted at 10.1.1.25
- Third-party services and APIs

**Note**: The Kali external backend at 10.1.1.13 is the testing platform — it is NOT a target.

---

## Rules of Engagement (RoE)

### Approved Testing Activities
- Port scanning and service enumeration against 10.1.1.25
- Web application vulnerability scanning (Nikto, Gobuster, Nuclei, etc.)
- Non-destructive SQL injection testing (read-only queries only)
- XSS testing with benign alert-based payloads
- Authentication testing with safe POC (immediate logout after demonstration)
- Directory brute-forcing and content discovery
- Technology fingerprinting and OSINT

### Prohibited Activities
- Data exfiltration of any kind from 10.1.1.25
- Destructive exploits (file deletion, data modification, crashes)
- Denial of Service or resource exhaustion attacks
- Lateral movement to any other host
- Installing backdoors, webshells (except benign phpinfo() — delete after)
- Testing any host other than 10.1.1.25

### Testing Constraints
- **Rate Limiting**: Nmap `-T4`, Gobuster max 20 threads
- **Timing**: No time window restrictions (internal lab environment)
- **Monitoring**: Stop immediately if service disruption is detected
- **Evidence**: Screenshot and document all findings

### Safe POC Guidelines
| Vulnerability Type | Safe Payload |
|--------------------|-------------|
| SQL Injection | `SELECT @@version`, `SELECT database()` |
| XSS | `<script>alert('ATHENA-XSS-POC')</script>` |
| RCE | `whoami`, `id`, `hostname` |
| File Upload | phpinfo() or test.txt (delete after) |
| Auth Bypass | Log out immediately after confirming access |

---

## Emergency Contacts

| Role | Contact |
|------|---------|
| Engagement Lead | Internal (no real client) |
| Technical POC | Internal (no real client) |

---

## Authorization Statement

This engagement is conducted against an **internal, authorized test target** (10.1.1.25) within a controlled lab environment. No real client or production systems are involved. All testing is conducted in compliance with ATHENA platform non-destructive testing policies.
