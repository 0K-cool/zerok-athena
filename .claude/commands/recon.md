# Execute Passive Reconnaissance

Conduct passive OSINT (Open Source Intelligence) gathering for: **$ARGUMENTS**

## 🤖 Multi-Agent Architecture Integration

**This command dispatches the Passive OSINT Agent** (PTES Phase 2a) - Zero target contact intelligence gathering.

**What the Passive OSINT Agent does:**
- ✅ Certificate Transparency log mining (crt.sh)
- ✅ Passive Amass subdomain enumeration
- ✅ Email harvesting (theHarvester, Hunter.io)
- ✅ Shodan organization search (passive database queries)
- ✅ Social media reconnaissance (LinkedIn, GitHub, Twitter)
- ✅ Google dorking for exposed data
- ✅ WHOIS and DNS registry lookups
- ✅ Breach database searches (HaveIBeenPwned)

**CRITICAL CONSTRAINT**: This agent makes ZERO contact with target systems. All intelligence comes from:
- Public databases (Shodan, Censys, crt.sh)
- Search engines (Google, Bing)
- Social media (public profiles only)
- Certificate logs
- WHOIS registries

**See**: `.claude/agents/passive-osint-agent.md`

---

## Safety Protocols

**ALLOWED** (Passive Intelligence):
- ✅ Querying public databases (Shodan, Censys, crt.sh)
- ✅ Search engine queries (Google, Bing)
- ✅ Social media reconnaissance (public information only)
- ✅ WHOIS and DNS registry lookups
- ✅ Certificate transparency log searches

**PROHIBITED** (Active Reconnaissance):
- ❌ DNS queries to target nameservers
- ❌ HTTP/HTTPS requests to target servers
- ❌ Port scans or ping sweeps
- ❌ Email sending to discovered addresses
- ❌ Direct contact with target infrastructure

---

## Expected Output

The Passive OSINT Agent will return:

```json
{
  "subdomains_discovered": [
    "www.example.com",
    "mail.example.com",
    "api.example.com"
  ],
  "emails_found": [
    "john.doe@example.com",
    "admin@example.com"
  ],
  "employees": [
    {"name": "John Doe", "role": "IT Manager", "source": "linkedin"}
  ],
  "technology_stack": {
    "web_server": "nginx 1.18.0",
    "cloud_provider": "AWS",
    "frameworks": ["React", "Node.js"]
  },
  "ip_ranges": ["192.0.2.0/24"],
  "exposed_assets": [
    {"ip": "192.0.2.10", "port": 443, "service": "nginx"}
  ],
  "exposed_secrets": [
    {"repo": "company/old-website", "file": ".env", "contains": "API_KEY"}
  ]
}
```

---

## Integration with Pentest Monitor

All OSINT activities are automatically logged:

```python
# Logged activities:
- Certificate transparency log search
- Amass passive enumeration
- theHarvester email collection
- Shodan organization search
- GitHub secret scanning
- Google dorking queries

# Dashboard shows:
- Subdomains discovered
- Email addresses found
- Technology stack identified
- Exposed secrets flagged
```

---

## Evidence Collection

All reconnaissance data is saved to:
```
02-reconnaissance/
├── osint/
│   ├── subdomains.txt (from crt.sh, Amass)
│   ├── emails.txt (from theHarvester, Hunter.io)
│   ├── employees.txt (from LinkedIn)
│   ├── technology-stack.md (from job postings, Shodan)
│   └── exposed-secrets.md (from GitHub, Pastebin)
├── shodan-results.json
├── amass-passive.txt
└── osint-summary.md
```

---

## Next Steps

After passive reconnaissance:
1. **Review findings** for attack surface understanding
2. **Validate scope** - Ensure all discovered assets are authorized
3. **Execute `/scan`** - Proceed to active reconnaissance with discovered targets
4. **Prioritize targets** - Focus on high-value assets (admin panels, APIs, databases)

---

**Reconnaissance Status**: PASSIVE ONLY (Zero Target Contact)
**Phase**: PTES Phase 2a (Intelligence Gathering - Passive)
**Agent**: Passive OSINT Specialist
**Safety Level**: MAXIMUM (No target contact)
**Target**: $ARGUMENTS
