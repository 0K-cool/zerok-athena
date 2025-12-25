# Generate Penetration Test Report

Generate professional penetration testing report for: **$ARGUMENTS**

## 🤖 Multi-Agent Architecture Integration

**This command dispatches the Reporting Agent** (PTES Phase 7) - Professional report generation specialist.

**What the Reporting Agent does:**
- ✅ Aggregates all findings from Pentest Monitor database
- ✅ Generates Executive Summary (non-technical, business impact)
- ✅ Creates Technical Report (detailed vulnerability analysis)
- ✅ Builds Remediation Roadmap (prioritized by CVSS and effort)
- ✅ Compiles Evidence Package (screenshots, logs, commands)
- ✅ Produces Client Presentation Deck
- ✅ Includes Methodology Appendix (PTES phases, tools used)
- ✅ Maps findings to OWASP Top 10, MITRE ATT&CK

**See**: `.claude/agents/reporting-agent.md`

---

## Report Components

### 1. Executive Summary (5-10 pages)
**Audience**: C-suite, Board of Directors, Business Stakeholders
**Content**:
- Engagement overview and scope
- Key findings at-a-glance (count by severity)
- Overall security posture assessment
- Top 3 risks to the business (in business terms)
- Recommended immediate actions

### 2. Technical Report (50-100 pages)
**Audience**: IT Security Team, System Administrators, Developers
**Content**:
- Detailed methodology (PTES phases)
- Complete vulnerability analysis (each finding detailed)
- CVSS v3.1 scoring with vector strings
- Proof of concept with exact reproduction steps
- Evidence (screenshots, HTTP requests, logs)
- Remediation guidance with code examples
- References (CVE, CWE, OWASP)

### 3. Remediation Roadmap (Excel/CSV)
**Prioritized action plan**:
- Critical → High → Medium → Low
- Effort estimation (Low/Medium/High)
- Expected duration for each fix
- Dependencies and prerequisites
- Tracking for client progress

### 4. Evidence Package (Encrypted Archive)
**Complete evidence collection**:
- All screenshots (properly named and organized)
- Tool outputs (Nmap XML, Nikto logs, etc.)
- Command history (complete repeatability)
- HTTP request/response logs
- Video recordings (if complex exploits)

### 5. Presentation Deck (PowerPoint)
**Client briefing materials**:
- High-level findings summary
- Business impact visualization
- Attack scenario diagrams
- Remediation timeline
- Q&A discussion points

---

## Report Quality Standards

**Writing Guidelines**:
- ✅ Clear, professional language
- ✅ Non-technical terms in executive summary
- ✅ Detailed technical analysis for IT teams
- ✅ Actionable remediation (not generic advice)
- ✅ Complete reproducibility (client can verify findings)

**Required Elements**:
- ✅ CVSS score for every vulnerability
- ✅ Screenshots for every finding
- ✅ Step-by-step reproduction instructions
- ✅ Specific remediation with code examples
- ✅ Business impact explanation
- ✅ References to industry standards

---

## Output Format

The Reporting Agent generates:

```
09-reporting/final/
├── Executive_Summary_[CLIENT]_[DATE].pdf
├── Technical_Report_[CLIENT]_[DATE].pdf
├── Remediation_Roadmap_[CLIENT]_[DATE].xlsx
├── Evidence_Package_[CLIENT]_[DATE].zip.enc (encrypted)
├── Presentation_[CLIENT]_[DATE].pptx
└── SHA256SUMS.txt (integrity verification)
```

---

## Findings Summary Example

```markdown
# Penetration Test Report: ACME Corporation

## Executive Summary

### Overall Security Posture: CONCERNING

During the 15-day external penetration test of ACME Corporation's web applications and network infrastructure, our team identified **21 vulnerabilities** including **2 CRITICAL** and **5 HIGH** severity findings that pose immediate risk to business operations.

### Key Findings At-a-Glance

| Severity | Count | Business Impact |
|----------|-------|-----------------|
| Critical | 2 | Immediate exploitation, severe data breach risk |
| High | 5 | Likely exploitation, significant business impact |
| Medium | 9 | Moderate risk, defense-in-depth improvements |
| Low | 5 | Best practice recommendations |

### Top 3 Risks to the Business

1. **SQL Injection in Customer Portal (CRITICAL)**
   - **Business Impact**: Attackers could access all 50,000 customer records including PII and payment data
   - **Likelihood**: HIGH - Publicly accessible, easily exploitable
   - **Recommendation**: Immediate remediation required (3-5 days)

2. **Authentication Bypass on Admin Panel (CRITICAL)**
   - **Business Impact**: Complete control over customer accounts, billing, and system configuration
   - **Likelihood**: HIGH - Simple bypass, no authentication required
   - **Recommendation**: Disable admin panel until fixed (1-2 days)

3. **Stored XSS in Support Ticket System (HIGH)**
   - **Business Impact**: Account takeover of support staff and customers
   - **Likelihood**: MEDIUM - Requires user interaction
   - **Recommendation**: Input sanitization within 30 days
```

---

## Integration with Pentest Monitor

The Reporting Agent automatically queries the Pentest Monitor database:

```python
# Data aggregation from database:
- All findings sorted by severity
- All commands executed (for methodology section)
- All HITL approvals (for audit trail)
- Scan progress and duration
- Evidence file locations
```

Dashboard provides report generation status in real-time.

---

## Compliance Mapping

Reports include compliance framework mapping:

**PCI DSS v4.0**:
- Requirement 6.5.1 (Injection flaws) → VULN-001 SQL Injection
- Requirement 6.5.7 (XSS) → VULN-002 Stored XSS

**OWASP Top 10 2021**:
- A03:2021 Injection → 3 findings
- A01:2021 Broken Access Control → 2 findings

**MITRE ATT&CK**:
- T1190 (Exploit Public-Facing Application) → VULN-001, VULN-003
- T1078 (Valid Accounts) → VULN-005 Authentication Bypass

---

## Deliverable Checklist

- [ ] Executive Summary (PDF, 5-10 pages)
- [ ] Technical Report (PDF, 50-100 pages)
- [ ] Remediation Roadmap (Excel)
- [ ] Evidence Package (Encrypted ZIP)
- [ ] Presentation Deck (PowerPoint)
- [ ] All findings have CVSS scores
- [ ] All findings have screenshots
- [ ] All findings have remediation guidance
- [ ] Client can reproduce every finding
- [ ] Report spell-checked and proofread
- [ ] Evidence integrity verified (SHA256)

---

## Client Delivery

**Delivery Method**:
- Encrypted email (PGP) for small reports
- Secure file transfer (SFTP/portal) for large packages
- Encrypted USB drive (hand-delivered) for highly sensitive engagements
- Password via separate channel (phone/SMS)

**Post-Delivery**:
- Schedule debrief meeting with client stakeholders
- Answer technical questions
- Provide remediation support
- Schedule retest after fixes applied

---

## Next Steps

After report generation:
1. **Review with client** - Schedule presentation
2. **Answer questions** - Technical Q&A session
3. **Remediation support** - Help prioritize fixes
4. **Retest scheduling** - Validate remediation effectiveness
5. Use **`/retest`** command for post-remediation validation

---

**Report Status**: GENERATING
**Engagement**: $ARGUMENTS
**Report Date**: [Auto-populate timestamp]
**Pentester**: [Your name]
**Deliverables**: Executive Summary, Technical Report, Evidence Package
**Format**: PDF, Excel, PowerPoint
**Encryption**: AES-256

---

## Professional Standards

This report follows industry standards:
- ✅ PTES (Penetration Testing Execution Standard)
- ✅ OWASP Testing Guide methodology
- ✅ NIST SP 800-115 (Technical Security Testing)
- ✅ CVSS v3.1 vulnerability scoring
- ✅ CWE (Common Weakness Enumeration) references
- ✅ Professional certifications (OSCP, CEH, GPEN)

**Remember**: Professional penetration test reports are legal documents that may be used for:
- Compliance audits (PCI DSS, HIPAA, SOC 2)
- Cyber insurance claims
- Board of Directors presentations
- Incident response planning
- Regulatory submissions

Accuracy, completeness, and professionalism are critical.
