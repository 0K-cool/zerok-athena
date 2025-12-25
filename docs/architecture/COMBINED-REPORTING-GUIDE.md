# Combined External + Internal Reporting - Quick Reference

**Created**: December 16, 2025
**Feature**: Unified reporting for external and internal penetration tests

---

## Overview

The multi-agent system now supports **combined reporting** - generating ONE comprehensive report that includes both external AND internal penetration test results.

**Why Combined Reporting?**
- Shows complete security posture (external + internal)
- Demonstrates real-world attack paths (external → internal)
- Provides holistic risk assessment
- Better prioritization (fixes that break the attack chain)
- One deliverable for client stakeholders

---

## How It Works

### Step 1: Run External Engagement

```bash
/orchestrate ACME.com - External Pentest
```

**Result**:
- External testing completed (8-12 hours)
- 36 findings documented
- Evidence collected
- Data stored in Pentest Monitor database

### Step 2: Run Internal Engagement

```bash
/orchestrate ACME.com - Internal Pentest
```

**Result**:
- Internal testing completed (8-12 hours)
- 28 findings documented
- Evidence collected
- Data stored in Pentest Monitor database

### Step 3: Generate Combined Report

```bash
/report-combined ACME.com
```

**Result**:
- ONE unified report package (1.5 hours)
- 64 total findings (external + internal)
- Attack chain analysis (external → internal)
- Unified remediation roadmap
- Complete evidence package

---

## What Makes Combined Reports Different?

### Single-Engagement Report
```markdown
Executive Summary:
- External findings: 36 (12 CRITICAL, 11 HIGH)
- Overall risk: HIGH

Technical Report:
- EXTERNAL-001: SQL Injection
- EXTERNAL-002: Tomcat Default Credentials
- [34 more findings]

Remediation:
- Fix SQL injection (Days 1-2)
- Change Tomcat password (Day 1)
- [All external findings]
```

### Combined Report
```markdown
Executive Summary:
- External findings: 36 (12 CRITICAL, 11 HIGH)
- Internal findings: 28 (8 CRITICAL, 12 HIGH)
- Combined risk: CRITICAL (attack chain exists) ⭐

Attack Chain Analysis: ⭐ NEW
  1. External: SQL Injection → Credential theft
  2. Internal: VPN password reuse → Network access
  3. Internal: Kerberoasting → Service account
  4. Internal: Lateral movement → Domain Admin

Business Impact: $5-20M (full compromise possible)

Technical Report:
- Part 2: External Findings (36)
- Part 3: Internal Findings (28)
- Part 4: Attack Chain Analysis ⭐ NEW
  - Shows how external vulnerabilities lead to internal compromise
  - Complete attack path documentation
  - Business impact of full compromise

Remediation Roadmap: ⭐ PRIORITIZED BY ATTACK CHAIN
- Phase 1: Break the Attack Chain (Days 1-7)
  - Fix SQL injection (external entry point)
  - Fix VPN password reuse (prevents internal access)
  - Deploy MFA (defense in depth)
  Result: External can no longer reach internal ✅

- Phase 2: Protect Critical Systems
  - Fix Kerberoasting (prevents privilege escalation)
  - Network segmentation (limits lateral movement)
```

---

## Key Features of Combined Reports

### 1. Attack Chain Analysis

Shows how vulnerabilities connect across engagement types:

```
External SQL Injection (EXTERNAL-001)
  ↓ Credential Theft
VPN Password Reuse (INTERNAL-005)
  ↓ Internal Network Access
Kerberoasting (INTERNAL-001)
  ↓ Service Account Compromise
GPO Misconfiguration (INTERNAL-008)
  ↓ Domain Admin Access

RESULT: Complete organizational compromise
TIME TO COMPROMISE: 8-12 hours
BUSINESS IMPACT: $10-20M
```

### 2. Dual Perspective Executive Summary

```markdown
## External Attack Surface (Internet-Facing)
- Scope: Public-facing systems (*.acme.com, 198.51.100.0/24)
- Findings: 12 CRITICAL, 11 HIGH
- Key Risk: SQL injection allows unauthenticated access

## Internal Attack Surface (Assumed Breach)
- Scope: Internal network (10.10.10.0/24, Active Directory)
- Findings: 8 CRITICAL, 12 HIGH
- Key Risk: Weak AD configuration allows privilege escalation

## Combined Risk Assessment
External alone: HIGH risk
Internal alone: HIGH risk
External + Internal: CRITICAL risk ⭐ (attack chain enables full compromise)
```

### 3. Unified Remediation Roadmap

Prioritized by attack chain disruption:

```markdown
Phase 1: Break the Attack Chain (PRIORITY)
├─ EXTERNAL-001: SQL Injection (blocks external entry)
├─ INTERNAL-005: VPN Password Reuse (prevents internal access)
└─ INTERNAL-007: MFA Missing (defense in depth)

Result: Attack chain broken ✅
Even if other vulnerabilities exist, external cannot reach internal
```

### 4. Combined Evidence Package

```
Evidence_Package_ACME_Combined_2025-12-19.zip.enc (287 MB)
├── external/
│   ├── screenshots/ (67 files)
│   ├── logs/ (8 files)
│   └── commands-used.md
└── internal/
    ├── screenshots/ (89 files)
    ├── logs/ (12 files)
    └── commands-used.md
```

---

## Usage Examples

### Example 1: Basic Combined Reporting

```bash
# Complete external pentest
/orchestrate ACME.com - External Pentest

# Wait for completion (8-12 hours)

# Complete internal pentest
/orchestrate ACME.com - Internal Pentest

# Wait for completion (8-12 hours)

# Generate combined report
/report-combined ACME.com

# Result: Unified report in 09-reporting/combined/
```

### Example 2: Explicit Engagement IDs

```bash
# If you have specific engagement IDs:
/report-combined ACME_2025-12-16_External ACME_2025-12-18_Internal

# Or from different quarters:
/report-combined ACME_Q1_External ACME_Q1_Internal
```

### Example 3: Multiple Engagement Types

```bash
# Combine external, internal, and wireless:
/report-combined ACME_External ACME_Internal ACME_Wireless

# System auto-aggregates all findings
```

---

## Report Deliverables

### Single-Engagement Report

```
09-reporting/final/ACME_2025-12-16_External/
├── Executive_Summary_ACME_External_2025-12-16.pdf (8 pages)
├── Technical_Report_ACME_External_2025-12-16.pdf (87 pages)
├── Remediation_Roadmap_ACME_External_2025-12-16.xlsx
├── Evidence_Package_ACME_External_2025-12-16.zip.enc (124 MB)
└── Presentation_ACME_External_2025-12-16.pptx (24 slides)
```

### Combined Report

```
09-reporting/combined/ACME_Combined_2025-12-19/
├── Executive_Summary_ACME_Combined_2025-12-19.pdf (15 pages) ⬆️
├── Technical_Report_ACME_Combined_2025-12-19.pdf (156 pages) ⬆️
│   ├── Part 1: Methodology
│   ├── Part 2: External Findings (36)
│   ├── Part 3: Internal Findings (28)
│   └── Part 4: Attack Chain Analysis ⭐ NEW
├── Remediation_Roadmap_ACME_Combined_2025-12-19.xlsx
│   ├── Phase 1: Break Attack Chain ⭐ NEW
│   ├── Phase 2: External Remediation
│   ├── Phase 3: Internal Remediation
│   └── Phase 4: Long-term Improvements
├── Evidence_Package_ACME_Combined_2025-12-19.zip.enc (287 MB) ⬆️
└── Presentation_ACME_Combined_2025-12-19.pptx (38 slides) ⬆️
```

**Size Comparison**:
- Executive Summary: +87% pages (more comprehensive)
- Technical Report: +79% pages (covers both engagements + attack chain)
- Evidence Package: +131% size (includes both engagements)
- Presentation: +58% slides (dual perspective + attack chains)

---

## Database Integration

The combined report automatically:

### 1. Auto-Detects Related Engagements

```sql
SELECT * FROM engagements
WHERE client_name LIKE '%ACME%'
AND status = 'COMPLETE'
ORDER BY started_at ASC;

Result:
- ACME_2025-12-16_External (36 findings)
- ACME_2025-12-18_Internal (28 findings)
```

### 2. Aggregates All Findings

```sql
SELECT
  e.type,
  f.severity,
  COUNT(*) as count
FROM findings f
JOIN engagements e ON f.engagement_id = e.id
WHERE e.client_name LIKE '%ACME%'
GROUP BY e.type, f.severity;

Result:
- External CRITICAL: 12
- External HIGH: 11
- Internal CRITICAL: 8
- Internal HIGH: 12
Total: 64 findings
```

### 3. Identifies Attack Chains

```sql
SELECT
  ext.title as external_entry,
  int.title as internal_escalation
FROM findings ext
JOIN findings int
WHERE ext.category LIKE '%credential%'
AND int.category LIKE '%password%'
AND ext.engagement_id IN (SELECT id FROM engagements WHERE type='External')
AND int.engagement_id IN (SELECT id FROM engagements WHERE type='Internal');

Result:
- External SQL Injection → Internal VPN Password Reuse
- Attack chain detected ⚠️
```

---

## Business Value

### For Security Teams

✅ **Complete risk picture** - External + internal combined
✅ **Better prioritization** - Fix what breaks the attack chain first
✅ **Efficient remediation** - No duplicate effort
✅ **One comprehensive deliverable** - Easier to manage

### For Executives

✅ **Clear business impact** - Shows real-world attack scenarios
✅ **Financial risk quantified** - $5-20M for full compromise
✅ **Actionable roadmap** - Prioritized by attack chain disruption
✅ **Compliance mapping** - Holistic view of gaps

### For Compliance

✅ **PCI DSS** - Complete infrastructure coverage
✅ **HIPAA** - External + internal security requirements
✅ **SOC 2** - Comprehensive security testing evidence
✅ **ISO 27001** - Complete security posture assessment

---

## Best Practices

### 1. Timing

**Recommended**:
- Run external first (Dec 16-17)
- Run internal second (Dec 18-19)
- Generate combined report (Dec 19)

**Why?**: External findings inform internal testing priorities

### 2. Scope

**External Scope**:
- Public-facing assets (*.acme.com, public IPs)
- No internal network access

**Internal Scope**:
- Internal network (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16)
- Active Directory
- Internal applications

### 3. Authorization

**Separate authorization required** for each engagement:
- External authorization: Public-facing assets only
- Internal authorization: Internal network testing

Both documented in `01-planning/` for each engagement.

### 4. Reporting

**When to use single reports**:
- Only external OR internal completed
- Client requested separate deliverables
- Different stakeholders for each engagement

**When to use combined reports**:
- Both external AND internal completed ✅
- Client wants complete security posture
- Need to show attack chain analysis
- Compliance requires holistic assessment

---

## Command Reference

```bash
# Single engagement reports (default)
/report ACME_2025-12-16_External
/report ACME_2025-12-18_Internal

# Combined report (auto-detect related engagements)
/report-combined ACME.com
/report-combined ACME

# Combined report (explicit engagement IDs)
/report-combined ACME_2025-12-16_External ACME_2025-12-18_Internal

# Full workflow example
/orchestrate ACME.com - External Pentest  # Day 1-2
/orchestrate ACME.com - Internal Pentest  # Day 3-4
/report-combined ACME.com                 # Day 4
```

---

## Sample Executive Summary Comparison

### Single-Engagement (External Only)

```markdown
# Executive Summary: ACME Corporation - External Penetration Test

## Overall Security Posture: HIGH RISK

### Key Findings
- 12 CRITICAL vulnerabilities
- 11 HIGH vulnerabilities
- SQL injection allows database access

### Business Impact
- Customer data at risk (50,000 records)
- Estimated financial impact: $2-5M
```

### Combined (External + Internal)

```markdown
# Executive Summary: ACME Corporation - Complete Security Assessment

## Overall Security Posture: CRITICAL RISK ⭐

### External Attack Surface
- 12 CRITICAL vulnerabilities
- SQL injection allows database access

### Internal Attack Surface
- 8 CRITICAL vulnerabilities
- Weak Active Directory configuration

### Complete Attack Path (External → Internal) ⭐
1. Attacker exploits SQL injection (external)
2. Steals credentials from database
3. Credentials valid on VPN (internal password reuse)
4. Kerberoasting → Service account compromise
5. GPO misconfiguration → Domain Admin
6. Complete organizational control in 8-12 hours

### Business Impact
- External alone: $2-5M ⭐
- Internal alone: $3-8M ⭐
- Combined (full compromise): $10-20M ⭐

**Risk Multiplier Effect**: External + Internal creates CRITICAL risk
```

---

## FAQ

**Q: Can I generate a combined report later?**
A: Yes! As long as both engagements are in the database, you can generate combined reports anytime:
```bash
/report-combined ACME_2024-Q1_External ACME_2024-Q1_Internal
```

**Q: What if I only have external completed?**
A: Use single-engagement reporting:
```bash
/report ACME_2025-12-16_External
```
You can generate combined report later after internal completes.

**Q: Can I combine more than 2 engagements?**
A: Yes! Combine external, internal, wireless, cloud, etc.:
```bash
/report-combined ACME_Ext ACME_Int ACME_Wireless ACME_Cloud
```

**Q: How does the system detect attack chains?**
A: The Reporting Agent queries the database for:
- External credential theft → Internal credential reuse
- External authentication bypass → Internal password reuse
- External RCE → Internal lateral movement opportunities

**Q: What if there's no attack chain?**
A: Combined report still generated, but focuses on:
- Separate external and internal findings
- No attack chain analysis section
- Independent remediation for each engagement type

**Q: Can I customize the report format?**
A: Yes! Edit `.claude/agents/reporting-agent.md` to customize:
- Executive summary format
- Technical report structure
- Remediation roadmap prioritization

---

## Summary

**Combined Reporting Benefits**:
- ✅ One comprehensive deliverable (easier for stakeholders)
- ✅ Shows real-world attack paths (external → internal)
- ✅ Better remediation prioritization (break the attack chain)
- ✅ Complete security posture assessment
- ✅ Higher perceived value for clients

**Workflow**:
1. `/orchestrate ACME.com - External Pentest`
2. `/orchestrate ACME.com - Internal Pentest`
3. `/report-combined ACME.com`

**Output**: ONE professional report package with 5 deliverables showing complete organizational risk.

---

**Ready to Use**: The combined reporting feature is production-ready! 🎉

For detailed technical implementation, see:
- `.claude/commands/report-combined.md` - Command documentation
- `.claude/agents/reporting-agent.md` - Agent implementation (Combined Mode Workflow section)
