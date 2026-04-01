# ATHENA Evidence Capture System — Design Document

**Date:** 2026-02-25
**Author:** Vex (Kelvin Lomboy / ZeroK Labs)
**Status:** Approved
**Phase:** Phase E Enhancement (pre-Phase F)

---

## 1. Problem Statement

ATHENA agents discover vulnerabilities and execute exploits, but evidence capture is manual and disconnected. The `EvidencePackage.screenshot` field exists in Neo4j but is never populated. Text-only evidence in Finding nodes is insufficient for client deliverables, especially in healthcare environments where vulnerabilities cannot be exploited on production systems.

**Clients need:** Reproducible proof that a vulnerability exists, visual evidence for reports, and a chain of custody for compliance (HIPAA, PCI-DSS).

---

## 2. Goals

1. **Automated evidence capture** — Verify agent captures screenshots, HTTP pairs, command output, and diffs for every finding without human intervention
2. **Dual capture modes** — Exploitable (replay attack) and Observable (document condition without triggering) for healthcare/production systems
3. **Neo4j-linked artifacts** — Every piece of evidence is a node in the graph with SHA-256 hash and metadata
4. **Dashboard evidence views** — Per-finding evidence panel + Evidence Gallery page
5. **Report integration** — Evidence embedded inline per finding in generated reports
6. **Client packaging** — One-click ZIP export with report + evidence + manifest
7. **Dual-backend support** — Works across both Kali external (Antsle) and Kali internal (mini-PC)

---

## 3. Non-Goals (Deferred)

- Video recording of exploitation steps
- EyeWitness mass recon screenshots (separate feature)
- Evidence annotation/markup tools
- Real-time evidence streaming via WebSocket
- Drag-and-drop manual upload
- Evidence diffing between engagement runs

---

## 4. Architecture

### 4.1 Approach: Filesystem + Neo4j Metadata (Hybrid)

Screenshots and artifacts stored on disk in structured folders. Neo4j stores metadata (path, hash, timestamp, type, agent) with relationships linking Artifact nodes to Findings and EvidencePackages.

**Why this approach:**
- Filesystem is fast for binary I/O (screenshots, logs)
- Neo4j excels at relationships (Finding -> Evidence -> Artifact)
- Easy to package for client delivery (zip the engagement folder)
- Dashboard serves images directly from disk via API endpoint
- No performance degradation with 100+ screenshots per engagement

### 4.2 Dual-Backend Considerations

ATHENA operates with two Kali boxes:

| Backend | Host | Role | Evidence Path |
|---------|------|------|---------------|
| **kali_external** | `your-kali-host:2222` (user: `kelvin`) | External pentesting (internet-facing targets) | `/home/kelvin/athena/engagements/{eid}/08-evidence/` |
| **kali_internal** | `your-internal-kali:3113` (user: `pentester_0k`) | Internal pentesting (network targets via ZeroTier) | `/home/pentester_0k/athena/engagements/{eid}/08-evidence/` |

**Evidence sync strategy:**
- Each Kali box stores evidence locally during capture
- Dashboard server (Mac) pulls artifacts via SCP/SFTP when serving to UI
- Artifact nodes in Neo4j include `backend` field (`external` | `internal`) so the server knows where to fetch from
- Client ZIP packaging pulls from both backends into a unified evidence folder

---

## 5. Data Model

### 5.1 New Node: Artifact

```cypher
CREATE (a:Artifact {
  id: $artifact_id,              // UUID[:8]
  engagement_id: $eid,
  finding_id: $finding_id,       // links to parent Finding
  evidence_package_id: $ep_id,   // links to EvidencePackage (optional)
  type: $type,                   // screenshot | http_pair | command_output | tool_log | response_diff
  file_path: $file_path,         // relative path within engagement folder
  file_hash: $file_hash,         // SHA-256 (chain of custody)
  file_size: $file_size,         // bytes
  mime_type: $mime_type,          // image/png, image/jpeg, text/plain, application/json
  caption: $caption,             // human-readable description
  agent: $agent,                 // who captured (VF, EX, WV, AR, etc.)
  backend: $backend,             // external | internal
  capture_mode: $mode,           // exploitable | observable
  timestamp: $timestamp
})
```

### 5.2 New Relationships

```cypher
// Finding -> Artifact (direct link)
(f:Finding)-[:HAS_ARTIFACT]->(a:Artifact)

// EvidencePackage -> Artifact (structured verification link)
(ep:EvidencePackage)-[:HAS_ARTIFACT]->(a:Artifact)
```

### 5.3 Updated: EvidencePackage

Existing `screenshot` field repurposed to reference Artifact node IDs instead of remaining NULL:

```cypher
SET ep.artifact_ids = $artifact_ids   // list of Artifact.id strings
```

### 5.4 Filesystem Structure

```
engagements/{engagement-id}/
├── 08-evidence/
│   ├── screenshots/
│   │   ├── 001-CRITICAL-A03-sqli-login-baseline-20260225-143200.png
│   │   ├── 002-CRITICAL-A03-sqli-login-exploit-20260225-143205.png
│   │   ├── 003-HIGH-A02-weak-tls-testssl-20260225-143300.png
│   │   └── thumbnails/          # Auto-generated 300px wide JPEG thumbnails
│   ├── http-pairs/
│   │   ├── 001-CRITICAL-A03-sqli-login-request.txt
│   │   ├── 001-CRITICAL-A03-sqli-login-response.txt
│   │   └── 003-HIGH-A05-idor-api-request.txt
│   ├── command-output/
│   │   ├── 001-CRITICAL-A03-sqlmap-output.txt
│   │   └── 003-HIGH-A02-testssl-output.txt
│   ├── tool-logs/
│   │   ├── nmap-10.1.1.20-full.xml
│   │   ├── nikto-10.1.1.20-443.json
│   │   └── sqlmap-session.log
│   ├── response-diffs/
│   │   └── 001-CRITICAL-A03-sqli-baseline-vs-exploit.diff
│   └── evidence-manifest.json   # Auto-generated from Neo4j
```

**Naming convention:**
```
{sequence}-{SEVERITY}-{OWASP_CODE}-{description}-{YYYYMMDD}-{HHMMSS}.{ext}
```

**File constraints:**
- Max 2MB per screenshot (auto-compress PNG -> JPEG at 85% if exceeded)
- Thumbnails: 300px wide, JPEG 75% quality (for gallery grid)
- SHA-256 computed on write, verified on read

---

## 6. Capture Mechanism

### 6.1 Hybrid Flow

```
RECON/VULN AGENTS (lightweight, inline)
  │  Find vulnerability → POST /api/findings (text evidence only)
  │  Agent continues scanning — no screenshot delay
  │
  ▼ triggers
VERIFY AGENT (thorough, evidence-focused)
  │  For EACH unverified Finding:
  │    1. Navigate to target (Playwright headless)
  │    2. Capture baseline screenshot
  │    3. Replay/demonstrate vulnerability OR observe condition
  │    4. Capture evidence screenshot
  │    5. Save HTTP request/response pair
  │    6. Save command output (if CLI tool)
  │    7. Compute response diff (baseline vs exploit)
  │    8. Hash all artifacts (SHA-256)
  │    9. CREATE Artifact nodes in Neo4j
  │   10. CREATE/UPDATE EvidencePackage with confidence
  │
  ▼ feeds into
REPORT AGENT (assembly)
     Query Findings + EvidencePackages + Artifacts
     Embed screenshots inline per finding
     Auto-number figures
     Generate evidence manifest
     Output: technical-report.md + evidence-manifest.json
```

### 6.2 Two Capture Modes

| Mode | When | Behavior |
|------|------|----------|
| **Exploitable** | Lab, test environment, CTF | Replay exploit, capture proof of success (shell output, data extracted, auth bypass, DOM change) |
| **Observable** | Healthcare, production, critical infra | Navigate to vulnerable endpoint, capture the *condition* without triggering (outdated TLS, missing headers, exposed admin panel, default creds page, open ports) |

**Observable mode examples (healthcare):**
- Weak TLS: Screenshot of `testssl.sh` output showing TLSv1.0 enabled
- Default credentials page: Screenshot showing login page exists (NOT logging in)
- Missing security headers: Screenshot of browser dev tools showing absent headers
- Exposed DICOM/HL7 port: Screenshot of nmap showing open port + service banner
- Unpatched software: Screenshot of HTTP response showing version disclosure
- Open admin panel: Screenshot of accessible admin URL without authentication

**Mode selection:**
- Engagement-level default set at creation (`exploitable` or `observable`)
- Per-finding override possible (some findings on a healthcare engagement may be safe to exploit in staging)
- Verify agent reads mode from Engagement node: `engagement.evidence_mode`

### 6.3 Backend-Aware Capture

The verify agent runs on whichever Kali box discovered the finding:

```
Finding.backend = "external"  →  Verify runs on kali_external (Antsle)
Finding.backend = "internal"  →  Verify runs on kali_internal (mini-PC)
```

Playwright runs headless on the Kali box (requires `xvfb` or `--headless` flag). Screenshots saved to local `08-evidence/` path. Artifact node records which backend holds the file.

---

## 7. API Endpoints

### 7.1 Artifact CRUD

```
POST   /api/artifacts
  Body: multipart/form-data
    file: binary (screenshot, log, etc.)
    finding_id: string (required)
    evidence_package_id: string (optional)
    type: screenshot | http_pair | command_output | tool_log | response_diff
    caption: string
    agent: string
    capture_mode: exploitable | observable
    backend: external | internal
  Response: { id, file_path, file_hash, ... }

GET    /api/artifacts?engagement_id={eid}
  Query params: type, severity, agent, backend, limit, offset
  Response: [ { id, type, caption, finding_id, severity, thumbnail_path, ... } ]

GET    /api/artifacts?finding_id={fid}
  Response: [ { id, type, caption, file_path, file_hash, ... } ]

GET    /api/artifacts/{artifact_id}
  Response: { full artifact metadata }

GET    /api/artifacts/{artifact_id}/file
  Response: binary file (served from filesystem, fetched from Kali if remote)

GET    /api/artifacts/{artifact_id}/thumbnail
  Response: JPEG thumbnail (300px wide)

DELETE /api/artifacts/{artifact_id}
  Response: { deleted: true }
```

### 7.2 Evidence Manifest

```
GET    /api/evidence/manifest?engagement_id={eid}
  Response: evidence-manifest.json (auto-generated from Neo4j)

POST   /api/evidence/package?engagement_id={eid}
  Response: { download_url: "/api/evidence/package/{eid}/download" }
  Action: Generates ZIP with report + evidence + manifest
```

### 7.3 Evidence Stats (for dashboard widgets)

```
GET    /api/evidence/stats?engagement_id={eid}
  Response: {
    total_artifacts: 47,
    by_type: { screenshot: 24, http_pair: 12, command_output: 8, tool_log: 2, response_diff: 1 },
    by_severity: { critical: 8, high: 15, medium: 18, low: 6 },
    by_backend: { external: 30, internal: 17 },
    by_mode: { exploitable: 28, observable: 19 },
    coverage: { findings_with_evidence: 22, findings_total: 25, percent: 88 },
    total_size_bytes: 48234567
  }
```

---

## 8. Dashboard UI

### 8.1 Per-Finding Evidence Panel (Primary)

Accessed by clicking any finding in the dashboard. A detail panel with three tabs:

**[Details]** — Existing finding information (description, CVSS, CVE, MITRE mapping)

**[Evidence (N)]** — Grid of evidence cards:
- Screenshot cards: thumbnail preview, caption, timestamp, hash
- HTTP pair cards: method + URL + status code, expandable
- Command output cards: first 3 lines preview, expandable
- Click any card to expand full-size with metadata overlay
- Confidence indicator bar with evidence type count

**[Remediation]** — Existing remediation guidance

### 8.2 Evidence Gallery Page (Secondary)

New navigation item between "Findings" and "Reports":

- **Grid layout** — Thumbnail cards with type icon, severity badge, finding reference
- **Filters** — Artifact type, severity, agent, backend (external/internal), capture mode
- **Sort** — Newest first, severity, finding order
- **Bulk actions:**
  - Export All (download ZIP)
  - Generate Manifest (evidence-manifest.json)
  - Package for Client (ZIP with report + evidence + HTML index)
- **Stats bar** — Total artifacts, coverage percentage, size

### 8.3 Theme Consistency

All evidence UI uses existing ATHENA dark theme:
- `--zerok-bg`, `--zerok-surface`, `--zerok-accent`
- Card pattern matches findings and attack chain cards
- Severity colors: CRITICAL (red), HIGH (orange), MEDIUM (yellow), LOW (blue)
- Type icons: camera (screenshot), document (HTTP pair), terminal (command output), file (tool log), diff (response diff)

---

## 9. Report Integration

### 9.1 Evidence Per Finding (Inline)

The report agent embeds evidence directly within each finding section:

```markdown
### 3.1 SQL Injection — Login Form
**Severity:** CRITICAL | **CVSS:** 9.8 | **Status:** Confirmed
**Target:** https://10.1.1.20/login
**MITRE ATT&CK:** T1190 (Exploit Public-Facing Application)

**Description:**
The login form is vulnerable to error-based SQL injection...

**Evidence:**

![Figure 3.1a — Login page baseline](screenshots/001-CRITICAL-A03-sqli-login-baseline-20260225-143200.png)
*SHA-256: a7f3e2d9...*

![Figure 3.1b — SQL error disclosure after injection](screenshots/002-CRITICAL-A03-sqli-login-exploit-20260225-143205.png)
*SHA-256: b8c4f3e1...*

**HTTP Request/Response:**
[Embedded code block with full request and response]

**Confidence:** HIGH (4 evidence types)
**Verified by:** athena-verify | 2026-02-25 14:32 AST
```

### 9.2 Observable Mode Labeling

Findings captured in observable mode display clearly:

```markdown
**Mode:** OBSERVABLE (vulnerability documented, not exploited — production system)
```

### 9.3 Evidence Manifest (Appendix)

Auto-generated appendix with complete artifact inventory:

```json
{
  "engagement_id": "ENG-0042",
  "generated": "2026-02-25T18:45:00-04:00",
  "total_artifacts": 47,
  "artifacts": [
    {
      "id": "art-a7f3e2d9",
      "finding_id": "F-a7f3e2d9",
      "type": "screenshot",
      "file_path": "08-evidence/screenshots/001-CRITICAL-A03-sqli-login-baseline-20260225-143200.png",
      "file_hash": "sha256:a7f3e2d9c4b8...",
      "file_size": 245760,
      "caption": "Login page baseline — normal state before injection",
      "agent": "athena-verify",
      "backend": "external",
      "capture_mode": "exploitable",
      "timestamp": "2026-02-25T14:32:00-04:00"
    }
  ]
}
```

### 9.4 Output Formats

- **Markdown** — Primary output from athena-report agent (with relative image paths)
- **PDF** — Via VERSANT docs pipeline (`versant-docs` skill, Pandoc + LaTeX)
- **Client ZIP** — `{client}-{date}-pentest-evidence.zip` containing:
  - `technical-report.pdf`
  - `08-evidence/` (full folder with all artifacts)
  - `evidence-manifest.json`
  - `index.html` (offline evidence browser)

---

## 10. Constraints & Risks

| Risk | Mitigation |
|------|-----------|
| Playwright headless on Kali | Standard setup: `--headless` flag or `xvfb-run`. Both Kali boxes have Chromium. |
| Screenshot file size | Cap at 2MB, auto-compress PNG -> JPEG 85% if exceeded. Thumbnails at 300px/75%. |
| SCP latency for remote artifacts | Cache fetched files locally on dashboard server. Serve from cache on repeat requests. |
| Neo4j storage growth | Artifact nodes are metadata only (~500 bytes each). Binary stays on disk. |
| Evidence integrity | SHA-256 on write, verify on read. Tampering detected immediately. |
| Dual-backend coordination | Artifact.backend field tells server where to fetch. Verify agent runs on same backend as finding. |
| Observable mode false confidence | Observable captures get max MEDIUM confidence (not HIGH) unless 3+ evidence types present. |

---

## 11. Success Metrics

| Metric | Target |
|--------|--------|
| Evidence coverage | 90%+ of findings have at least 1 artifact |
| Capture latency | < 10 seconds per finding (screenshot + save + hash) |
| Gallery load time | < 2 seconds for 50 artifacts |
| Report generation | Evidence-enriched report in < 60 seconds |
| Client package | ZIP ready in < 30 seconds |
| Zero manual screenshots | Agents capture 100% of evidence automatically |

---

## 12. File Changes Summary

| File | Action | Description |
|------|--------|-------------|
| `server.py` | Modify | Add Artifact CRUD endpoints, file serving, manifest generation, ZIP packaging |
| `index.html` | Modify | Add Evidence tab in finding panel, Evidence Gallery page, gallery grid, filters |
| `athena-verify.md` | Modify | Add screenshot capture via Playwright, HTTP pair saving, dual capture modes |
| `athena-report.md` | Modify | Query Artifacts, embed inline, auto-number figures, generate manifest |
| `tool-registry.json` | Modify | Add `playwright_screenshot` and `evidence_capture` tool entries |
| `start.sh` | Modify | Ensure `08-evidence/` subdirectories created on engagement start |

---

**Approved by:** Kelvin Lomboy
**Date:** 2026-02-25
