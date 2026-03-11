# Structured Finding Pipeline Implementation Plan

> **For agentic workers:** REQUIRED: Use superpowers:subagent-driven-development (if subagents available) or superpowers:executing-plans to implement this plan. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Replace ATHENA's regex-on-everything finding extractor with a structured-first pipeline that eliminates false positives while preserving real-time detection from scanner output and agent self-reporting.

**Architecture:** Agent self-reporting is primary (structured bus publish). Scanner extractor is a whitelist-only safety net. Catch-all heuristic handles novel tools via 5 unambiguous strong signals. Three confidence levels (HIGH/MEDIUM/LOW) gate broadcast vs dashboard-only vs silent.

**Tech Stack:** Python 3.14, asyncio, FastAPI, Neo4j, WebSocket

**Spec:** `docs/superpowers/specs/2026-03-11-structured-finding-pipeline-design.md`

---

## File Structure

| File | Responsibility | Action |
|------|---------------|--------|
| `tools/athena-dashboard/finding_pipeline.py` | **NEW** — FindingSchema dataclass, ScannerExtractor, CatchAllHeuristic, confidence assignment, dedup logic | Create |
| `tools/athena-dashboard/message_bus.py` | Remove old `extract_findings()` and all regex patterns. Add confidence-gated broadcast. Keep BusMessage, MessageBus, format_intel_update unchanged. | Modify |
| `tools/athena-dashboard/sdk_agent.py` | Update extraction call sites to use new pipeline. Pass Bash command string for whitelist check. | Modify |
| `tools/athena-dashboard/server.py` | Update `/api/bus/publish` to accept structured Finding schema, validate, assign confidence. | Modify |
| `tools/athena-dashboard/agent_configs.py` | Update `_REALTIME_INTEL_WORKER` template with structured publish format and MANDATORY instruction. | Modify |
| `tools/athena-dashboard/agent_session_manager.py` | Update `_bus_to_neo4j` to read structured Finding fields from `msg.data`. Add `unvalidated` flag for LOW confidence. | Modify |
| `tools/athena-dashboard/index.html` | Add "unvalidated" badge CSS + dimmed styling for LOW confidence findings in timeline. | Modify |
| `tools/athena-dashboard/tests/test_finding_pipeline.py` | **NEW** — Unit tests for the entire pipeline | Create |

---

## Chunk 1: Core Pipeline Module

### Task 1: Create FindingSchema and ScannerExtractor

**Files:**
- Create: `tools/athena-dashboard/finding_pipeline.py`
- Create: `tools/athena-dashboard/tests/test_finding_pipeline.py`

- [ ] **Step 1: Write failing tests for FindingSchema validation**

```python
# tests/test_finding_pipeline.py
"""Tests for the structured finding pipeline."""
import pytest
from finding_pipeline import FindingSchema, validate_finding


class TestFindingSchema:
    def test_valid_finding(self):
        f = FindingSchema(
            finding_type="open_port",
            confidence="high",
            source="agent",
            summary="SSH on port 22",
            severity="medium",
            target="10.0.0.1",
            port=22,
            service="ssh",
        )
        assert f.finding_type == "open_port"
        assert f.confidence == "high"
        assert f.dedup_key  # Auto-generated

    def test_dedup_key_auto_generated(self):
        f = FindingSchema(
            finding_type="open_port",
            confidence="medium",
            source="extractor",
            summary="SSH on port 22",
            severity="medium",
            target="10.0.0.1",
        )
        assert f.dedup_key is not None
        assert len(f.dedup_key) > 0

    def test_dedup_key_deterministic(self):
        """Same finding_type + target + summary → same dedup_key."""
        f1 = FindingSchema(
            finding_type="open_port", confidence="high", source="agent",
            summary="SSH on port 22", severity="medium", target="10.0.0.1",
        )
        f2 = FindingSchema(
            finding_type="open_port", confidence="medium", source="extractor",
            summary="SSH on port 22", severity="medium", target="10.0.0.1",
        )
        assert f1.dedup_key == f2.dedup_key

    def test_explicit_dedup_key_preserved(self):
        f = FindingSchema(
            finding_type="cve", confidence="high", source="agent",
            summary="CVE-2023-1234", severity="high", target="10.0.0.1",
            dedup_key="my-custom-key",
        )
        assert f.dedup_key == "my-custom-key"

    def test_validate_finding_from_api_body(self):
        body = {
            "agent": "AR",
            "finding_type": "open_port",
            "confidence": "high",
            "summary": "8 ports open on 10.0.0.1",
            "severity": "high",
            "target": "10.0.0.1",
            "evidence": {"tool": "nmap", "command": "nmap -sV 10.0.0.1"},
        }
        f = validate_finding(body)
        assert f.finding_type == "open_port"
        assert f.source == "agent"
        assert f.confidence == "high"

    def test_validate_finding_defaults(self):
        """Minimal body gets sensible defaults."""
        body = {
            "agent": "WV",
            "summary": "Found something",
            "severity": "medium",
        }
        f = validate_finding(body)
        assert f.finding_type == "vulnerability"
        assert f.confidence == "high"  # Agent self-report default
        assert f.source == "agent"
        assert f.state == "discovered"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard && .venv/bin/python -m pytest tests/test_finding_pipeline.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'finding_pipeline'`

- [ ] **Step 3: Implement FindingSchema and validate_finding**

```python
# finding_pipeline.py
"""ATHENA Structured Finding Pipeline.

Replaces the regex-on-everything extract_findings() with a structured-first
approach: agent self-reporting (primary) + scanner whitelist extractor (safety net)
+ catch-all strong signals (novel tools/zero-days).

Spec: docs/superpowers/specs/2026-03-11-structured-finding-pipeline-design.md
"""
from __future__ import annotations

import hashlib
import logging
import re
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ── Confidence Levels ──────────────────────────────────────
CONFIDENCE_HIGH = "high"
CONFIDENCE_MEDIUM = "medium"
CONFIDENCE_LOW = "low"

# Broadcast threshold: HIGH and MEDIUM broadcast to agents + Neo4j
# LOW goes to dashboard only (dimmed, "unvalidated" badge)
BROADCAST_CONFIDENCES = {CONFIDENCE_HIGH, CONFIDENCE_MEDIUM}


def _make_dedup_key(finding_type: str, target: str | None, summary: str) -> str:
    """Deterministic dedup key from finding identity fields."""
    raw = f"{finding_type}:{target or ''}:{summary[:50]}"
    return hashlib.sha256(raw.encode()).hexdigest()[:16]


@dataclass
class FindingSchema:
    """Structured finding — the canonical format for all pipeline outputs."""
    # Identity
    finding_type: str  # open_port|cve|vulnerability|credential|shell|service|network
    confidence: str  # high|medium|low
    source: str  # agent|extractor
    summary: str
    severity: str  # critical|high|medium|low

    # Target
    target: str | None = None
    port: int | None = None
    service: str | None = None

    # Optional enrichment
    cve: list[str] = field(default_factory=list)
    cwe: str | None = None
    technique: str | None = None  # MITRE ATT&CK

    # Lifecycle
    state: str = "discovered"  # discovered|exploited
    dedup_key: str = ""

    # Proof
    evidence: dict[str, str] = field(default_factory=dict)

    # Action
    action_needed: str | None = None

    def __post_init__(self):
        if not self.dedup_key:
            self.dedup_key = _make_dedup_key(
                self.finding_type, self.target, self.summary)

    def to_dict(self) -> dict[str, Any]:
        """Serialize for BusMessage.data and API responses."""
        return {
            "finding_type": self.finding_type,
            "confidence": self.confidence,
            "source": self.source,
            "state": self.state,
            "dedup_key": self.dedup_key,
            "summary": self.summary,
            "severity": self.severity,
            "target": self.target,
            "port": self.port,
            "service": self.service,
            "cve": self.cve,
            "cwe": self.cwe,
            "technique": self.technique,
            "evidence": self.evidence,
            "action_needed": self.action_needed,
        }


def validate_finding(body: dict) -> FindingSchema:
    """Validate and normalize an API body into a FindingSchema.

    Used by POST /api/bus/publish for agent self-reports.
    """
    return FindingSchema(
        finding_type=body.get("finding_type", "vulnerability"),
        confidence=body.get("confidence", CONFIDENCE_HIGH),
        source="agent",
        summary=body.get("summary", ""),
        severity=body.get("severity", "medium"),
        target=body.get("target"),
        port=body.get("port"),
        service=body.get("service"),
        cve=body.get("cve", []),
        cwe=body.get("cwe"),
        technique=body.get("technique"),
        state=body.get("state", "discovered"),
        dedup_key=body.get("dedup_key", ""),
        evidence=body.get("evidence", {}),
        action_needed=body.get("action_needed"),
    )
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard && .venv/bin/python -m pytest tests/test_finding_pipeline.py::TestFindingSchema -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add tools/athena-dashboard/finding_pipeline.py tools/athena-dashboard/tests/test_finding_pipeline.py
git commit -m "feat(pipeline): add FindingSchema dataclass and validation"
```

---

### Task 2: Scanner Whitelist Extractor

**Files:**
- Modify: `tools/athena-dashboard/finding_pipeline.py`
- Modify: `tools/athena-dashboard/tests/test_finding_pipeline.py`

- [ ] **Step 1: Write failing tests for scanner extractor**

```python
# Append to tests/test_finding_pipeline.py
from finding_pipeline import ScannerExtractor


class TestScannerExtractor:
    def setup_method(self):
        self.extractor = ScannerExtractor()

    def test_nmap_ports_extracted(self):
        output = "22/tcp open ssh OpenSSH 8.9p1\n80/tcp open http nginx 1.20.1\n443/tcp open ssl/http"
        findings = self.extractor.extract("AR", "Bash", output, command="nmap -sV 10.0.0.1")
        assert len(findings) >= 1
        port_finding = [f for f in findings if f.finding_type == "open_port"]
        assert len(port_finding) == 1
        assert port_finding[0].confidence == "medium"

    def test_nuclei_cve_extracted(self):
        output = "[CVE-2023-12345] [critical] http://10.0.0.1:8080/api/debug"
        findings = self.extractor.extract("WV", "Bash", output, command="nuclei -u http://10.0.0.1")
        cve_findings = [f for f in findings if f.finding_type == "cve"]
        assert len(cve_findings) == 1
        assert "CVE-2023-12345" in cve_findings[0].cve
        assert cve_findings[0].confidence == "high"

    def test_non_scanner_command_skipped(self):
        """Non-whitelisted commands produce no findings."""
        output = "22/tcp open ssh OpenSSH 8.9p1"
        findings = self.extractor.extract("WV", "Bash", output, command="cat /etc/services")
        assert len(findings) == 0

    def test_read_tool_skipped(self):
        """Read tool always skipped regardless of content."""
        output = "22/tcp open ssh OpenSSH 8.9p1"
        findings = self.extractor.extract("AR", "Read", output, command="")
        assert len(findings) == 0

    def test_playbook_content_skipped(self):
        """Playbook about SQL injection is NOT a finding."""
        output = "# SQL Injection Testing Playbook\n## Overview\nSQL injection (SQLi) is..."
        findings = self.extractor.extract("WV", "Bash", output, command="nuclei -u http://target")
        assert len(findings) == 0

    def test_naabu_ports_extracted(self):
        output = "10.0.0.1:22\n10.0.0.1:80\n10.0.0.1:443"
        findings = self.extractor.extract("AR", "Bash", output, command="naabu -host 10.0.0.1")
        port_findings = [f for f in findings if f.finding_type == "open_port"]
        assert len(port_findings) == 1

    def test_localhost_ports_filtered(self):
        output = "127.0.0.1:8080\n127.0.0.1:3000"
        findings = self.extractor.extract("AR", "Bash", output, command="naabu -host 127.0.0.1")
        assert len(findings) == 0

    def test_piped_command_first_token_checked(self):
        """nmap ... | grep ... → 'nmap' is whitelisted."""
        output = "22/tcp open ssh"
        findings = self.extractor.extract("AR", "Bash", output, command="nmap -sV 10.0.0.1 | grep open")
        assert len(findings) >= 1

    def test_service_version_extracted(self):
        output = "22/tcp open ssh OpenSSH 8.9p1\n80/tcp open http Apache 2.4.51"
        findings = self.extractor.extract("AR", "Bash", output, command="nmap -sV 10.0.0.1")
        svc_findings = [f for f in findings if f.finding_type == "service"]
        assert len(svc_findings) >= 1
        assert svc_findings[0].confidence == "medium"

    def test_empty_output_skipped(self):
        findings = self.extractor.extract("AR", "Bash", "", command="nmap 10.0.0.1")
        assert len(findings) == 0

    def test_short_output_skipped(self):
        findings = self.extractor.extract("AR", "Bash", "ok", command="nmap 10.0.0.1")
        assert len(findings) == 0

    def test_hydra_credentials_extracted(self):
        output = "[22][ssh] host: 10.0.0.1   login: admin   password: admin123"
        findings = self.extractor.extract("EX", "Bash", output, command="hydra -l admin -P pass.txt 10.0.0.1 ssh")
        cred_findings = [f for f in findings if f.finding_type == "credential"]
        assert len(cred_findings) == 1
        assert cred_findings[0].confidence == "high"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard && .venv/bin/python -m pytest tests/test_finding_pipeline.py::TestScannerExtractor -v`
Expected: FAIL — `ImportError: cannot import name 'ScannerExtractor'`

- [ ] **Step 3: Implement ScannerExtractor**

Add to `finding_pipeline.py`:

```python
# ── Scanner Whitelist ──────────────────────────────────────

SCANNER_COMMANDS = {
    # Recon
    "nmap", "naabu", "masscan", "subfinder", "amass", "httpx",
    # Web scanning
    "nuclei", "nikto", "gobuster", "feroxbuster", "ffuf", "wpscan", "dirb",
    # Exploitation
    "sqlmap", "hydra", "crackmapexec", "metasploit", "msfconsole",
    # Network
    "enum4linux", "smbclient", "rpcclient", "snmpwalk",
    # SSL/TLS
    "testssl", "sslscan",
}

# Only extract from these tool names (SDK block.name values)
_EXTRACTABLE_TOOLS = {"Bash"}

# Regex patterns (reused from old extractor, proven reliable)
_PORT_RE = re.compile(r'(\d{1,5})/(?:tcp|udp)\s+open\s+(\S+)', re.IGNORECASE)
_NAABU_PORT_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3}):(\d{1,5})')
_CVE_RE = re.compile(r'(CVE-\d{4}-\d{4,7})', re.IGNORECASE)
_IP_RE = re.compile(r'(\d{1,3}(?:\.\d{1,3}){3})')
_SERVICE_RE = re.compile(
    r'(Apache|Nginx|Tomcat|IIS|OpenSSH|MySQL|PostgreSQL|Redis|MongoDB'
    r'|Elasticsearch|Jenkins|GitLab|WordPress|Drupal|Joomla'
    r'|vsftpd|ProFTPD|Exim|Postfix|Dovecot|Samba)'
    r'[/\s]*([\d.]+)?',
    re.IGNORECASE)
_LOCALHOST = {"127.0.0.1", "0.0.0.0", "localhost"}

# Credential patterns for scanner output (hydra, crackmapexec, etc.)
_CRED_RE = re.compile(
    r'(?:login|user(?:name)?)\s*[:=]\s*(\S+)\s+'
    r'(?:password|pass)\s*[:=]\s*(\S+)', re.IGNORECASE)
_CRED_KEYWORDS = (
    "valid credentials", "password found", "login successful",
    "authenticated successfully", "creds found", "default credentials",
)


def _extract_scanner_command(command: str) -> str | None:
    """Extract the scanner name from a Bash command string.

    Returns the first token if it's in SCANNER_COMMANDS, else None.
    Handles pipes: 'nmap -sV 10.0.0.1 | grep open' → 'nmap'.
    """
    if not command:
        return None
    # Strip leading whitespace, sudo, env vars
    cmd = command.strip()
    for prefix in ("sudo ", "bash -c ", "sh -c "):
        if cmd.startswith(prefix):
            cmd = cmd[len(prefix):].lstrip("'\"")
    first_token = cmd.split()[0].split("/")[-1] if cmd.split() else ""
    return first_token if first_token in SCANNER_COMMANDS else None


class ScannerExtractor:
    """Whitelist-only extractor for known scanner tool output.

    Only runs regex extraction on Bash output from whitelisted scanner
    commands. Everything else is skipped — agent self-reporting handles
    non-scanner findings.
    """

    def extract(
        self,
        agent_code: str,
        tool_name: str,
        tool_output: str,
        command: str = "",
    ) -> list[FindingSchema]:
        """Extract structured findings from tool output.

        Returns empty list if:
        - tool_name not in _EXTRACTABLE_TOOLS (only Bash)
        - command not in SCANNER_COMMANDS whitelist
        - output too short or looks like file content
        """
        if not tool_output or len(tool_output) < 20:
            return []

        if tool_name not in _EXTRACTABLE_TOOLS:
            return []

        scanner = _extract_scanner_command(command)
        if not scanner:
            return []  # Not a whitelisted scanner — skip

        output = tool_output[:8000]
        output_lower = output.lower()

        # Skip file content that leaked through (Read tool format)
        if re.match(r'\s*\d+→', output):
            return []

        # Skip playbook/documentation content even in scanner output
        # (agent might cat a file inside a bash session)
        _PLAYBOOK_INDICATORS = ("# ", "## ", "playbook", "testing guide",
                                "methodology", "**tactic**", "**technique**",
                                "owasp reference", "structured approach")
        if sum(1 for kw in _PLAYBOOK_INDICATORS if kw in output_lower) >= 3:
            return []

        findings: list[FindingSchema] = []

        # 1. CVEs (HIGH confidence from scanner)
        cve_matches = _CVE_RE.findall(output)
        if cve_matches:
            cves = list(set(cve_matches))[:5]
            ip_match = _IP_RE.search(output)
            target = ip_match.group(1) if ip_match else None
            if target not in _LOCALHOST:
                findings.append(FindingSchema(
                    finding_type="cve",
                    confidence=CONFIDENCE_HIGH,
                    source="extractor",
                    summary=f"CVE(s) identified: {', '.join(cves)}",
                    severity="high",
                    target=target,
                    cve=cves,
                    evidence={"tool": scanner, "command": command[:200],
                              "output": output[:1000]},
                    action_needed=f"Research and exploit {', '.join(cves)}",
                ))

        # 2. Open ports — nmap format (MEDIUM confidence)
        ports = _PORT_RE.findall(output)
        naabu_ports = _NAABU_PORT_RE.findall(output)
        naabu_ports = [(ip, p) for ip, p in naabu_ports if ip not in _LOCALHOST]

        if ports:
            port_list = [(p, s) for p, s in ports][:10]
            ip_match = _IP_RE.search(output)
            target = ip_match.group(1) if ip_match else None
            if target in _LOCALHOST:
                target = None
            port_str = ", ".join(f"{p}/{s}" for p, s in port_list)
            findings.append(FindingSchema(
                finding_type="open_port",
                confidence=CONFIDENCE_MEDIUM,
                source="extractor",
                summary=f"Open ports: {port_str}",
                severity="high",
                target=target,
                evidence={"tool": scanner, "command": command[:200],
                          "output": output[:1000]},
                action_needed="Fingerprint services and check for known vulnerabilities",
            ))
        elif naabu_ports:
            port_str = ", ".join(f"{ip}:{p}" for ip, p in naabu_ports[:10])
            target = naabu_ports[0][0] if naabu_ports else None
            findings.append(FindingSchema(
                finding_type="open_port",
                confidence=CONFIDENCE_MEDIUM,
                source="extractor",
                summary=f"Open ports: {port_str}",
                severity="high",
                target=target,
                evidence={"tool": scanner, "command": command[:200]},
            ))

        # 3. Credentials (HIGH — scanner confirmed)
        if _CRED_RE.search(output) or any(kw in output_lower for kw in _CRED_KEYWORDS):
            ip_match = _IP_RE.search(output)
            target = ip_match.group(1) if ip_match else None
            findings.append(FindingSchema(
                finding_type="credential",
                confidence=CONFIDENCE_HIGH,
                source="extractor",
                summary=f"Credentials discovered: {output[:200]}",
                severity="critical",
                target=target,
                evidence={"tool": scanner, "command": command[:200],
                          "output": output[:1000]},
                action_needed="Try credentials against all discovered services",
            ))

        # 4. Service/version identification (MEDIUM)
        svc_matches = _SERVICE_RE.findall(output)
        if svc_matches:
            services = [f"{s} {v}".strip() for s, v in svc_matches[:5]]
            ip_match = _IP_RE.search(output)
            target = ip_match.group(1) if ip_match else None
            if target not in _LOCALHOST:
                findings.append(FindingSchema(
                    finding_type="service",
                    confidence=CONFIDENCE_MEDIUM,
                    source="extractor",
                    summary=f"Service identified: {', '.join(services)}",
                    severity="medium",
                    target=target,
                    evidence={"tool": scanner, "command": command[:200]},
                    action_needed="Check for known CVEs and misconfigurations",
                ))

        return findings
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard && .venv/bin/python -m pytest tests/test_finding_pipeline.py::TestScannerExtractor -v`
Expected: All 13 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add tools/athena-dashboard/finding_pipeline.py tools/athena-dashboard/tests/test_finding_pipeline.py
git commit -m "feat(pipeline): add ScannerExtractor with whitelist approach"
```

---

### Task 3: Catch-All Strong Signal Heuristic

**Files:**
- Modify: `tools/athena-dashboard/finding_pipeline.py`
- Modify: `tools/athena-dashboard/tests/test_finding_pipeline.py`

- [ ] **Step 1: Write failing tests for catch-all heuristic**

```python
# Append to tests/test_finding_pipeline.py
from finding_pipeline import CatchAllHeuristic


class TestCatchAllHeuristic:
    def setup_method(self):
        self.heuristic = CatchAllHeuristic()

    def test_root_shell_detected(self):
        output = "uid=0(root) gid=0(root) groups=0(root)"
        findings = self.heuristic.check("EX", output)
        assert len(findings) == 1
        assert findings[0].finding_type == "shell"
        assert findings[0].confidence == "low"

    def test_meterpreter_detected(self):
        output = "meterpreter > getuid\nServer username: NT AUTHORITY\\SYSTEM"
        findings = self.heuristic.check("EX", output)
        assert len(findings) >= 1
        assert any(f.finding_type == "shell" for f in findings)

    def test_cve_in_unknown_tool(self):
        output = "Vulnerable to CVE-2024-99999 — remote code execution"
        findings = self.heuristic.check("WV", output)
        assert len(findings) == 1
        assert findings[0].finding_type == "cve"
        assert findings[0].confidence == "low"

    def test_normal_output_no_match(self):
        output = "Starting scan on 10.0.0.1... 50% complete... done."
        findings = self.heuristic.check("AR", output)
        assert len(findings) == 0

    def test_playbook_mentioning_root_no_match(self):
        """Playbook content should not trigger strong signals."""
        output = "# Privilege Escalation\n## Overview\nCheck uid=0(root) after exploit"
        findings = self.heuristic.check("WV", output)
        # This WOULD match uid=0(root) but playbook guard catches it
        assert len(findings) == 0

    def test_windows_system_detected(self):
        output = "whoami\nnt authority\\system"
        findings = self.heuristic.check("EX", output)
        assert len(findings) == 1
        assert findings[0].finding_type == "shell"

    def test_root_prompt_detected(self):
        output = "root@target-server:~# whoami\nroot"
        findings = self.heuristic.check("EX", output)
        assert len(findings) >= 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard && .venv/bin/python -m pytest tests/test_finding_pipeline.py::TestCatchAllHeuristic -v`
Expected: FAIL — `ImportError: cannot import name 'CatchAllHeuristic'`

- [ ] **Step 3: Implement CatchAllHeuristic**

Add to `finding_pipeline.py`:

```python
# ── Catch-All Strong Signals ──────────────────────────────

# Unambiguous patterns that indicate exploitation regardless of source tool.
# These never false-positive on documentation content.
_STRONG_SIGNALS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'uid=\d+\(root\)'), "shell"),
    (re.compile(r'root@[\w.-]+[:#]'), "shell"),
    (re.compile(r'NT AUTHORITY\\SYSTEM', re.IGNORECASE), "shell"),
    (re.compile(r'meterpreter\s*>', re.IGNORECASE), "shell"),
    (re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE), "cve"),
]

# Playbook content guard (reuse from ScannerExtractor)
_PLAYBOOK_INDICATORS = ("# ", "## ", "playbook", "testing guide",
                        "methodology", "**tactic**", "**technique**",
                        "owasp reference", "structured approach")


class CatchAllHeuristic:
    """Safety net for novel tools and zero-days.

    Checks ALL Bash output (even non-whitelisted commands) for 5
    unambiguous strong signals. Findings get LOW confidence —
    dashboard-visible but not broadcast to agents.
    """

    def check(self, agent_code: str, tool_output: str) -> list[FindingSchema]:
        if not tool_output or len(tool_output) < 10:
            return []

        output = tool_output[:8000]
        output_lower = output.lower()

        # Skip file content
        if re.match(r'\s*\d+→', output):
            return []

        # Skip playbook/documentation
        if sum(1 for kw in _PLAYBOOK_INDICATORS if kw in output_lower) >= 3:
            return []

        findings: list[FindingSchema] = []
        seen_types: set[str] = set()

        for pattern, finding_type in _STRONG_SIGNALS:
            if finding_type in seen_types:
                continue  # One finding per type
            match = pattern.search(output)
            if match:
                seen_types.add(finding_type)
                ip_match = _IP_RE.search(output)
                target = ip_match.group(1) if ip_match else None
                if target in _LOCALHOST:
                    target = None

                summary = (f"Strong signal ({finding_type}): "
                           f"{output[:200]}")
                cves = []
                if finding_type == "cve":
                    cves = list(set(_CVE_RE.findall(output)))[:5]
                    summary = f"CVE(s) detected: {', '.join(cves)}"

                findings.append(FindingSchema(
                    finding_type=finding_type,
                    confidence=CONFIDENCE_LOW,
                    source="extractor",
                    summary=summary,
                    severity="critical" if finding_type == "shell" else "high",
                    target=target,
                    cve=cves,
                    evidence={"output": output[:1000]},
                ))

        return findings
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard && .venv/bin/python -m pytest tests/test_finding_pipeline.py::TestCatchAllHeuristic -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add tools/athena-dashboard/finding_pipeline.py tools/athena-dashboard/tests/test_finding_pipeline.py
git commit -m "feat(pipeline): add CatchAllHeuristic for novel tools and zero-days"
```

---

### Task 4: Dedup Logic and Pipeline Orchestrator

**Files:**
- Modify: `tools/athena-dashboard/finding_pipeline.py`
- Modify: `tools/athena-dashboard/tests/test_finding_pipeline.py`

- [ ] **Step 1: Write failing tests for dedup and orchestrator**

```python
# Append to tests/test_finding_pipeline.py
from finding_pipeline import FindingDedup, extract_findings_v2


class TestFindingDedup:
    def setup_method(self):
        self.dedup = FindingDedup()

    def test_new_finding_accepted(self):
        f = FindingSchema(
            finding_type="open_port", confidence="medium", source="extractor",
            summary="Port 22 open", severity="high", target="10.0.0.1",
        )
        result = self.dedup.check(f)
        assert result is not None
        assert result.dedup_key == f.dedup_key

    def test_duplicate_finding_rejected(self):
        f1 = FindingSchema(
            finding_type="open_port", confidence="medium", source="extractor",
            summary="Port 22 open", severity="high", target="10.0.0.1",
        )
        f2 = FindingSchema(
            finding_type="open_port", confidence="medium", source="extractor",
            summary="Port 22 open", severity="high", target="10.0.0.1",
        )
        self.dedup.check(f1)
        result = self.dedup.check(f2)
        assert result is None  # Duplicate, no state change

    def test_state_upgrade_re_emits(self):
        f1 = FindingSchema(
            finding_type="cve", confidence="medium", source="extractor",
            summary="CVE-2023-1234", severity="high", target="10.0.0.1",
            state="discovered",
        )
        f2 = FindingSchema(
            finding_type="cve", confidence="high", source="agent",
            summary="CVE-2023-1234", severity="high", target="10.0.0.1",
            state="exploited",
        )
        self.dedup.check(f1)
        result = self.dedup.check(f2)
        assert result is not None  # State changed — re-emit
        assert result.state == "exploited"
        assert result.confidence == "high"

    def test_reset_clears_state(self):
        f = FindingSchema(
            finding_type="open_port", confidence="medium", source="extractor",
            summary="Port 22", severity="high", target="10.0.0.1",
        )
        self.dedup.check(f)
        self.dedup.reset()
        result = self.dedup.check(f)
        assert result is not None  # Accepted after reset


class TestExtractFindingsV2:
    """Integration tests for the full pipeline orchestrator."""

    def test_scanner_output_produces_findings(self):
        findings = extract_findings_v2(
            agent_code="AR", tool_name="Bash",
            tool_output="22/tcp open ssh OpenSSH 8.9p1",
            command="nmap -sV 10.0.0.1",
        )
        assert len(findings) >= 1

    def test_read_tool_produces_nothing(self):
        findings = extract_findings_v2(
            agent_code="WV", tool_name="Read",
            tool_output="# SQL Injection Playbook\nThis describes SQLi...",
            command="",
        )
        assert len(findings) == 0

    def test_unknown_command_with_root_shell(self):
        findings = extract_findings_v2(
            agent_code="EX", tool_name="Bash",
            tool_output="uid=0(root) gid=0(root)",
            command="python3 /tmp/exploit.py",
        )
        assert len(findings) == 1
        assert findings[0].confidence == "low"  # Catch-all

    def test_unknown_command_no_signals(self):
        findings = extract_findings_v2(
            agent_code="EX", tool_name="Bash",
            tool_output="File downloaded successfully to /tmp/data.csv",
            command="python3 /tmp/download.py",
        )
        assert len(findings) == 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard && .venv/bin/python -m pytest tests/test_finding_pipeline.py::TestFindingDedup tests/test_finding_pipeline.py::TestExtractFindingsV2 -v`
Expected: FAIL — `ImportError`

- [ ] **Step 3: Implement FindingDedup and extract_findings_v2**

Add to `finding_pipeline.py`:

```python
# ── Dedup ──────────────────────────────────────────────────

_STATE_ORDER = {"discovered": 0, "exploited": 1}
_CONFIDENCE_ORDER = {"low": 0, "medium": 1, "high": 2}


class FindingDedup:
    """In-memory dedup for an engagement's findings.

    Returns the finding if new or if state/confidence upgraded.
    Returns None if duplicate with no change.
    """

    def __init__(self):
        self._seen: dict[str, FindingSchema] = {}

    def check(self, finding: FindingSchema) -> FindingSchema | None:
        key = finding.dedup_key
        existing = self._seen.get(key)
        if existing is None:
            self._seen[key] = finding
            return finding

        # Check for state or confidence upgrade
        state_upgraded = (
            _STATE_ORDER.get(finding.state, 0)
            > _STATE_ORDER.get(existing.state, 0)
        )
        confidence_upgraded = (
            _CONFIDENCE_ORDER.get(finding.confidence, 0)
            > _CONFIDENCE_ORDER.get(existing.confidence, 0)
        )

        if state_upgraded or confidence_upgraded:
            # Merge: take best of each field
            merged = FindingSchema(
                finding_type=finding.finding_type,
                confidence=(finding.confidence if confidence_upgraded
                            else existing.confidence),
                source=("agent" if finding.source == "agent"
                        else existing.source),
                summary=finding.summary if finding.source == "agent" else existing.summary,
                severity=finding.severity,
                target=finding.target or existing.target,
                port=finding.port or existing.port,
                service=finding.service or existing.service,
                cve=finding.cve or existing.cve,
                cwe=finding.cwe or existing.cwe,
                technique=finding.technique or existing.technique,
                state=finding.state if state_upgraded else existing.state,
                dedup_key=key,
                evidence=finding.evidence if finding.evidence else existing.evidence,
                action_needed=finding.action_needed or existing.action_needed,
            )
            self._seen[key] = merged
            return merged

        return None  # Exact duplicate, no change

    def reset(self):
        self._seen.clear()


# ── Pipeline Orchestrator ──────────────────────────────────

# Singleton instances (created per-engagement via reset)
_scanner_extractor = ScannerExtractor()
_catchall_heuristic = CatchAllHeuristic()


def extract_findings_v2(
    agent_code: str,
    tool_name: str,
    tool_output: str,
    command: str = "",
) -> list[FindingSchema]:
    """Structured finding extraction pipeline (v2).

    Replaces the old extract_findings(). Flow:
    1. Scanner extractor (whitelist only) → HIGH/MEDIUM confidence
    2. Catch-all heuristic (strong signals) → LOW confidence
    3. Returns list of FindingSchema objects
    """
    if not tool_output or len(tool_output) < 20:
        return []

    # Non-Bash tools produce no findings (agents self-report)
    if tool_name not in _EXTRACTABLE_TOOLS:
        return []

    # Try scanner extractor first (whitelisted commands)
    findings = _scanner_extractor.extract(agent_code, tool_name, tool_output, command)
    if findings:
        return findings

    # Fall through to catch-all for non-whitelisted Bash commands
    return _catchall_heuristic.check(agent_code, tool_output)
```

- [ ] **Step 4: Run all tests**

Run: `cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard && .venv/bin/python -m pytest tests/test_finding_pipeline.py -v`
Expected: All tests PASS (31 total)

- [ ] **Step 5: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add tools/athena-dashboard/finding_pipeline.py tools/athena-dashboard/tests/test_finding_pipeline.py
git commit -m "feat(pipeline): add FindingDedup and extract_findings_v2 orchestrator"
```

---

## Chunk 2: Integration (Wire Pipeline Into Existing Code)

### Task 5: Replace extract_findings in sdk_agent.py

**Files:**
- Modify: `tools/athena-dashboard/sdk_agent.py:35-36, 1541-1598`

- [ ] **Step 1: Update import**

In `sdk_agent.py`, change line 35:
```python
# OLD:
from message_bus import extract_findings, format_intel_update
# NEW:
from message_bus import format_intel_update
from finding_pipeline import extract_findings_v2, FindingSchema, BROADCAST_CONFIDENCES
```

- [ ] **Step 2: Update extraction call site 1 (line 1541-1555)**

Replace the extraction block at line 1541-1555 with:

```python
                    # Real-time bus: extract findings from tool output and broadcast
                    if self._bus and output and len(output) > 20:
                        # Get the Bash command for whitelist check
                        cmd = ""
                        if tool_name == "Bash":
                            cmd = self._pending_commands.get(block.tool_use_id, "")
                        findings = extract_findings_v2(
                            self._current_agent, tool_name, output, command=cmd)
                        for finding in findings:
                            from message_bus import BusMessage
                            msg = BusMessage(
                                from_agent=finding.source == "agent" and self._current_agent or self._current_agent,
                                to="ALL",
                                bus_type="finding",
                                priority=finding.severity,
                                summary=finding.summary,
                                target=finding.target,
                                data=finding.to_dict(),
                                action_needed=finding.action_needed,
                            )
                            if finding.confidence in BROADCAST_CONFIDENCES:
                                await self._bus.broadcast(msg)
                                if finding.severity in ("high", "critical"):
                                    await self.send_bilateral_message(
                                        from_agent=self._current_agent,
                                        to_agent="ST",
                                        msg_type="discovery",
                                        content=finding.summary[:500],
                                        priority=finding.severity,
                                    )
                            else:
                                # LOW confidence: fire callbacks (dashboard) but don't enqueue to agents
                                self._bus._history.append(msg)
                                for cb in self._bus._callbacks:
                                    asyncio.create_task(cb(msg))
```

- [ ] **Step 3: Update extraction call site 2 (line 1585-1598)**

Apply the same pattern to the second extraction block (line 1585-1598). Same code, same logic.

- [ ] **Step 4: Track Bash commands for whitelist lookup**

Add a `_pending_commands` dict to track tool_use_id → Bash command. Near line 1495 where `_pending_tools` is set:

```python
                self._pending_tools[block.id] = block.name
                # Track Bash command for finding pipeline whitelist check
                if block.name == "Bash" and command:
                    if not hasattr(self, '_pending_commands'):
                        self._pending_commands = {}
                    self._pending_commands[block.id] = command
```

And in the tool result handler, pop it:

```python
                    tool_name = self._pending_tools.pop(block.tool_use_id, "")
                    cmd = getattr(self, '_pending_commands', {}).pop(block.tool_use_id, "")
```

- [ ] **Step 5: Test manually** — Restart server and run an engagement. Verify:
- Playbook reads produce zero findings
- nmap output produces port findings
- No false positives

Run: Kill port 8080, restart server, create engagement, start pentest.

- [ ] **Step 6: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add tools/athena-dashboard/sdk_agent.py
git commit -m "feat(pipeline): wire extract_findings_v2 into sdk_agent.py"
```

---

### Task 6: Update /api/bus/publish for Structured Finding Schema

**Files:**
- Modify: `tools/athena-dashboard/server.py:10289-10312`

- [ ] **Step 1: Update the endpoint**

Replace the `/api/bus/publish` handler:

```python
@app.post("/api/bus/publish")
async def bus_publish(request: Request):
    """Agent publishes a structured finding to the message bus."""
    global _active_session_manager
    if not _active_session_manager:
        return JSONResponse({"error": "No active engagement"}, 400)

    body = await request.json()

    # Support both old format (summary/type) and new structured format (finding_type)
    from finding_pipeline import validate_finding, BROADCAST_CONFIDENCES
    from message_bus import BusMessage

    finding = validate_finding(body)

    msg = BusMessage(
        from_agent=body.get("agent", "unknown"),
        to=body.get("to", "ALL"),
        bus_type="finding",
        priority=finding.severity,
        summary=finding.summary,
        target=finding.target,
        data=finding.to_dict(),
        action_needed=finding.action_needed,
    )

    if finding.confidence in BROADCAST_CONFIDENCES:
        if msg.to == "ALL":
            await _active_session_manager.bus.broadcast(msg)
        else:
            await _active_session_manager.bus.send(msg)
    else:
        # LOW confidence: dashboard only
        _active_session_manager.bus._history.append(msg)
        for cb in _active_session_manager.bus._callbacks:
            import asyncio
            asyncio.create_task(cb(msg))

    return {"ok": True, "message_id": msg.id, "confidence": finding.confidence,
            "dedup_key": finding.dedup_key}
```

- [ ] **Step 2: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add tools/athena-dashboard/server.py
git commit -m "feat(pipeline): update /api/bus/publish for structured Finding schema"
```

---

### Task 7: Update Agent Prompt Templates

**Files:**
- Modify: `tools/athena-dashboard/agent_configs.py:135-169`

- [ ] **Step 1: Replace _REALTIME_INTEL_WORKER**

```python
_REALTIME_INTEL_WORKER = """
## Real-Time Intelligence

You are part of a coordinated multi-agent team. Share discoveries IMMEDIATELY.

**MANDATORY: After EVERY tool execution that reveals a security finding, you MUST
publish it to the message bus.** Do not assume the system detects findings
automatically. You are the intelligence — the system is just the transport.

**To publish a finding to ALL agents:**
```bash
curl -s -X POST http://localhost:8080/api/bus/publish \\
  -H "Content-Type: application/json" \\
  -d '{{"agent": "{{AGENT_CODE}}", "finding_type": "open_port", "confidence": "high", "summary": "WHAT YOU FOUND", "severity": "high", "target": "IP:PORT", "evidence": {{"tool": "TOOL_NAME", "command": "WHAT YOU RAN", "output": "KEY OUTPUT LINE"}}, "action_needed": "NEXT STEP"}}'
```

**finding_type values:** open_port, cve, vulnerability, credential, shell, service, network
**severity values:** critical, high, medium, low

**ALWAYS publish when you find:**
- Open ports, services, or version info (finding_type: open_port or service)
- Vulnerabilities or CVE matches (finding_type: cve or vulnerability)
- Valid credentials (finding_type: credential)
- Successful exploits / shell access (finding_type: shell)
- New networks or hosts (finding_type: network)

**Intel from other agents is injected between your work cycles. Read it. Act on it.**

### How to use incoming intel:
- Service version found by another agent → check for known CVEs before scanning
- Credentials shared → try them on your target services
- Directive from ST → reprioritize immediately
- Exploit succeeded → note for reports, avoid redundant work

### When to escalate to ST:
- Found credentials that might work on other targets
- Discovered a new internal network
- Need to pivot — lateral movement opportunity
"""
```

- [ ] **Step 2: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add tools/athena-dashboard/agent_configs.py
git commit -m "feat(pipeline): update agent prompts for structured self-reporting"
```

---

### Task 8: Update _bus_to_neo4j for Structured Findings

**Files:**
- Modify: `tools/athena-dashboard/agent_session_manager.py:423-565`

- [ ] **Step 1: Update the callback to read structured Finding fields**

The key change: instead of parsing `msg.summary` with keywords, read from `msg.data` which now contains the FindingSchema fields.

Replace the `_bus_to_neo4j` function body (inside `_persist()`):

```python
            async def _bus_to_neo4j(msg):
                """Auto-persist structured findings into Neo4j attack graph."""
                if msg.bus_type not in ("finding", "escalation"):
                    return

                # Read structured fields from data (FindingSchema)
                data = msg.data or {}
                confidence = data.get("confidence", "medium")
                finding_type = data.get("finding_type", "")

                # Only persist HIGH and MEDIUM confidence
                if confidence == "low":
                    logger.debug("Bus→Neo4j: skipping LOW confidence finding from %s",
                                 msg.from_agent)
                    return

                try:
                    import hashlib
                    dedup_key = data.get("dedup_key", "")
                    if not dedup_key:
                        fingerprint = hashlib.sha256(
                            f"{msg.summary}:{msg.target or ''}:{msg.from_agent}".encode()
                        ).hexdigest()[:16]
                        dedup_key = fingerprint
                    finding_id = f"bus-{dedup_key}"

                    def _persist():
                        with driver.session() as sess:
                            # 1. Create/update Finding node with structured fields
                            sess.run(
                                "MERGE (f:Finding {id: $id}) "
                                "SET f.title = $title, "
                                "    f.severity = $severity, "
                                "    f.finding_type = $finding_type, "
                                "    f.category = $category, "
                                "    f.target = $target, "
                                "    f.agent = $agent, "
                                "    f.description = $description, "
                                "    f.engagement_id = $eid, "
                                "    f.fingerprint = $fingerprint, "
                                "    f.discovery_source = $source, "
                                "    f.confidence = $confidence, "
                                "    f.state = $state, "
                                "    f.bus_type = $bus_type, "
                                "    f.timestamp = datetime()",
                                id=finding_id,
                                title=msg.summary[:200],
                                severity=data.get("severity", msg.priority),
                                finding_type=finding_type,
                                category=msg.bus_type,
                                target=msg.target or "",
                                agent=msg.from_agent,
                                description=msg.summary,
                                eid=eid,
                                fingerprint=dedup_key,
                                source=data.get("source", "bus"),
                                confidence=confidence,
                                state=data.get("state", "discovered"),
                                bus_type=msg.bus_type,
                            )

                            # 2-5: Host, Service, Credential, Escalation nodes
                            # (keep existing logic — unchanged)
```

Note: The Host/Service/Credential/Escalation node creation logic (lines 474-557 in current code) stays the same — it already works correctly. Only the Finding node creation and the entry guard (confidence check) change.

- [ ] **Step 2: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add tools/athena-dashboard/agent_session_manager.py
git commit -m "feat(pipeline): update _bus_to_neo4j for structured Finding fields"
```

---

### Task 9: Remove Old extract_findings from message_bus.py

**Files:**
- Modify: `tools/athena-dashboard/message_bus.py:134-363`

- [ ] **Step 1: Remove old code**

Delete everything from line 134 (`# ── Finding Extraction Patterns`) through line 363 (end of `extract_findings()`). This removes:
- All regex pattern constants (`_PORT_RE`, `_CVE_RE`, etc.)
- All keyword tuples (`_CRED_KEYWORDS`, `_SHELL_KEYWORDS`, etc.)
- The `extract_findings()` function
- The `_SKIP_TOOLS` set and all false-positive guards

Keep everything else in `message_bus.py`:
- `BusMessage` dataclass (lines 21-47)
- `_PRIORITY_ORDER` (line 51)
- `MessageBus` class (lines 54-131)
- `format_intel_update()` (lines 366-425)

- [ ] **Step 2: Verify no remaining imports of extract_findings**

Search the codebase for any remaining `from message_bus import extract_findings` — should only be in the old `sdk_agent.py` import which was already updated in Task 5.

Run: `grep -r "extract_findings" /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard/ --include="*.py" | grep -v test | grep -v finding_pipeline | grep -v __pycache__ | grep -v .venv`

Expected: No matches (or only `extract_findings_v2` references)

- [ ] **Step 3: Run full test suite**

Run: `cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard && .venv/bin/python -m pytest tests/test_finding_pipeline.py -v`
Expected: All tests PASS

- [ ] **Step 4: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add tools/athena-dashboard/message_bus.py
git commit -m "refactor(pipeline): remove old regex extract_findings — replaced by finding_pipeline.py"
```

---

### Task 10: Dashboard "Unvalidated" Badge for LOW Confidence

**Files:**
- Modify: `tools/athena-dashboard/index.html`

- [ ] **Step 1: Add CSS for unvalidated badge**

Add near the existing `.severity-badge` styles:

```css
.confidence-badge-low {
    display: inline-block;
    font-size: 9px;
    padding: 1px 5px;
    border-radius: 3px;
    background: color-mix(in srgb, var(--zerok-text-dim) 20%, transparent);
    color: var(--zerok-text-dim);
    margin-left: 4px;
    font-style: italic;
}

.timeline-card.low-confidence {
    opacity: 0.6;
}
```

- [ ] **Step 2: Update timeline card rendering to show badge**

In the JavaScript where `agent_intel` events are rendered in the timeline, check `msg.metadata.confidence`:

```javascript
// Inside the card rendering for agent_intel events:
const confidence = (msg.metadata && msg.metadata.confidence) || 'high';
if (confidence === 'low') {
    card.classList.add('low-confidence');
    // Add badge after summary text
    summaryEl.innerHTML += '<span class="confidence-badge-low">unvalidated</span>';
}
```

- [ ] **Step 3: Commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add tools/athena-dashboard/index.html
git commit -m "feat(pipeline): add unvalidated badge for LOW confidence findings on dashboard"
```

---

### Task 11: End-to-End Manual Test

- [ ] **Step 1: Restart the server**

```bash
lsof -ti:8080 | xargs kill -9 2>/dev/null; sleep 1
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA/tools/athena-dashboard && .venv/bin/uvicorn server:app --host 127.0.0.1 --port 8080 --log-level info &
```

- [ ] **Step 2: Verify zero false positives**

Create an engagement, start pentest. Monitor the dashboard:
- Agent reads playbooks → NO findings (verify in bus history: `curl -s http://localhost:8080/api/bus/history | python3 -m json.tool`)
- Agent queries Neo4j → NO findings
- Agent runs nmap → ports appear as MEDIUM confidence findings
- Agent runs nuclei → CVEs appear as HIGH confidence findings

- [ ] **Step 3: Verify agent self-reporting works**

Manually test the structured publish endpoint:
```bash
curl -s -X POST http://localhost:8080/api/bus/publish \
  -H "Content-Type: application/json" \
  -d '{"agent": "WV", "finding_type": "vulnerability", "confidence": "high", "summary": "XSS in /search endpoint", "severity": "high", "target": "10.0.0.1", "evidence": {"tool": "manual", "output": "<script>alert(1)</script> reflected"}, "action_needed": "Verify session hijacking impact"}'
```
Expected: Returns `{"ok": true, "confidence": "high", ...}`, finding appears on dashboard in full color.

- [ ] **Step 4: Verify LOW confidence dimmed on dashboard**

```bash
curl -s -X POST http://localhost:8080/api/bus/publish \
  -H "Content-Type: application/json" \
  -d '{"agent": "EX", "finding_type": "shell", "confidence": "low", "summary": "Possible root shell obtained", "severity": "critical", "target": "10.0.0.1"}'
```
Expected: Finding appears on dashboard with "unvalidated" badge and dimmed styling. NOT broadcast to agents.

- [ ] **Step 5: Final commit**

```bash
cd /Users/kelvinlomboy/VERSANT/Projects/ATHENA
git add -A
git commit -m "feat: structured finding pipeline — eliminates false positives (A+ architecture)"
```
