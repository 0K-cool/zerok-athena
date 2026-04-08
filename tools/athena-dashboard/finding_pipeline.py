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
import time
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

    # Timestamps
    discovered_at: float = field(default_factory=time.time)
    confirmed_at: float | None = None

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
            "discovered_at": self.discovered_at,
            "confirmed_at": self.confirmed_at,
        }


_TITLE_ERROR_PATTERNS = [
    "<html", "<!doctype", "502 bad gateway", "503 service unavailable",
    "504 gateway timeout", "500 internal server error", "connection refused",
    "connection timed out", "errno", "traceback (most recent call last)",
    '{"error":', '"type": "missing"', "api validation error", "failed to fetch",
    "422 unprocessable", "field required",
]


def validate_finding(body: dict) -> FindingSchema | None:
    """Validate and normalize an API body into a FindingSchema.

    Used by POST /api/bus/publish for agent self-reports.
    Returns None if the body looks like an error response rather than a finding.
    """
    title = (body.get("title") or body.get("summary") or "").strip()
    if not title or len(title) < 5:
        return None
    title_lower = title.lower()
    if any(pat in title_lower for pat in _TITLE_ERROR_PATTERNS):
        logger.warning("Rejected finding with error-like title: %s", title[:80])
        return None
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


def _is_version_string_ip(ip: str | None) -> bool:
    """B53: Return True if the IP looks like a version string (all 4 octets < 20).

    The _IP_RE pattern captures dotted-quad numbers without distinguishing real
    IPs from software version banners like Samba `3.2.8.1` or UnrealIRCd `3.2.8.1`.
    Without this filter, the finding pipeline creates findings with `host_ip="3.2.8.1"`
    that get MERGED as phantom Host nodes in Neo4j. Mirrors the same-named helper
    at server.py:2027.
    """
    if not ip:
        return False
    parts = ip.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(int(p) < 20 for p in parts)
    except ValueError:
        return False

# Credential patterns for scanner output (hydra, crackmapexec, etc.)
_CRED_RE = re.compile(
    r'(?:login|user(?:name)?)\s*[:=]\s*(\S+)\s+'
    r'(?:password|pass)\s*[:=]\s*(\S+)', re.IGNORECASE)
_CRED_KEYWORDS = (
    "valid credentials", "password found", "login successful",
    "authenticated successfully", "creds found", "default credentials",
)

# Playbook content guard
_PLAYBOOK_INDICATORS = ("# ", "## ", "playbook", "testing guide",
                        "methodology", "**tactic**", "**technique**",
                        "owasp reference", "structured approach")


def _extract_scanner_command(command: str) -> str | None:
    """Extract the scanner name from a Bash command string.

    Returns the first token if it's in SCANNER_COMMANDS, else None.
    Handles pipes: 'nmap -sV 10.0.0.1 | grep open' → 'nmap'.
    """
    if not command:
        return None
    cmd = command.strip()
    for prefix in ("sudo ", "bash -c ", "sh -c "):
        if cmd.startswith(prefix):
            cmd = cmd[len(prefix):].lstrip("'\"")
    first_token = cmd.split()[0].split("/")[-1] if cmd.split() else ""
    return first_token if first_token in SCANNER_COMMANDS else None


def _is_file_content(output: str) -> bool:
    """Check if output looks like Read tool output (line-numbered format)."""
    return bool(re.match(r'\s*\d+→', output))


def _is_playbook_content(output_lower: str) -> bool:
    """Check if output looks like playbook/documentation."""
    return sum(1 for kw in _PLAYBOOK_INDICATORS if kw in output_lower) >= 3


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
        if not tool_output or len(tool_output) < 20:
            return []

        if tool_name not in _EXTRACTABLE_TOOLS:
            return []

        scanner = _extract_scanner_command(command)
        if not scanner:
            return []

        output = tool_output[:8000]
        output_lower = output.lower()

        if _is_file_content(output):
            return []

        if _is_playbook_content(output_lower):
            return []

        findings: list[FindingSchema] = []

        # 1. CVEs (HIGH confidence from scanner)
        cve_matches = _CVE_RE.findall(output)
        if cve_matches:
            cves = list(set(cve_matches))[:5]
            ip_match = _IP_RE.search(output)
            target = ip_match.group(1) if ip_match else None
            if target in _LOCALHOST or _is_version_string_ip(target):
                target = None  # B53: drop version-string IPs (e.g. Samba 3.2.8.1)
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
            if target in _LOCALHOST or _is_version_string_ip(target):
                target = None  # B53
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
            if _is_version_string_ip(target):  # B53
                target = None
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
            if target not in _LOCALHOST and not _is_version_string_ip(target):  # B53
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


# ── Catch-All Strong Signals ──────────────────────────────

_STRONG_SIGNALS: list[tuple[re.Pattern, str]] = [
    (re.compile(r'uid=\d+\(root\)'), "shell"),
    (re.compile(r'root@[\w.-]+[:#]'), "shell"),
    (re.compile(r'NT AUTHORITY\\SYSTEM', re.IGNORECASE), "shell"),
    (re.compile(r'meterpreter\s*>', re.IGNORECASE), "shell"),
    (re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE), "cve"),
]


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

        if _is_file_content(output):
            return []

        if _is_playbook_content(output_lower):
            return []

        findings: list[FindingSchema] = []
        seen_types: set[str] = set()

        for pattern, finding_type in _STRONG_SIGNALS:
            if finding_type in seen_types:
                continue
            match = pattern.search(output)
            if match:
                seen_types.add(finding_type)
                ip_match = _IP_RE.search(output)
                target = ip_match.group(1) if ip_match else None
                if target in _LOCALHOST or _is_version_string_ip(target):
                    target = None  # B53

                summary = f"Strong signal ({finding_type}): {output[:200]}"
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

        state_upgraded = (
            _STATE_ORDER.get(finding.state, 0)
            > _STATE_ORDER.get(existing.state, 0)
        )
        confidence_upgraded = (
            _CONFIDENCE_ORDER.get(finding.confidence, 0)
            > _CONFIDENCE_ORDER.get(existing.confidence, 0)
        )

        if state_upgraded or confidence_upgraded:
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

        return None

    def reset(self):
        self._seen.clear()


# ── Pipeline Orchestrator ──────────────────────────────────

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

    if tool_name not in _EXTRACTABLE_TOOLS:
        return []

    findings = _scanner_extractor.extract(agent_code, tool_name, tool_output, command)
    if findings:
        return findings

    return _catchall_heuristic.check(agent_code, tool_output)
