# SPDX-License-Identifier: AGPL-3.0-or-later
"""
ATHENA H1: Pentest Knowledge Graph Ontology for Graphiti

Defines entity and edge types for Graphiti's LLM entity extraction.
Docstrings are critical — the LLM reads them to classify entities.
"""

from pydantic import BaseModel, Field
from typing import Optional


# --- Entity Types (9) ---

class Target(BaseModel):
    """A target organization, network range, or domain being assessed in a penetration test."""
    scope: Optional[str] = Field(None, description="IP range or domain scope")
    engagement_type: Optional[str] = Field(None, description="External, Internal, Web App, API, Cloud")
    industry: Optional[str] = Field(None, description="Target industry")

class Host(BaseModel):
    """A network host, server, endpoint, or virtual machine discovered during reconnaissance."""
    ip_address: Optional[str] = Field(None, description="IPv4 or IPv6 address")
    hostname: Optional[str] = Field(None, description="DNS hostname or FQDN")
    os: Optional[str] = Field(None, description="Operating system and version")
    open_ports: Optional[str] = Field(None, description="Comma-separated list of open ports")
    is_compromised: Optional[bool] = Field(False, description="Whether this host has been compromised")

class Service(BaseModel):
    """A network service running on a host, such as HTTP, SSH, SMB, or a database."""
    name: Optional[str] = Field(None, description="Service name (e.g., Apache, OpenSSH, MySQL)")
    version: Optional[str] = Field(None, description="Service version string")
    port: Optional[int] = Field(None, description="Port number")
    protocol: Optional[str] = Field(None, description="TCP or UDP")
    banner: Optional[str] = Field(None, description="Service banner or fingerprint")

class Vulnerability(BaseModel):
    """A security vulnerability or weakness found during the penetration test."""
    cve_id: Optional[str] = Field(None, description="CVE identifier")
    cvss_score: Optional[float] = Field(None, description="CVSS v3 base score (0.0-10.0)")
    severity: Optional[str] = Field(None, description="CRITICAL, HIGH, MEDIUM, or LOW")
    vuln_type: Optional[str] = Field(None, description="OWASP category or CWE type")
    affected_component: Optional[str] = Field(None, description="Specific component affected")

class Exploit(BaseModel):
    """An exploit, proof-of-concept, or attack payload used to compromise a vulnerability."""
    tool: Optional[str] = Field(None, description="Tool used (e.g., sqlmap, metasploit)")
    payload: Optional[str] = Field(None, description="Attack payload or technique description")
    success: Optional[bool] = Field(None, description="Whether the exploit succeeded")
    source: Optional[str] = Field(None, description="Exploit source (ExploitDB, Metasploit, GitHub)")

class Credential(BaseModel):
    """Credentials discovered, cracked, or extracted during the penetration test."""
    username: Optional[str] = Field(None, description="Username or account name")
    credential_type: Optional[str] = Field(None, description="password, hash, token, key, certificate")
    service: Optional[str] = Field(None, description="Service these credentials are valid for")
    privilege_level: Optional[str] = Field(None, description="user, admin, root, domain_admin")

class Technique(BaseModel):
    """A MITRE ATT&CK technique or PTES methodology step used during the engagement."""
    mitre_id: Optional[str] = Field(None, description="MITRE ATT&CK technique ID (e.g., T1190)")
    tactic: Optional[str] = Field(None, description="ATT&CK tactic (e.g., Initial Access)")
    ptes_phase: Optional[str] = Field(None, description="PTES phase (e.g., Exploitation)")

class Tool(BaseModel):
    """A security tool used during the penetration test engagement."""
    name: Optional[str] = Field(None, description="Tool name (e.g., nmap, gobuster, sqlmap)")
    category: Optional[str] = Field(None, description="Tool category (recon, vuln_scan, exploit)")
    effectiveness: Optional[str] = Field(None, description="How effective: high, medium, low, none")

class Defense(BaseModel):
    """A security defense, WAF, or mitigation encountered during testing."""
    name: Optional[str] = Field(None, description="Defense name (e.g., Cloudflare WAF)")
    type: Optional[str] = Field(None, description="WAF, IDS, IPS, firewall, rate_limit, CAPTCHA")
    bypass_found: Optional[bool] = Field(None, description="Whether a bypass was discovered")
    bypass_technique: Optional[str] = Field(None, description="Description of bypass method")


# --- Edge Types (7) ---

class RunsOn(BaseModel):
    """A service runs on a specific host and port."""
    port: Optional[int] = Field(None, description="Port number")

class HasVulnerability(BaseModel):
    """A service or host has a specific vulnerability."""
    discovery_method: Optional[str] = Field(None, description="How the vuln was found")
    confirmed: Optional[bool] = Field(None, description="Whether confirmed")

class ExploitedBy(BaseModel):
    """A vulnerability was exploited using a specific exploit or technique."""
    success: Optional[bool] = Field(None, description="Whether exploitation succeeded")
    impact: Optional[str] = Field(None, description="Impact: RCE, data_access, privilege_escalation")

class AuthenticatesTo(BaseModel):
    """Credentials authenticate to a specific service or host."""
    method: Optional[str] = Field(None, description="Auth method: password, key, token, pass-the-hash")

class LateralMovement(BaseModel):
    """Movement from one compromised host to another."""
    technique: Optional[str] = Field(None, description="Lateral movement technique used")
    tool: Optional[str] = Field(None, description="Tool used for lateral movement")

class ProtectedBy(BaseModel):
    """A service or host is protected by a defense mechanism."""
    effectiveness: Optional[str] = Field(None, description="blocked, partially_bypassed, fully_bypassed")

class ChainedWith(BaseModel):
    """Two techniques or exploits are chained together in an attack path."""
    order: Optional[int] = Field(None, description="Position in the attack chain")
    dependency: Optional[str] = Field(None, description="What the next step depends on")


# --- Ontology Registration ---

ENTITY_TYPES = {
    "Target": Target, "Host": Host, "Service": Service,
    "Vulnerability": Vulnerability, "Exploit": Exploit, "Credential": Credential,
    "Technique": Technique, "Tool": Tool, "Defense": Defense,
}

EDGE_TYPES = {
    "RunsOn": RunsOn, "HasVulnerability": HasVulnerability,
    "ExploitedBy": ExploitedBy, "AuthenticatesTo": AuthenticatesTo,
    "LateralMovement": LateralMovement, "ProtectedBy": ProtectedBy,
    "ChainedWith": ChainedWith,
}

EDGE_TYPE_MAP = {
    ("Service", "Host"): ["RunsOn"],
    ("Host", "Vulnerability"): ["HasVulnerability"],
    ("Service", "Vulnerability"): ["HasVulnerability"],
    ("Vulnerability", "Exploit"): ["ExploitedBy"],
    ("Credential", "Host"): ["AuthenticatesTo"],
    ("Credential", "Service"): ["AuthenticatesTo"],
    ("Host", "Host"): ["LateralMovement"],
    ("Host", "Defense"): ["ProtectedBy"],
    ("Service", "Defense"): ["ProtectedBy"],
    ("Technique", "Technique"): ["ChainedWith"],
    ("Exploit", "Exploit"): ["ChainedWith"],
    ("Tool", "Vulnerability"): ["HasVulnerability"],
}
