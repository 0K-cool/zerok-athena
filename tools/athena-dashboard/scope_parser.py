"""scope_parser.py — Parse engagement scope strings into structured target objects.

Handles single IPs, CIDR ranges, hostnames, comma-separated lists, and mixed formats.
Designed for ATHENA pentest platform multi-target engagement support.
"""

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional

# Maximum number of individual hosts to expand from CIDR ranges.
# Prevents accidental /8 expansions from consuming memory.
MAX_EXPAND = 1024

# Regex for hostname validation (RFC 952/1123).
# Allows labels of letters, digits, hyphens; dots separating labels; optional port suffix.
_HOSTNAME_RE = re.compile(
    r'^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)*'
    r'[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?$'
)


@dataclass
class ScopeTarget:
    """Represents a single parsed scope entry.

    A target is exactly one of: a single IP, a CIDR range, or a hostname.
    The ``host_count`` field reflects the number of usable hosts the entry covers.
    """

    ip: Optional[str] = None         # Single IP address (string form)
    cidr: Optional[str] = None       # CIDR range (e.g. "10.1.1.0/24")
    hostname: Optional[str] = None   # Fully-qualified or short hostname
    host_count: int = 1              # Number of hosts this entry covers
    ports: list[int] = field(default_factory=list)

    def __repr__(self) -> str:  # noqa: D105
        label = self.ip or self.cidr or self.hostname or "<empty>"
        port_str = f":{self.ports}" if self.ports else ""
        return f"ScopeTarget({label}{port_str}, hosts={self.host_count})"


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_entry(raw: str) -> Optional[ScopeTarget]:
    """Parse a single whitespace-stripped scope token into a ScopeTarget.

    Returns None for tokens that are empty or completely unparseable.
    """
    raw = raw.strip()
    if not raw:
        return None

    ports: list[int] = []

    # --- Try CIDR / plain IP first (before port extraction to avoid mangling IPv6) ---
    try:
        network = ipaddress.ip_network(raw, strict=False)
        if network.prefixlen == network.max_prefixlen:
            # /32 (IPv4) or /128 (IPv6) — treat as single host
            return ScopeTarget(
                ip=str(network.network_address),
                host_count=1,
                ports=ports,
            )
        # Multi-host CIDR — num_addresses excludes network/broadcast for host count
        usable = network.num_addresses
        if network.version == 4 and network.prefixlen < 31:
            # Subtract network and broadcast addresses for /0–/30
            usable = max(1, network.num_addresses - 2)
        return ScopeTarget(
            cidr=str(network),
            host_count=usable,
            ports=ports,
        )
    except ValueError:
        pass

    # --- Port extraction for IPv4 + hostname tokens (not IPv6, which uses colons natively) ---
    # Only attempt if token contains exactly one colon — IPv6 addresses have multiple colons.
    port_match = re.match(r'^(.+):(\d{1,5})$', raw)
    if port_match and raw.count(':') == 1:
        candidate, port_str = port_match.group(1), port_match.group(2)
        port_num = int(port_str)
        if 1 <= port_num <= 65535:
            ports = [port_num]
            raw = candidate
            # After stripping the port, re-try as IP/CIDR (e.g. "10.1.1.25:8080" → "10.1.1.25")
            try:
                network = ipaddress.ip_network(raw, strict=False)
                if network.prefixlen == network.max_prefixlen:
                    return ScopeTarget(
                        ip=str(network.network_address),
                        host_count=1,
                        ports=ports,
                    )
                usable = network.num_addresses
                if network.version == 4 and network.prefixlen < 31:
                    usable = max(1, network.num_addresses - 2)
                return ScopeTarget(
                    cidr=str(network),
                    host_count=usable,
                    ports=ports,
                )
            except ValueError:
                pass

    # --- Try hostname ---
    if _HOSTNAME_RE.match(raw):
        return ScopeTarget(hostname=raw, host_count=1, ports=ports)

    # Unparseable token — skip silently
    return None


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def parse_scope(scope_string: str) -> list[ScopeTarget]:
    """Parse an engagement scope string into a list of ScopeTarget objects.

    Supports:
    - Single IP:              "10.1.1.25"
    - CIDR /32:               "10.1.1.25/32"
    - CIDR range:             "10.1.1.0/24"
    - Comma-separated:        "10.1.1.25, 10.1.1.26, 10.1.1.30"
    - Hostname:               "metasploitable.local"
    - Mixed:                  "10.1.1.0/24, 192.168.1.100, web.target.com"
    - IP with port:           "10.1.1.25:8080"
    - Empty string:           "" → []

    Returns a list of ScopeTarget dataclasses, one per valid token.
    """
    if not scope_string or not scope_string.strip():
        return []

    tokens = [t.strip() for t in scope_string.split(',')]
    targets: list[ScopeTarget] = []
    for token in tokens:
        if not token:
            continue
        target = _parse_entry(token)
        if target is not None:
            targets.append(target)
    return targets


def expand_scope_to_hosts(targets: list[ScopeTarget]) -> list[str]:
    """Expand a list of ScopeTargets to individual IP address strings.

    CIDR ranges are expanded to individual host IPs (network/broadcast excluded
    for /0–/30 IPv4 ranges). Expansion is capped at MAX_EXPAND (1024) total IPs
    as a safety guard against enormous ranges.

    Returns a flat list of IP strings (order: singles/hostnames first, then CIDR
    expansions in the order they appear).
    """
    result: list[str] = []
    for target in targets:
        if len(result) >= MAX_EXPAND:
            break
        if target.ip:
            result.append(target.ip)
        elif target.hostname:
            result.append(target.hostname)
        elif target.cidr:
            network = ipaddress.ip_network(target.cidr, strict=False)
            # Use hosts() for /0–/30 IPv4 (excludes network+broadcast);
            # for /31, /32, or IPv6 iterate all addresses.
            if network.version == 4 and network.prefixlen <= 30:
                host_iter = network.hosts()
            else:
                host_iter = network
            for addr in host_iter:
                if len(result) >= MAX_EXPAND:
                    break
                result.append(str(addr))
    return result


def estimate_engagement_scale(targets: list[ScopeTarget]) -> dict:
    """Return a scale estimate for an engagement based on total host count.

    Scale categories:
    - small      : 1–10 hosts
    - medium     : 11–100 hosts
    - large      : 101–500 hosts
    - enterprise : 501+ hosts

    Returns a dict with keys:
    - total_hosts        : int
    - scale              : str (small/medium/large/enterprise)
    - recommended_agent_teams : int   (suggested parallel agent threads)
    - estimated_findings : str   (rough range, e.g. "5–20")
    - estimated_cost_usd : str   (rough API cost estimate)
    """
    total_hosts = sum(t.host_count for t in targets)

    if total_hosts <= 10:
        scale = "small"
        agents = 1
        findings_range = "5–20"
        cost_range = "$1–$5"
    elif total_hosts <= 100:
        scale = "medium"
        agents = 3
        findings_range = "20–80"
        cost_range = "$5–$20"
    elif total_hosts <= 500:
        scale = "large"
        agents = 6
        findings_range = "50–200"
        cost_range = "$20–$80"
    else:
        scale = "enterprise"
        agents = 10
        findings_range = "100–500+"
        cost_range = "$80–$300+"

    return {
        "total_hosts": total_hosts,
        "scale": scale,
        "recommended_agent_teams": agents,
        "estimated_findings": findings_range,
        "estimated_cost_usd": cost_range,
    }
