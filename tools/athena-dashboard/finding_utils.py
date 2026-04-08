"""Shared finding utilities for ATHENA deduplication.

Extracted from server.py so agent_session_manager.py (bus pipeline)
can use the same 5-tier fingerprint logic as /api/findings.
"""

import hashlib
import re as _re_fp


# B58 Layer 1: normalization patterns for fingerprint input.
# Applied to titles and targets BEFORE the 5-tier hash computation so that
# cross-agent duplicates (where WV and EX report the same vuln with slightly
# different wording) collapse into the same fingerprint. Previously Tier 5
# (normalized-title fallback) only collapsed whitespace, which meant titles
# that differed in IP/port/agent-prefix leaked through as separate findings.
#
# Examples of duplicates this catches:
#   "[EX] SSH Default Credentials on 10.1.1.25:22" → "ssh default credentials"
#   "VF verified: SSH default creds"               → "ssh default creds"
#   "SSH Default Credentials (root/root)"          → "ssh default credentials (root/root)"
#
# These three titles now share the same normalized form (when combined with
# the same service + host + port in Tier 4) and dedupe correctly.
_FP_IP_RE = _re_fp.compile(r'\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b')
_FP_PORT_COLON_RE = _re_fp.compile(r':\d{1,5}\b')
_FP_PORT_WORD_RE = _re_fp.compile(r'\bport\s*\d{1,5}\b', _re_fp.IGNORECASE)
_FP_AGENT_PREFIX_RE = _re_fp.compile(
    r'^(?:\[[A-Z]{2}\]|[A-Z]{2}:|[A-Z]{2}\s*-\s*)\s*', _re_fp.IGNORECASE
)
_FP_STATUS_MARKER_RE = _re_fp.compile(
    r'^(?:vf\s+verified:|confirmed:|verified:|exploit\s+confirmed:)\s*',
    _re_fp.IGNORECASE,
)
_FP_WHITESPACE_RE = _re_fp.compile(r'\s+')


def _normalize_title_for_fingerprint(title: str) -> str:
    """B58 Layer 1: normalize a finding title so cross-agent dupes collapse.

    Strips IP addresses, port numbers, agent prefixes, and status markers
    from the title. Returns a lowercased whitespace-collapsed canonical form
    suitable for hashing in Tier 4 keyword matching and Tier 5 title fallback.
    """
    if not title:
        return ""
    s = title
    # Strip leading agent prefix (e.g. "[EX] ", "WV:", "EX - ")
    s = _FP_AGENT_PREFIX_RE.sub('', s)
    # Strip leading status marker (e.g. "VF verified:", "Confirmed:")
    s = _FP_STATUS_MARKER_RE.sub('', s)
    # Strip IP addresses so "SSH on 10.1.1.25" == "SSH on 10.1.1.31"
    s = _FP_IP_RE.sub('', s)
    # Strip port colons first (":22"), then port words ("port 22")
    s = _FP_PORT_COLON_RE.sub('', s)
    s = _FP_PORT_WORD_RE.sub('', s)
    # Lowercase + collapse whitespace
    s = _FP_WHITESPACE_RE.sub(' ', s.lower()).strip()
    return s


def _normalize_target_for_fingerprint(target: str) -> str:
    """B58 Layer 1: normalize a target URL/host to a canonical host:port form.

    Strips URL scheme (http://, https://) and path/query/fragment so that
    "http://10.1.1.25:8080/admin" and "10.1.1.25:8080" hash identically.
    """
    if not target:
        return ""
    s = target.strip()
    # Strip URL scheme
    if '://' in s:
        s = s.split('://', 1)[1]
    # Strip path/query/fragment (everything after first / ? or #)
    for sep in ('/', '?', '#'):
        if sep in s:
            s = s.split(sep, 1)[0]
    return s.lower().strip()


def _compute_finding_fingerprint(
    engagement_id: str, title: str, target: str,
    cve: str | None, host_ip: str | None, service_port: int | None,
) -> str:
    """Compute a stable fingerprint for finding deduplication.

    5-tier strategy (based on Faraday/DefectDojo research):
      Tier 1: CVE + host + port (strongest — deterministic across agents)
      Tier 2: CVE + host (when port unknown)
      Tier 3: CVE only (single-target engagements)
      Tier 4: Service canonical name + host + port (non-CVE: default creds, backdoors)
      Tier 5: Normalized title + target (last resort)

    Returns 16-char hex digest (collision probability ~1 in 2^64).

    Key principle: same vulnerability on same host = same fingerprint,
    regardless of which agent reports it or how they phrase the title.
    """
    title_lower = (title or "").lower()

    # Auto-extract CVE from title if not explicitly provided
    if not cve:
        cve_match = _re_fp.search(r'CVE-\d{4}-\d+', title, _re_fp.IGNORECASE)
        if cve_match:
            cve = cve_match.group(0)

    # Auto-extract host_ip from target if not provided
    if not host_ip and target:
        ip_match = _re_fp.search(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', target)
        if ip_match:
            host_ip = ip_match.group(1)

    # Auto-extract port from target or title if not provided
    if not service_port:
        port_match = _re_fp.search(r':(\d{1,5})\b', target or '') or \
                     _re_fp.search(r'port\s*(\d{1,5})', title_lower)
        if port_match:
            p = int(port_match.group(1))
            if 1 <= p <= 65535:
                service_port = p

    # Tier 1: CVE + host + port (strongest — cross-agent, deterministic)
    if cve and host_ip and service_port:
        key = f"{engagement_id}|{cve.upper()}|{host_ip}|{service_port}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    # Tier 2: CVE + host (port unknown but host known)
    if cve and host_ip:
        key = f"{engagement_id}|{cve.upper()}|{host_ip}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    # Tier 3: CVE only (single-target engagement, host implicit)
    if cve:
        key = f"{engagement_id}|{cve.upper()}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    # Tier 4: Service-based dedup for non-CVE findings (default creds, backdoors, misconfigs)
    # Two strategies: (A) well-known port → service, (B) keyword → service
    #
    # Strategy A: Port-based service identification (works for ANY environment)
    # IANA well-known ports — not hardcoded to any specific target
    _PORT_TO_SERVICE = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 111: "rpc", 135: "msrpc", 139: "netbios",
        143: "imap", 443: "https", 445: "smb", 465: "smtps", 587: "smtp",
        993: "imaps", 995: "pop3s", 1433: "mssql", 1521: "oracle",
        1524: "ingreslock", 2049: "nfs", 2121: "ftp", 3306: "mysql",
        3389: "rdp", 3632: "distccd", 5432: "postgresql", 5900: "vnc",
        5985: "winrm", 5986: "winrm", 6379: "redis", 6667: "irc",
        8080: "http-proxy", 8443: "https-alt", 8787: "rmi",
        8888: "http-alt", 9200: "elasticsearch", 11211: "memcached",
        27017: "mongodb", 6380: "redis",
    }
    # Strategy B: Keyword-based service identification (catches service names in titles)
    # Ordered by specificity — longer/more specific keywords first
    _KEYWORD_TO_SERVICE = [
        ("apache tomcat", "tomcat"), ("tomcat", "tomcat"),
        ("postgresql", "postgresql"), ("postgres", "postgresql"), ("psql", "postgresql"),
        ("microsoft sql", "mssql"), ("mssql", "mssql"),
        ("mysql", "mysql"), ("mariadb", "mysql"),
        ("mongodb", "mongodb"), ("redis", "redis"),
        ("elasticsearch", "elasticsearch"), ("memcached", "memcached"),
        ("openssh", "ssh"), ("ssh", "ssh"),
        ("vsftpd", "ftp"), ("proftpd", "ftp"), ("pureftpd", "ftp"), ("ftp", "ftp"),
        ("samba", "smb"), ("smb", "smb"), ("cifs", "smb"),
        ("telnet", "telnet"),
        ("ingreslock", "ingreslock"), ("bindshell", "ingreslock"), ("bind shell", "ingreslock"),
        ("unrealircd", "irc"), ("irc", "irc"),
        ("distccd", "distccd"), ("distcc", "distccd"),
        ("nfs", "nfs"), ("vnc", "vnc"), ("rdp", "rdp"),
        ("rmi", "rmi"), ("java rmi", "rmi"), ("ruby drb", "rmi"),
        ("winrm", "winrm"), ("wmi", "wmi"),
        ("ldap", "ldap"), ("active directory", "ldap"),
        ("kerberos", "kerberos"), ("snmp", "snmp"),
        ("smtp", "smtp"), ("pop3", "pop3"), ("imap", "imap"),
        ("php", "php"), ("webdav", "webdav"),
        ("jenkins", "jenkins"), ("jboss", "jboss"), ("weblogic", "weblogic"),
        ("iis", "iis"), ("nginx", "nginx"), ("apache", "apache"),
        ("docker", "docker"), ("kubernetes", "kubernetes"), ("k8s", "kubernetes"),
        ("aws", "aws"), ("azure", "azure"), ("gcloud", "gcloud"),
    ]

    service = ""
    # Try port-based identification first (most reliable for any environment)
    if service_port and service_port in _PORT_TO_SERVICE:
        service = _PORT_TO_SERVICE[service_port]
    # Fall back to keyword matching in title
    if not service:
        for keyword, canonical in _KEYWORD_TO_SERVICE:
            if keyword in title_lower:
                service = canonical
                break

    if service:
        # BUG-058 FIX: Omit empty fields from the key so a finding with no host_ip
        # matches any same-service same-port finding regardless of host.
        # Prevents per-host duplication when agents report the same finding without host_ip.
        if host_ip and service_port:
            key = f"{engagement_id}|{service}|{host_ip}|{service_port}"
        elif service_port:
            key = f"{engagement_id}|{service}|{service_port}"
        else:
            key = f"{engagement_id}|{service}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    # Tier 5: Normalized title fallback (last resort — different titles = different findings)
    # B58 Layer 1: Use aggressive normalization (strip IPs, ports, agent prefixes,
    # status markers) so cross-agent dupes with slightly different wording collapse
    # to the same fingerprint. Previously this tier only collapsed whitespace,
    # which let ~12 duplicates per engagement slip through when agents phrased
    # the same vuln differently.
    title_norm = _normalize_title_for_fingerprint(title or "")
    target_norm = _normalize_target_for_fingerprint(target or "")
    key = f"{engagement_id}|{title_norm}|{target_norm}"
    return hashlib.sha256(key.encode()).hexdigest()[:16]


def _canonical_cve(cve_input) -> str | None:
    """Normalize CVE input (str, list, or None) to a single uppercase canonical CVE ID."""
    if isinstance(cve_input, list):
        cve_input = cve_input[0] if cve_input else None
    if isinstance(cve_input, str) and cve_input.strip():
        return cve_input.strip().upper()
    return None
