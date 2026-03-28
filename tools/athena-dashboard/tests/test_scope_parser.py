"""Tests for scope_parser — CIDR, hostname, comma-separated, and mixed scope support."""

import sys
import os

# Allow importing scope_parser from the parent directory during test runs.
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

import pytest
from scope_parser import (
    ScopeTarget,
    parse_scope,
    expand_scope_to_hosts,
    estimate_engagement_scale,
    MAX_EXPAND,
)


# ---------------------------------------------------------------------------
# Core parse_scope tests (7 mandatory)
# ---------------------------------------------------------------------------

class TestParseScopeCore:
    def test_single_ip(self):
        """Single bare IP address → 1 ScopeTarget with ip set."""
        targets = parse_scope("10.1.1.25")
        assert len(targets) == 1
        t = targets[0]
        assert t.ip == "10.1.1.25"
        assert t.cidr is None
        assert t.hostname is None
        assert t.host_count == 1
        assert t.ports == []

    def test_cidr_32(self):
        """CIDR /32 → single-host target (ip field set, not cidr)."""
        targets = parse_scope("10.1.1.25/32")
        assert len(targets) == 1
        t = targets[0]
        assert t.ip == "10.1.1.25"
        assert t.cidr is None
        assert t.host_count == 1

    def test_cidr_24(self):
        """CIDR /24 → 1 target representing 254 usable hosts."""
        targets = parse_scope("10.1.1.0/24")
        assert len(targets) == 1
        t = targets[0]
        assert t.cidr == "10.1.1.0/24"
        assert t.ip is None
        assert t.host_count == 254

    def test_comma_separated(self):
        """Three IPs separated by commas → 3 targets."""
        targets = parse_scope("10.1.1.25, 10.1.1.26, 10.1.1.30")
        assert len(targets) == 3
        ips = {t.ip for t in targets}
        assert ips == {"10.1.1.25", "10.1.1.26", "10.1.1.30"}

    def test_mixed_scope(self):
        """Mixed CIDR + single IP + hostname → 3 targets."""
        targets = parse_scope("10.1.1.0/24, 192.168.1.100, web.target.com")
        assert len(targets) == 3

        cidrs = [t for t in targets if t.cidr]
        ips   = [t for t in targets if t.ip]
        hosts = [t for t in targets if t.hostname]

        assert len(cidrs) == 1
        assert cidrs[0].cidr == "10.1.1.0/24"
        assert len(ips) == 1
        assert ips[0].ip == "192.168.1.100"
        assert len(hosts) == 1
        assert hosts[0].hostname == "web.target.com"

    def test_hostname(self):
        """Bare hostname → 1 ScopeTarget with hostname set."""
        targets = parse_scope("metasploitable.local")
        assert len(targets) == 1
        t = targets[0]
        assert t.hostname == "metasploitable.local"
        assert t.ip is None
        assert t.cidr is None
        assert t.host_count == 1

    def test_empty_scope(self):
        """Empty string → 0 targets."""
        assert parse_scope("") == []
        assert parse_scope("   ") == []


# ---------------------------------------------------------------------------
# Additional parse_scope tests
# ---------------------------------------------------------------------------

class TestParseScopeAdditional:
    def test_ip_with_port(self):
        """IP:port notation → port extracted into ports list."""
        targets = parse_scope("10.1.1.25:8080")
        assert len(targets) == 1
        t = targets[0]
        assert t.ip == "10.1.1.25"
        assert t.ports == [8080]
        assert t.host_count == 1

    def test_hostname_with_port(self):
        """hostname:port → port extracted."""
        targets = parse_scope("web.target.com:443")
        assert len(targets) == 1
        t = targets[0]
        assert t.hostname == "web.target.com"
        assert t.ports == [443]

    def test_cidr_16(self):
        """/16 CIDR → host_count reflects large range (65534 usable)."""
        targets = parse_scope("192.168.0.0/16")
        assert len(targets) == 1
        assert targets[0].cidr == "192.168.0.0/16"
        assert targets[0].host_count == 65534

    def test_cidr_31(self):
        """/31 point-to-point subnet → 2 addresses (no broadcast exclusion)."""
        targets = parse_scope("10.0.0.0/31")
        assert len(targets) == 1
        assert targets[0].host_count == 2

    def test_whitespace_handling(self):
        """Extra whitespace around entries should not produce extra targets."""
        targets = parse_scope("  10.1.1.1  ,  10.1.1.2  ")
        assert len(targets) == 2

    def test_trailing_comma(self):
        """Trailing comma → no phantom empty target."""
        targets = parse_scope("10.1.1.1,")
        assert len(targets) == 1

    def test_invalid_token_skipped(self):
        """Unparseable tokens are silently skipped."""
        targets = parse_scope("10.1.1.1, not_valid_!@#, 10.1.1.2")
        assert len(targets) == 2
        ips = {t.ip for t in targets}
        assert ips == {"10.1.1.1", "10.1.1.2"}

    def test_ipv6_single(self):
        """IPv6 address → single-host target."""
        targets = parse_scope("::1")
        assert len(targets) == 1
        assert targets[0].ip == "::1"

    def test_repr_shows_label(self):
        """ScopeTarget __repr__ includes the label."""
        t = ScopeTarget(ip="1.2.3.4", host_count=1)
        assert "1.2.3.4" in repr(t)


# ---------------------------------------------------------------------------
# expand_scope_to_hosts tests
# ---------------------------------------------------------------------------

class TestExpandScope:
    def test_expand_scope_small(self):
        """Single /30 CIDR (2 usable hosts) expands to 2 IPs."""
        targets = parse_scope("10.0.0.0/30")
        expanded = expand_scope_to_hosts(targets)
        assert len(expanded) == 2
        assert "10.0.0.1" in expanded
        assert "10.0.0.2" in expanded

    def test_expand_scope_single_ip(self):
        """Single IP target expands to itself."""
        targets = parse_scope("192.168.1.5")
        expanded = expand_scope_to_hosts(targets)
        assert expanded == ["192.168.1.5"]

    def test_expand_scope_hostname_passthrough(self):
        """Hostname target passes through unchanged (no DNS resolution)."""
        targets = parse_scope("web.target.com")
        expanded = expand_scope_to_hosts(targets)
        assert expanded == ["web.target.com"]

    def test_expand_scope_large_cidr_safety(self):
        """Expansion from a /8 is capped at MAX_EXPAND (1024) IPs."""
        targets = parse_scope("10.0.0.0/8")
        assert targets[0].host_count > MAX_EXPAND
        expanded = expand_scope_to_hosts(targets)
        assert len(expanded) == MAX_EXPAND

    def test_expand_scope_mixed(self):
        """/30 + single IP expands to 2 + 1 = 3 entries (all under cap)."""
        targets = parse_scope("10.0.0.0/30, 192.168.1.1")
        expanded = expand_scope_to_hosts(targets)
        assert len(expanded) == 3

    def test_expand_scope_multiple_cidrs_cap(self):
        """Multiple CIDRs that collectively exceed MAX_EXPAND are capped."""
        # Two /22s = 2 * 1022 = 2044 usable hosts — well over 1024
        targets = parse_scope("10.0.0.0/22, 10.0.4.0/22")
        expanded = expand_scope_to_hosts(targets)
        assert len(expanded) == MAX_EXPAND


# ---------------------------------------------------------------------------
# estimate_engagement_scale tests
# ---------------------------------------------------------------------------

class TestEstimateScale:
    def test_estimate_scale_small(self):
        """1–10 hosts → small scale."""
        targets = parse_scope("10.1.1.1, 10.1.1.2, 10.1.1.3")
        result = estimate_engagement_scale(targets)
        assert result["scale"] == "small"
        assert result["total_hosts"] == 3
        assert result["recommended_agent_teams"] == 1

    def test_estimate_scale_medium(self):
        """11–100 hosts → medium scale."""
        # /28 = 14 usable hosts
        targets = parse_scope("10.0.0.0/28")
        result = estimate_engagement_scale(targets)
        assert result["scale"] == "medium"
        assert result["total_hosts"] == 14

    def test_estimate_scale_large(self):
        """101–500 hosts → large scale."""
        # /24 = 254 usable hosts
        targets = parse_scope("10.1.1.0/24")
        result = estimate_engagement_scale(targets)
        assert result["scale"] == "large"
        assert result["total_hosts"] == 254

    def test_estimate_scale_enterprise(self):
        """501+ hosts → enterprise scale."""
        # /22 = 1022 usable hosts
        targets = parse_scope("10.0.0.0/22")
        result = estimate_engagement_scale(targets)
        assert result["scale"] == "enterprise"
        assert result["total_hosts"] == 1022
        assert result["recommended_agent_teams"] == 10

    def test_estimate_scale_result_keys(self):
        """Result dict contains all expected keys."""
        targets = parse_scope("10.1.1.1")
        result = estimate_engagement_scale(targets)
        expected_keys = {
            "total_hosts", "scale", "recommended_agent_teams",
            "estimated_findings", "estimated_cost_usd"
        }
        assert expected_keys.issubset(result.keys())

    def test_estimate_scale_empty(self):
        """Empty target list → 0 hosts, small scale."""
        result = estimate_engagement_scale([])
        assert result["total_hosts"] == 0
        assert result["scale"] == "small"
