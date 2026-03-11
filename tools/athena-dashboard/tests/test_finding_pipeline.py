"""Tests for the structured finding pipeline."""
import pytest
from finding_pipeline import (
    FindingSchema, validate_finding,
    ScannerExtractor, CatchAllHeuristic, FindingDedup, extract_findings_v2,
)


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
        """Same finding_type + target + summary -> same dedup_key."""
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

    def test_to_dict_roundtrip(self):
        f = FindingSchema(
            finding_type="cve", confidence="high", source="agent",
            summary="CVE-2023-1234", severity="high", target="10.0.0.1",
            cve=["CVE-2023-1234"],
        )
        d = f.to_dict()
        assert d["finding_type"] == "cve"
        assert d["cve"] == ["CVE-2023-1234"]
        assert d["dedup_key"] == f.dedup_key


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
        output = "# SQL Injection Testing Playbook\n## Overview\nSQL injection (SQLi) is a methodology for structured approach"
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
        """nmap ... | grep ... -> 'nmap' is whitelisted."""
        output = "22/tcp open ssh OpenSSH 8.9p1"
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

    def test_sudo_prefix_stripped(self):
        output = "22/tcp open ssh OpenSSH 8.9p1"
        findings = self.extractor.extract("AR", "Bash", output, command="sudo nmap -sV 10.0.0.1")
        assert len(findings) >= 1

    def test_file_content_skipped(self):
        """Read tool format (line-numbered) should be skipped."""
        output = "     1\u2192some content\n     2\u2192more content"
        findings = self.extractor.extract("AR", "Bash", output, command="nmap -sV 10.0.0.1")
        assert len(findings) == 0


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
        output = "Vulnerable to CVE-2024-99999 -- remote code execution"
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
        output = "# Privilege Escalation\n## Overview\nCheck uid=0(root) after exploit methodology"
        findings = self.heuristic.check("WV", output)
        # Playbook guard catches it (3+ indicators: # , ## , methodology)
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
        assert result is not None  # State changed -- re-emit
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
