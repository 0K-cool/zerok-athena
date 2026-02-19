# mcp-servers/kali-neo4j-bridge/tests/test_bridge.py
import sys
import os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))
from bridge import parse_naabu_results, parse_nuclei_results, parse_httpx_results, validate_scope

def test_parse_naabu_text():
    raw = "10.0.0.5:80\n10.0.0.5:443\n10.0.0.6:22"
    results = parse_naabu_results(raw, "eng-001")
    assert len(results) == 3
    assert results[0] == {"ip": "10.0.0.5", "port": 80, "protocol": "tcp"}

def test_parse_naabu_json():
    raw = '{"ip":"10.0.0.5","port":80}\n{"ip":"10.0.0.5","port":443}'
    results = parse_naabu_results(raw, "eng-001")
    assert len(results) == 2

def test_validate_scope_cidr():
    scope = {"targets": ["10.0.0.0/24"], "exclusions": ["10.0.0.1"]}
    assert validate_scope("10.0.0.5", scope) == True
    assert validate_scope("10.0.0.1", scope) == False  # excluded
    assert validate_scope("192.168.1.1", scope) == False  # out of range

def test_validate_scope_wildcard():
    scope = {"targets": ["*.example.com"], "exclusions": []}
    assert validate_scope("web.example.com", scope) == True
    assert validate_scope("other.com", scope) == False
