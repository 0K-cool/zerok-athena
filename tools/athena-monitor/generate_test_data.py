#!/usr/bin/env python3
"""
Test Data Generator for ATHENA Monitor v2.0
Generates realistic penetration testing data for UI testing
"""

import sys
sys.path.insert(0, '.')

from athena_monitor_v2 import PentestDatabase
from datetime import datetime, timedelta
import random

# Initialize database
db = PentestDatabase()

# Sample data
ENGAGEMENT = "BVHPR_2025-12-15_External-Internal"
TARGET_IP = "192.168.70.13"

print("🔧 Generating test data for ATHENA Monitor v2.0...")
print(f"📁 Engagement: {ENGAGEMENT}")
print(f"🎯 Target: {TARGET_IP}\n")

# Create engagement
try:
    eng_id = db.create_engagement(
        name=ENGAGEMENT,
        client="Buena Vista Home and Healthcare",
        engagement_type="External + Internal",
        scope=f"{TARGET_IP}, bvhpr.org, *.bvhpr.org",
        authorization_verified=True
    )
    print(f"✅ Created engagement (ID: {eng_id})")
except Exception as e:
    print(f"⚠️  Engagement already exists: {e}")

# ===========================================================================
# SERVICES (from Nmap scan)
# ===========================================================================

services_data = [
    (21, 'tcp', 'open', 'ftp', 'vsftpd', '2.3.4'),
    (22, 'tcp', 'open', 'ssh', 'OpenSSH', '4.7p1 Debian 8ubuntu1'),
    (23, 'tcp', 'open', 'telnet', 'Linux telnetd', ''),
    (25, 'tcp', 'open', 'smtp', 'Postfix', ''),
    (53, 'tcp', 'open', 'domain', 'ISC BIND', '9.4.2'),
    (80, 'tcp', 'open', 'http', 'Apache httpd', '2.2.8'),
    (111, 'tcp', 'open', 'rpcbind', '', '2'),
    (139, 'tcp', 'open', 'netbios-ssn', 'Samba smbd', '3.X - 4.X'),
    (445, 'tcp', 'open', 'netbios-ssn', 'Samba smbd', '3.0.20-Debian'),
    (512, 'tcp', 'open', 'exec', 'netkit-rsh', ''),
    (513, 'tcp', 'open', 'login', '', ''),
    (514, 'tcp', 'open', 'shell', '', ''),
    (1099, 'tcp', 'open', 'java-rmi', 'GNU Classpath', ''),
    (1524, 'tcp', 'open', 'bindshell', 'Metasploitable', ''),
    (2049, 'tcp', 'open', 'nfs', '', '2-4'),
    (2121, 'tcp', 'open', 'ftp', 'ProFTPD', '1.3.1'),
    (3306, 'tcp', 'open', 'mysql', '', ''),
    (3632, 'tcp', 'open', 'distccd', 'distccd', 'v1'),
    (5432, 'tcp', 'open', 'postgresql', 'PostgreSQL DB', '8.3.0 - 8.3.7'),
    (5900, 'tcp', 'open', 'vnc', 'VNC', ''),
    (6000, 'tcp', 'open', 'X11', '', ''),
    (6667, 'tcp', 'open', 'irc', 'UnrealIRCd', ''),
    (6697, 'tcp', 'open', 'irc', 'UnrealIRCd', ''),
    (8009, 'tcp', 'open', 'ajp13', 'Apache Jserv', ''),
    (8180, 'tcp', 'open', 'http', 'Apache Tomcat/Coyote', ''),
    (8787, 'tcp', 'open', 'drb', 'Ruby DRb RMI', ''),
]

print("\n📡 Creating services...")
for port, protocol, state, name, product, version in services_data:
    service_id = db.create_service(
        engagement=ENGAGEMENT,
        host=TARGET_IP,
        port=port,
        protocol=protocol,
        state=state,
        name=name,
        product=product,
        version=version
    )

print(f"✅ Created {len(services_data)} services")

# ===========================================================================
# VULNERABILITIES
# ===========================================================================

vulnerabilities_data = [
    {
        'severity': 'CRITICAL',
        'category': 'Root Shell Backdoor',
        'title': 'Metasploitable Root Shell Backdoor',
        'description': 'Port 1524 exposes a root shell backdoor allowing unauthenticated remote code execution',
        'port': 1524,
        'protocol': 'tcp',
        'cve_id': None,
        'cvss_score': 10.0,
        'status': 'verified'
    },
    {
        'severity': 'CRITICAL',
        'category': 'Backdoor',
        'title': 'vsftpd 2.3.4 Backdoor',
        'description': 'Malicious backdoor version of vsftpd that allows remote code execution',
        'port': 21,
        'protocol': 'tcp',
        'cve_id': None,
        'cvss_score': 10.0,
        'status': 'identified'
    },
    {
        'severity': 'CRITICAL',
        'category': 'Remote Code Execution',
        'title': 'UnrealIRCd Backdoor',
        'description': 'Backdoored version of UnrealIRCd IRC daemon allowing remote command execution',
        'port': 6667,
        'protocol': 'tcp',
        'cve_id': None,
        'cvss_score': 10.0,
        'status': 'identified'
    },
    {
        'severity': 'CRITICAL',
        'category': 'Remote Code Execution',
        'title': 'DistCC Daemon RCE',
        'description': 'DistCC v1 allows arbitrary command execution',
        'port': 3632,
        'protocol': 'tcp',
        'cve_id': None,
        'cvss_score': 9.8,
        'status': 'identified'
    },
    {
        'severity': 'HIGH',
        'category': 'Multiple Vulnerabilities',
        'title': 'Samba 3.0.20 Multiple Vulnerabilities',
        'description': 'Multiple known vulnerabilities in Samba smbd 3.0.20',
        'port': 445,
        'protocol': 'tcp',
        'cve_id': None,
        'cvss_score': 8.1,
        'status': 'identified'
    },
    {
        'severity': 'HIGH',
        'category': 'Service Misconfiguration',
        'title': 'Rsh Service Enabled',
        'description': 'Remote shell service enabled without authentication',
        'port': 514,
        'protocol': 'tcp',
        'cve_id': None,
        'cvss_score': 7.5,
        'status': 'identified'
    },
    {
        'severity': 'HIGH',
        'category': 'Service Misconfiguration',
        'title': 'Rlogin Service Enabled',
        'description': 'Remote login service enabled without proper authentication',
        'port': 513,
        'protocol': 'tcp',
        'cve_id': None,
        'cvss_score': 7.5,
        'status': 'identified'
    },
    {
        'severity': 'MEDIUM',
        'category': 'Null Session',
        'title': 'SMB Null Session',
        'description': 'Samba allows anonymous null sessions for enumeration',
        'port': 139,
        'protocol': 'tcp',
        'cve_id': None,
        'cvss_score': 5.3,
        'status': 'identified'
    },
    {
        'severity': 'MEDIUM',
        'category': 'Anonymous Access',
        'title': 'Anonymous FTP Access',
        'description': 'FTP server allows anonymous login',
        'port': 21,
        'protocol': 'tcp',
        'cve_id': None,
        'cvss_score': 5.3,
        'status': 'verified'
    },
    {
        'severity': 'MEDIUM',
        'category': 'Weak Authentication',
        'title': 'PostgreSQL DB Weak Authentication',
        'description': 'PostgreSQL database accessible with weak or default credentials',
        'port': 5432,
        'protocol': 'tcp',
        'cve_id': None,
        'cvss_score': 6.5,
        'status': 'identified'
    },
]

print("\n🔓 Creating vulnerabilities...")
for vuln in vulnerabilities_data:
    finding_id = db.create_finding(
        engagement=ENGAGEMENT,
        host=TARGET_IP,
        severity=vuln['severity'],
        category=vuln['category'],
        title=vuln['title'],
        description=vuln['description'],
        port=vuln['port'],
        protocol=vuln['protocol'],
        cve_id=vuln['cve_id'],
        cvss_score=vuln['cvss_score'],
        status=vuln['status']
    )

print(f"✅ Created {len(vulnerabilities_data)} vulnerabilities")

# ===========================================================================
# COMMAND ACTIVITY (realistic pentest workflow)
# ===========================================================================

commands_data = [
    {
        'phase': 'reconnaissance',
        'command': f'nmap -sS -sV -O -p- {TARGET_IP}',
        'tool': 'nmap',
        'summary': 'None',
        'duration': 1205.3
    },
    {
        'phase': 'reconnaissance',
        'command': f'ping -c 3 {TARGET_IP}',
        'tool': 'ping',
        'summary': 'Host is alive and responsive',
        'duration': 3.2
    },
    {
        'phase': 'reconnaissance',
        'command': f'nmap -sT {TARGET_IP}',
        'tool': 'nmap',
        'summary': 'Initial port scan revealed 23 open services including ftp, ssh, telnet, smtp, domain, http, rpcbind, netbios-ssn, microsoft-ds, login, shell, nfs, ccproxy-ftp, mysql, postgresql, vnc, X11, ajp13.',
        'duration': 45.7
    },
    {
        'phase': 'enumeration',
        'command': f'curl http://{TARGET_IP}',
        'tool': 'curl',
        'summary': 'Web server identified as Apache 2.2.8 with default Metasploitable page',
        'duration': 0.8
    },
    {
        'phase': 'enumeration',
        'command': f'curl -I http://{TARGET_IP}',
        'tool': 'curl',
        'summary': 'None',
        'duration': 0.3
    },
    {
        'phase': 'enumeration',
        'command': f'ftp {TARGET_IP}',
        'tool': 'ftp',
        'summary': 'None',
        'duration': 2.1
    },
    {
        'phase': 'enumeration',
        'command': f'ssh -o ConnectTimeout=5 msfadmin@{TARGET_IP}',
        'tool': 'ssh',
        'summary': 'None',
        'duration': 5.2
    },
    {
        'phase': 'vulnerability_assessment',
        'command': f'enum4linux {TARGET_IP}',
        'tool': 'enum4linux',
        'summary': 'None',
        'duration': 23.5
    },
    {
        'phase': 'exploitation',
        'command': f'smbclient //{TARGET_IP}/tmp',
        'tool': 'smbclient',
        'summary': 'None',
        'duration': 1.9
    },
    {
        'phase': 'enumeration',
        'command': f'nc -w 3 {TARGET_IP} 3632',
        'tool': 'netcat',
        'summary': 'None',
        'duration': 3.1
    },
    {
        'phase': 'exploitation',
        'command': f'nc {TARGET_IP} 1524',
        'tool': 'netcat',
        'summary': 'None',
        'duration': 0.4
    },
    {
        'phase': 'post_exploitation',
        'command': 'whoami; id; uname -a',
        'tool': 'shell',
        'summary': 'None',
        'duration': 0.2
    },
    {
        'phase': 'post_exploitation',
        'command': 'cat /etc/passwd | head -10',
        'tool': 'shell',
        'summary': 'None',
        'duration': 0.1
    },
    {
        'phase': 'post_exploitation',
        'command': 'ifconfig; netstat -tulpn',
        'tool': 'shell',
        'summary': 'None',
        'duration': 0.3
    },
]

print("\n⚡ Creating command activity...")
base_time = datetime.now() - timedelta(hours=2)

for i, cmd in enumerate(commands_data):
    cmd_time = base_time + timedelta(minutes=i*5)

    db.record_command(
        engagement=ENGAGEMENT,
        host=TARGET_IP,
        phase=cmd['phase'],
        command=cmd['command'],
        tool=cmd['tool'],
        summary=cmd['summary'],
        output=None,  # Not storing full output in this test
        duration=cmd['duration']
    )

print(f"✅ Created {len(commands_data)} commands")

# ===========================================================================
# SUMMARY
# ===========================================================================

print("\n" + "="*70)
print("✅ TEST DATA GENERATION COMPLETE")
print("="*70)
print(f"\n📊 Summary:")
print(f"   • Engagement: {ENGAGEMENT}")
print(f"   • Target Host: {TARGET_IP}")
print(f"   • Services: {len(services_data)}")
print(f"   • Vulnerabilities: {len(vulnerabilities_data)}")
print(f"   • Commands: {len(commands_data)}")
print(f"\n🚀 Start the monitor:")
print(f"   cd tools/athena-monitor")
print(f"   python3 athena_monitor_v2.py")
print(f"\n🌐 Access the dashboard:")
print(f"   http://localhost:8080")
print(f"\n📱 Available pages:")
print(f"   • Command Activity: http://localhost:8080/")
print(f"   • Services: http://localhost:8080/services")
print(f"   • Vulnerabilities: http://localhost:8080/vulnerabilities")
print("")
