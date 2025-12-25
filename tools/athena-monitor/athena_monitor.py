#!/usr/bin/env python3
"""
ATHENA Monitor - Strategic Penetration Testing Dashboard
Real-time monitoring and auditing for AI-powered multi-agent penetration testing

ATHENA: Automated Tactical Hacking and Exploitation Network Architecture
Enhanced with: NiceGUI for superior real-time capabilities
"""

import sqlite3
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path
from nicegui import ui, app
import asyncio

# ============================================================================
# DATABASE LAYER
# ============================================================================

class PentestDatabase:
    """SQLite database for pentest activity tracking"""

    def __init__(self, db_path: str = "pentest_tracker.db"):
        self.db_path = db_path
        self.init_database()

    def init_database(self):
        """Initialize database schema"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Commands table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS commands (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                engagement TEXT NOT NULL,
                phase TEXT NOT NULL,
                command TEXT NOT NULL,
                tool TEXT,
                target TEXT,
                output TEXT,
                status TEXT DEFAULT 'executed',
                duration_seconds REAL
            )
        """)

        # Findings table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS findings (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                engagement TEXT NOT NULL,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                target TEXT,
                evidence_path TEXT,
                cvss_score REAL,
                cve_id TEXT,
                status TEXT DEFAULT 'discovered',
                validated BOOLEAN DEFAULT 0
            )
        """)

        # Scan progress table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_progress (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                engagement TEXT NOT NULL,
                phase TEXT NOT NULL,
                target TEXT NOT NULL,
                progress REAL DEFAULT 0.0,
                status TEXT DEFAULT 'pending',
                started_at TEXT,
                completed_at TEXT,
                total_hosts INTEGER,
                scanned_hosts INTEGER
            )
        """)

        # HITL approvals table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS hitl_approvals (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                engagement TEXT NOT NULL,
                checkpoint_type TEXT NOT NULL,
                description TEXT,
                approved BOOLEAN,
                approver TEXT,
                notes TEXT
            )
        """)

        # Engagements table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS engagements (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT UNIQUE NOT NULL,
                client TEXT NOT NULL,
                engagement_type TEXT NOT NULL,
                started_at TEXT NOT NULL,
                status TEXT DEFAULT 'active',
                scope TEXT,
                authorization_verified BOOLEAN DEFAULT 0
            )
        """)

        conn.commit()
        conn.close()

    def record_command(self, engagement: str, phase: str, command: str,
                      tool: str = None, target: str = None, output: str = None,
                      duration: float = None) -> int:
        """Record executed command"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO commands (timestamp, engagement, phase, command, tool, target, output, duration_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), engagement, phase, command, tool, target, output, duration))

        command_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return command_id

    def search_commands(self, engagement: str = None, tool: str = None,
                       target: str = None, limit: int = 100) -> List[Dict]:
        """Search previous commands to prevent redundant work"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = "SELECT * FROM commands WHERE 1=1"
        params = []

        if engagement:
            query += " AND engagement = ?"
            params.append(engagement)
        if tool:
            query += " AND tool = ?"
            params.append(tool)
        if target:
            query += " AND target = ?"
            params.append(target)

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]

        conn.close()
        return results

    def create_finding(self, engagement: str, severity: str, category: str,
                      title: str, description: str = None, target: str = None,
                      evidence_path: str = None, cvss_score: float = None,
                      cve_id: str = None) -> int:
        """Create vulnerability finding"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO findings (timestamp, engagement, severity, category, title,
                                description, target, evidence_path, cvss_score, cve_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), engagement, severity, category, title,
              description, target, evidence_path, cvss_score, cve_id))

        finding_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return finding_id

    def list_findings(self, engagement: str = None, severity: str = None,
                     validated: bool = None) -> List[Dict]:
        """List findings with optional filters"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = "SELECT * FROM findings WHERE 1=1"
        params = []

        if engagement:
            query += " AND engagement = ?"
            params.append(engagement)
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if validated is not None:
            query += " AND validated = ?"
            params.append(1 if validated else 0)

        query += " ORDER BY timestamp DESC"

        cursor.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]

        conn.close()
        return results

    def update_scan_progress(self, engagement: str, phase: str, target: str,
                            progress: float, scanned_hosts: int = 0,
                            total_hosts: int = 0):
        """Update scan progress for real-time monitoring"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        # Check if record exists
        cursor.execute("""
            SELECT id FROM scan_progress
            WHERE engagement = ? AND phase = ? AND target = ?
        """, (engagement, phase, target))

        existing = cursor.fetchone()

        if existing:
            # Update existing record
            cursor.execute("""
                UPDATE scan_progress
                SET progress = ?, scanned_hosts = ?, total_hosts = ?
                WHERE id = ?
            """, (progress, scanned_hosts, total_hosts, existing[0]))
        else:
            # Create new record
            cursor.execute("""
                INSERT INTO scan_progress
                (engagement, phase, target, progress, scanned_hosts, total_hosts, started_at)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (engagement, phase, target, progress, scanned_hosts, total_hosts,
                  datetime.now().isoformat()))

        conn.commit()
        conn.close()

    def record_hitl_approval(self, engagement: str, checkpoint_type: str,
                            description: str, approved: bool, approver: str,
                            notes: str = None) -> int:
        """Record HITL checkpoint approval/denial"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO hitl_approvals
            (timestamp, engagement, checkpoint_type, description, approved, approver, notes)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), engagement, checkpoint_type, description,
              1 if approved else 0, approver, notes))

        approval_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return approval_id

    def create_engagement(self, name: str, client: str, engagement_type: str,
                         scope: str = None, authorization_verified: bool = False) -> int:
        """Create new engagement"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO engagements
            (name, client, engagement_type, started_at, scope, authorization_verified)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (name, client, engagement_type, datetime.now().isoformat(), scope,
              1 if authorization_verified else 0))

        engagement_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return engagement_id

    def get_active_engagements(self) -> List[Dict]:
        """Get all active engagements"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            SELECT * FROM engagements WHERE status = 'active' ORDER BY started_at DESC
        """)

        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]

        conn.close()
        return results

# ============================================================================
# NICEGUI DASHBOARD
# ============================================================================

# Initialize database
db = PentestDatabase()

# Global state
current_engagement = None
auto_refresh_enabled = True

def get_severity_color(severity: str) -> str:
    """Get color for severity badge"""
    colors = {
        'CRITICAL': 'red',
        'HIGH': 'orange',
        'MEDIUM': 'yellow',
        'LOW': 'blue',
        'INFO': 'gray'
    }
    return colors.get(severity.upper(), 'gray')

def get_severity_icon(severity: str) -> str:
    """Get icon for severity"""
    icons = {
        'CRITICAL': '🔴',
        'HIGH': '🟠',
        'MEDIUM': '🟡',
        'LOW': '🔵',
        'INFO': '⚪'
    }
    return icons.get(severity.upper(), '⚪')

# ============================================================================
# DASHBOARD PAGES
# ============================================================================

@ui.page('/')
def main_dashboard():
    """Main dashboard - overview of all engagements"""

    def refresh_dashboard():
        """Refresh dashboard data"""
        engagements_container.clear()

        with engagements_container:
            engagements = db.get_active_engagements()

            if not engagements:
                ui.label('No active engagements').classes('text-gray-500 text-lg')
                ui.button('Create New Engagement', on_click=lambda: ui.navigate.to('/engagement/new'))
            else:
                for eng in engagements:
                    with ui.card().classes('w-full'):
                        ui.label(eng['name']).classes('text-2xl font-bold')
                        ui.label(f"Client: {eng['client']}").classes('text-gray-600')
                        ui.label(f"Type: {eng['engagement_type']}").classes('text-gray-600')

                        # Get stats
                        findings = db.list_findings(engagement=eng['name'])
                        critical_count = len([f for f in findings if f['severity'] == 'CRITICAL'])
                        high_count = len([f for f in findings if f['severity'] == 'HIGH'])

                        with ui.row():
                            ui.badge(f"{critical_count} Critical", color='red')
                            ui.badge(f"{high_count} High", color='orange')
                            ui.badge(f"{len(findings)} Total Findings", color='blue')

                        ui.button('View Details',
                                on_click=lambda e=eng: ui.navigate.to(f'/engagement/{e["name"]}'))

    with ui.header().classes('bg-indigo-600'):
        with ui.row().classes('w-full items-center'):
            ui.label('🏛️ ATHENA Monitor').classes('text-2xl text-white font-bold')
            ui.space()
            ui.button('Refresh', icon='refresh', on_click=refresh_dashboard).props('flat color=white')

    with ui.column().classes('w-full p-4'):
        ui.label('Active Engagements').classes('text-3xl font-bold mb-4')

        engagements_container = ui.column().classes('w-full gap-4')

        # Initial load
        refresh_dashboard()

        # Auto-refresh every 10 seconds
        if auto_refresh_enabled:
            ui.timer(10.0, refresh_dashboard)

@ui.page('/engagement/{name}')
def engagement_details(name: str):
    """Detailed view of specific engagement"""

    findings_container = ui.column()
    commands_container = ui.column()

    def refresh_findings():
        """Refresh findings display"""
        findings_container.clear()

        with findings_container:
            findings = db.list_findings(engagement=name)

            if not findings:
                ui.label('No findings yet').classes('text-gray-500')
            else:
                for finding in findings:
                    with ui.card().classes('w-full'):
                        with ui.row().classes('items-center gap-2'):
                            ui.label(get_severity_icon(finding['severity'])).classes('text-2xl')
                            ui.label(finding['title']).classes('text-xl font-bold')
                            ui.badge(finding['severity'], color=get_severity_color(finding['severity']))

                        ui.label(f"Category: {finding['category']}").classes('text-gray-600')
                        ui.label(f"Target: {finding['target']}").classes('text-gray-600')

                        if finding['description']:
                            ui.label(finding['description']).classes('text-sm text-gray-700 mt-2')

                        if finding['cvss_score']:
                            ui.label(f"CVSS: {finding['cvss_score']}").classes('font-mono')

                        if finding['cve_id']:
                            ui.label(f"CVE: {finding['cve_id']}").classes('font-mono')

                        with ui.row():
                            if not finding['validated']:
                                ui.button('Validate', icon='check_circle',
                                        on_click=lambda f=finding: validate_finding(f))
                            else:
                                ui.badge('Validated', color='green')

    def refresh_commands():
        """Refresh commands display"""
        commands_container.clear()

        with commands_container:
            commands = db.search_commands(engagement=name, limit=20)

            if not commands:
                ui.label('No commands executed yet').classes('text-gray-500')
            else:
                for cmd in commands:
                    with ui.card().classes('w-full'):
                        with ui.row().classes('items-center gap-2'):
                            ui.label(f"[{cmd['phase']}]").classes('font-bold text-indigo-600')
                            if cmd['tool']:
                                ui.badge(cmd['tool'], color='blue')

                        ui.code(cmd['command']).classes('w-full')

                        with ui.row().classes('text-sm text-gray-500'):
                            ui.label(f"Time: {cmd['timestamp']}")
                            if cmd['duration_seconds']:
                                ui.label(f"Duration: {cmd['duration_seconds']:.2f}s")

    def validate_finding(finding: Dict):
        """Mark finding as validated"""
        # In real implementation, this would trigger validation workflow
        ui.notify(f"Validation workflow for: {finding['title']}", type='info')

    with ui.header().classes('bg-indigo-600'):
        with ui.row().classes('w-full items-center'):
            ui.button(icon='arrow_back', on_click=lambda: ui.navigate.to('/')).props('flat color=white')
            ui.label(f'📊 {name}').classes('text-2xl text-white font-bold')
            ui.space()
            ui.button('Refresh', icon='refresh',
                     on_click=lambda: (refresh_findings(), refresh_commands())).props('flat color=white')

    with ui.column().classes('w-full p-4'):
        # Tabs for different views
        with ui.tabs().classes('w-full') as tabs:
            findings_tab = ui.tab('Findings')
            commands_tab = ui.tab('Commands')
            progress_tab = ui.tab('Progress')
            hitl_tab = ui.tab('HITL Approvals')

        with ui.tab_panels(tabs, value=findings_tab).classes('w-full'):
            with ui.tab_panel(findings_tab):
                ui.label('Vulnerability Findings').classes('text-2xl font-bold mb-4')
                refresh_findings()

            with ui.tab_panel(commands_tab):
                ui.label('Command History').classes('text-2xl font-bold mb-4')
                refresh_commands()

            with ui.tab_panel(progress_tab):
                ui.label('Scan Progress').classes('text-2xl font-bold mb-4')
                ui.label('Progress tracking coming soon...').classes('text-gray-500')

            with ui.tab_panel(hitl_tab):
                ui.label('HITL Checkpoints').classes('text-2xl font-bold mb-4')
                ui.label('HITL approval log coming soon...').classes('text-gray-500')

        # Auto-refresh
        if auto_refresh_enabled:
            ui.timer(5.0, lambda: (refresh_findings(), refresh_commands()))

@ui.page('/test')
def test_page():
    """Test page to generate sample data"""

    with ui.header().classes('bg-indigo-600'):
        ui.label('🧪 Test Data Generator').classes('text-2xl text-white font-bold')

    with ui.column().classes('w-full p-4 gap-4'):
        ui.label('Generate Test Data').classes('text-3xl font-bold')

        with ui.card():
            ui.label('Create Sample Engagement').classes('text-xl font-bold')

            name_input = ui.input('Engagement Name', value='TestCorp_2025-12-16_External')
            client_input = ui.input('Client', value='TestCorp Inc.')

            def create_test_engagement():
                eng_id = db.create_engagement(
                    name=name_input.value,
                    client=client_input.value,
                    engagement_type='External',
                    scope='192.168.1.0/24, testcorp.com',
                    authorization_verified=True
                )
                ui.notify(f'Created engagement ID: {eng_id}', type='positive')

            ui.button('Create Engagement', on_click=create_test_engagement, color='primary')

        with ui.card():
            ui.label('Add Sample Findings').classes('text-xl font-bold')

            engagement_input = ui.input('Engagement Name', value='TestCorp_2025-12-16_External')

            def add_test_findings():
                # Critical SQL Injection
                db.create_finding(
                    engagement=engagement_input.value,
                    severity='CRITICAL',
                    category='SQL Injection',
                    title='SQL Injection in login.php',
                    description='Unauthenticated SQL injection in username parameter',
                    target='https://testcorp.com/login.php',
                    cvss_score=9.8,
                    cve_id='CVE-2024-XXXXX'
                )

                # High XSS
                db.create_finding(
                    engagement=engagement_input.value,
                    severity='HIGH',
                    category='Cross-Site Scripting (XSS)',
                    title='Reflected XSS in search functionality',
                    description='User input not properly sanitized',
                    target='https://testcorp.com/search',
                    cvss_score=7.4
                )

                # Medium Info Disclosure
                db.create_finding(
                    engagement=engagement_input.value,
                    severity='MEDIUM',
                    category='Information Disclosure',
                    title='Server version disclosure',
                    description='Apache version exposed in response headers',
                    target='https://testcorp.com',
                    cvss_score=5.3
                )

                ui.notify('Added 3 test findings', type='positive')

            ui.button('Add Test Findings', on_click=add_test_findings, color='primary')

        with ui.card():
            ui.label('Add Sample Commands').classes('text-xl font-bold')

            def add_test_commands():
                db.record_command(
                    engagement=engagement_input.value,
                    phase='Reconnaissance',
                    command='nmap -sn 192.168.1.0/24',
                    tool='nmap',
                    target='192.168.1.0/24',
                    output='15 hosts discovered',
                    duration=45.3
                )

                db.record_command(
                    engagement=engagement_input.value,
                    phase='Scanning',
                    command='nmap -p- -T4 -sV 192.168.1.10',
                    tool='nmap',
                    target='192.168.1.10',
                    output='8 open ports found',
                    duration=320.7
                )

                db.record_command(
                    engagement=engagement_input.value,
                    phase='Web Scanning',
                    command='gobuster dir -u https://testcorp.com -w /usr/share/wordlists/dirb/common.txt',
                    tool='gobuster',
                    target='https://testcorp.com',
                    output='12 directories discovered',
                    duration=67.2
                )

                ui.notify('Added 3 test commands', type='positive')

            ui.button('Add Test Commands', on_click=add_test_commands, color='primary')

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ in {"__main__", "__mp_main__"}:
    # Set app title and favicon
    app.native.window_args['resizable'] = True
    app.native.start_args['debug'] = False

    ui.run(
        title='ATHENA Monitor - Strategic Penetration Testing',
        port=8080,
        reload=True,
        show=True
    )
