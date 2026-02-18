#!/usr/bin/env python3
"""
ATHENA Monitor v2.0 - Strategic Penetration Testing Dashboard
Real-time monitoring and auditing for AI-powered multi-agent penetration testing

ATHENA: Automated Tactical Hacking and Exploitation Network Architecture
Built with: NiceGUI + Tailwind CSS
"""

import sqlite3
from datetime import datetime
from typing import List, Dict, Optional
from pathlib import Path
from nicegui import ui, app
import asyncio

# ============================================================================
# DATABASE LAYER (unchanged from v1)
# ============================================================================

class AthenaDatabase:
    """SQLite database for ATHENA activity tracking"""

    def __init__(self, db_path: str = "athena_tracker.db"):
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
                host TEXT,
                phase TEXT NOT NULL,
                command TEXT NOT NULL,
                tool TEXT,
                target TEXT,
                summary TEXT,
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
                host TEXT,
                severity TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                description TEXT,
                target TEXT,
                port INTEGER,
                protocol TEXT,
                cve_id TEXT,
                evidence_path TEXT,
                cvss_score REAL,
                status TEXT DEFAULT 'identified',
                validated BOOLEAN DEFAULT 0
            )
        """)

        # Services table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS services (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp TEXT NOT NULL,
                engagement TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                protocol TEXT NOT NULL,
                state TEXT NOT NULL,
                name TEXT,
                product TEXT,
                version TEXT,
                last_seen TEXT
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
                      host: str = None, tool: str = None, target: str = None,
                      summary: str = None, output: str = None,
                      duration: float = None) -> int:
        """Record executed command"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO commands (timestamp, engagement, host, phase, command, tool, target, summary, output, duration_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), engagement, host, phase, command, tool, target, summary, output, duration))

        command_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return command_id

    def search_commands(self, engagement: str = None, host: str = None,
                       search_text: str = None, limit: int = 50) -> List[Dict]:
        """Search commands with filters"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = "SELECT * FROM commands WHERE 1=1"
        params = []

        if engagement:
            query += " AND engagement = ?"
            params.append(engagement)
        if host:
            query += " AND host LIKE ?"
            params.append(f"%{host}%")
        if search_text:
            query += " AND (command LIKE ? OR summary LIKE ?)"
            params.append(f"%{search_text}%")
            params.append(f"%{search_text}%")

        query += " ORDER BY timestamp DESC LIMIT ?"
        params.append(limit)

        cursor.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]

        conn.close()
        return results

    def create_finding(self, engagement: str, host: str, severity: str,
                      category: str, title: str, description: str = None,
                      port: int = None, protocol: str = None,
                      cve_id: str = None, cvss_score: float = None,
                      status: str = 'identified') -> int:
        """Create vulnerability finding"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO findings (timestamp, engagement, host, severity, category, title,
                                description, port, protocol, cve_id, cvss_score, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), engagement, host, severity, category, title,
              description, port, protocol, cve_id, cvss_score, status))

        finding_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return finding_id

    def search_findings(self, engagement: str = None, host: str = None,
                       severity: str = None, status: str = None,
                       search_text: str = None) -> List[Dict]:
        """Search findings with filters"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = "SELECT * FROM findings WHERE 1=1"
        params = []

        if engagement:
            query += " AND engagement = ?"
            params.append(engagement)
        if host:
            query += " AND host LIKE ?"
            params.append(f"%{host}%")
        if severity:
            query += " AND severity = ?"
            params.append(severity)
        if status:
            query += " AND status = ?"
            params.append(status)
        if search_text:
            query += " AND (title LIKE ? OR description LIKE ? OR cve_id LIKE ?)"
            params.append(f"%{search_text}%")
            params.append(f"%{search_text}%")
            params.append(f"%{search_text}%")

        query += " ORDER BY timestamp DESC"

        cursor.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]

        conn.close()
        return results

    def create_service(self, engagement: str, host: str, port: int,
                      protocol: str, state: str, name: str = None,
                      product: str = None, version: str = None) -> int:
        """Record discovered service"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO services (timestamp, engagement, host, port, protocol, state,
                                name, product, version, last_seen)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), engagement, host, port, protocol, state,
              name, product, version, datetime.now().isoformat()))

        service_id = cursor.lastrowid
        conn.commit()
        conn.close()
        return service_id

    def search_services(self, engagement: str = None, host: str = None,
                       name: str = None, port: int = None,
                       protocol: str = None, state: str = None) -> List[Dict]:
        """Search services with filters"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        query = "SELECT * FROM services WHERE 1=1"
        params = []

        if engagement:
            query += " AND engagement = ?"
            params.append(engagement)
        if host:
            query += " AND host LIKE ?"
            params.append(f"%{host}%")
        if name:
            query += " AND name LIKE ?"
            params.append(f"%{name}%")
        if port:
            query += " AND port = ?"
            params.append(port)
        if protocol:
            query += " AND protocol = ?"
            params.append(protocol)
        if state:
            query += " AND state = ?"
            params.append(state)

        query += " ORDER BY port ASC"

        cursor.execute(query, params)
        columns = [desc[0] for desc in cursor.description]
        results = [dict(zip(columns, row)) for row in cursor.fetchall()]

        conn.close()
        return results

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
# UI COMPONENTS & STYLING
# ============================================================================

# Initialize database
db = AthenaDatabase()

# Global state
current_engagement = "BVHPR_2025-12-15_External-Internal"  # Default engagement
dark_mode_enabled = True

# Color schemes
COLORS = {
    'primary': '#3B82F6',  # Blue
    'success': '#10B981',  # Green
    'danger': '#EF4444',   # Red
    'warning': '#F59E0B',  # Orange
    'info': '#6366F1',     # Indigo
    'dark_bg': '#1E293B',  # Dark slate
    'light_bg': '#F8FAFC', # Light slate
}

def get_severity_badge_color(severity: str) -> str:
    """Get Tailwind color class for severity badge"""
    colors = {
        'CRITICAL': 'bg-red-600 text-white',
        'HIGH': 'bg-orange-500 text-white',
        'MEDIUM': 'bg-yellow-500 text-black',
        'LOW': 'bg-blue-500 text-white',
        'INFO': 'bg-gray-500 text-white'
    }
    return colors.get(severity.upper(), 'bg-gray-500 text-white')

def get_phase_badge_color(phase: str) -> str:
    """Get Tailwind color class for phase badge"""
    colors = {
        'reconnaissance': 'bg-blue-600 text-white',
        'RECON': 'bg-blue-600 text-white',
        'scanning': 'bg-indigo-600 text-white',
        'enumeration': 'bg-purple-600 text-white',
        'vulnerability_assessment': 'bg-yellow-600 text-white',
        'exploitation': 'bg-red-600 text-white',
        'post_exploitation': 'bg-pink-600 text-white',
        'reporting': 'bg-green-600 text-white',
    }
    return colors.get(phase.lower(), 'bg-gray-600 text-white')

def get_status_badge_color(status: str) -> str:
    """Get Tailwind color class for status badge"""
    colors = {
        'identified': 'bg-yellow-500 text-black',
        'verified': 'bg-green-600 text-white',
        'false_positive': 'bg-gray-500 text-white',
        'open': 'bg-green-600 text-white',
    }
    return colors.get(status.lower(), 'bg-gray-500 text-white')

# ============================================================================
# SHARED COMPONENTS
# ============================================================================

def create_navigation(active_page: str):
    """Create consistent navigation bar for all pages"""
    # Header with dark background
    with ui.element('div').classes('bg-gray-900 text-white px-6 py-4'):
        with ui.row().classes('w-full items-center justify-between'):
            with ui.column().classes('gap-1'):
                ui.label('EXECUTION TRAIL').classes('text-xs font-semibold text-gray-400 tracking-wider')
                ui.label(active_page).classes('text-2xl font-bold')

            # Engagement badge
            ui.badge(current_engagement, color='blue').classes('text-sm px-3 py-1')

    # Navigation bar
    with ui.element('div').classes('bg-white dark:bg-gray-800 border-b dark:border-gray-700 px-6 py-3'):
        with ui.row().classes('w-full items-center justify-between'):
            # Navigation tabs
            with ui.row().classes('gap-2'):
                # Command Activity tab
                if active_page == 'Command Activity':
                    ui.link('Command Activity', '/').classes('px-4 py-2 rounded bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 font-semibold')
                else:
                    ui.link('Command Activity', '/').classes('px-4 py-2 rounded hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300')

                # Vulnerabilities tab
                if active_page == 'Vulnerabilities':
                    ui.link('Vulnerabilities', '/vulnerabilities').classes('px-4 py-2 rounded bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 font-semibold')
                else:
                    ui.link('Vulnerabilities', '/vulnerabilities').classes('px-4 py-2 rounded hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300')

                # Services tab
                if active_page == 'Services':
                    ui.link('Services', '/services').classes('px-4 py-2 rounded bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 font-semibold')
                else:
                    ui.link('Services', '/services').classes('px-4 py-2 rounded hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300')

                # Hosts tab
                if active_page == 'Hosts':
                    ui.link('Hosts', '/hosts').classes('px-4 py-2 rounded bg-blue-100 dark:bg-blue-900 text-blue-700 dark:text-blue-300 font-semibold')
                else:
                    ui.link('Hosts', '/hosts').classes('px-4 py-2 rounded hover:bg-gray-100 dark:hover:bg-gray-700 text-gray-700 dark:text-gray-300')

            # Dark mode toggle
            with ui.row().classes('gap-2 items-center'):
                ui.label('🌙 Dark Mode').classes('text-sm text-gray-600 dark:text-gray-400')
                dark_mode_switch = ui.switch(value=False)
                dark_mode_switch.on_value_change(lambda e: ui.dark_mode.enable() if e.value else ui.dark_mode.disable())

# ============================================================================
# PAGE: COMMAND ACTIVITY (Main Dashboard)
# ============================================================================

@ui.page('/')
def command_activity():
    """Command Activity Dashboard - Execution Trail"""

    # Filter state
    filter_host = ''
    filter_search = ''
    filter_per_page = 50
    results_container = None
    host_input = None
    search_input = None
    per_page_select = None

    def apply_filters():
        """Apply filters and refresh results"""
        nonlocal filter_host, filter_search, filter_per_page

        filter_host = host_input.value.strip()
        filter_search = search_input.value.strip()
        filter_per_page = int(per_page_select.value)

        refresh_results()

    def reset_filters():
        """Reset all filters"""
        host_input.value = ''
        search_input.value = ''
        per_page_select.value = '50'
        apply_filters()

    def refresh_results():
        """Refresh command results"""
        results_container.clear()

        with results_container:
            commands = db.search_commands(
                engagement=current_engagement,
                host=filter_host if filter_host else None,
                search_text=filter_search if filter_search else None,
                limit=filter_per_page
            )

            # Results header
            with ui.row().classes('w-full items-center justify-between mb-4'):
                ui.label('Command log').classes('text-sm font-semibold text-gray-600')
                ui.badge(f'{len(commands)}', color='gray').classes('text-sm')

            if not commands:
                ui.label('No commands executed yet').classes('text-gray-500 text-center py-8')
            else:
                # Table
                with ui.element('div').classes('w-full overflow-x-auto'):
                    with ui.element('table').classes('w-full text-sm'):
                        # Header
                        with ui.element('thead').classes('bg-gray-50 border-b'):
                            with ui.element('tr'):
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('ID')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('HOST')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('PHASE')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('COMMAND')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('SUMMARY')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('CREATED')

                        # Body
                        with ui.element('tbody').classes('divide-y divide-gray-200'):
                            for cmd in commands:
                                with ui.element('tr').classes('hover:bg-gray-50'):
                                    # ID
                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-900'):
                                        ui.label(f"#{cmd['id']}")
                                    # Host
                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-900'):
                                        ui.label(cmd['host'] or 'N/A')
                                    # Phase badge
                                    with ui.element('td').classes('px-4 py-3'):
                                        phase_text = cmd['phase'].upper() if cmd['phase'] else 'N/A'
                                        ui.badge(phase_text).classes(
                                            f"{get_phase_badge_color(cmd['phase'])} text-xs font-semibold px-2 py-1 rounded"
                                        )
                                    # Command
                                    with ui.element('td').classes('px-4 py-3 text-sm font-mono text-gray-700'):
                                        ui.label(cmd['command'][:80] + ('...' if len(cmd['command']) > 80 else ''))
                                    # Summary
                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-600'):
                                        ui.label(cmd['summary'] or 'None')
                                    # Created
                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-500'):
                                        ui.label(cmd['timestamp'][:16] if cmd['timestamp'] else '')

    # Use shared navigation component
    create_navigation('Command Activity')

    # Main content
    with ui.column().classes('w-full max-w-7xl mx-auto p-6 gap-6'):
        # Filters bar
        with ui.card().classes('w-full p-4'):
            with ui.grid(columns=4).classes('w-full gap-4 items-end'):
                # Host filter
                with ui.column().classes('gap-1'):
                    ui.label('Host').classes('text-sm font-medium text-gray-700')
                    host_input = ui.input(placeholder='Filter by host').classes('w-full')

                # Search filter
                with ui.column().classes('gap-1'):
                    ui.label('Search text').classes('text-sm font-medium text-gray-700')
                    search_input = ui.input(placeholder='Command or summary').classes('w-full')

                # Per page
                with ui.column().classes('gap-1'):
                    ui.label('Per page').classes('text-sm font-medium text-gray-700')
                    per_page_select = ui.select(
                        options=['10', '20', '50', '100'],
                        value='50'
                    ).classes('w-full')

                # Buttons
                with ui.row().classes('gap-2'):
                    ui.button('Apply', on_click=apply_filters, color='primary')
                    ui.button('Reset', on_click=reset_filters, color='gray')

        # Results container
        results_container = ui.column().classes('w-full')

    # Initial load
    refresh_results()

    # Auto-refresh every 10 seconds
    ui.timer(10.0, refresh_results)

# ============================================================================
# PAGE: VULNERABILITIES
# ============================================================================

@ui.page('/vulnerabilities')
def vulnerabilities_page():
    """Vulnerabilities Dashboard"""

    filter_host = ''
    filter_cve = ''
    filter_title = ''
    filter_severity = None
    filter_status = None

    results_container = ui.column()

    def apply_filters():
        nonlocal filter_host, filter_cve, filter_title, filter_severity, filter_status

        filter_host = host_input.value.strip()
        filter_cve = cve_input.value.strip()
        filter_title = title_input.value.strip()
        filter_severity = severity_select.value if severity_select.value != 'All' else None
        filter_status = status_select.value if status_select.value != 'All' else None

        refresh_results()

    def reset_filters():
        host_input.value = ''
        cve_input.value = ''
        title_input.value = ''
        severity_select.value = 'All'
        status_select.value = 'All'
        apply_filters()

    def refresh_results():
        results_container.clear()

        with results_container:
            findings = db.search_findings(
                engagement=current_engagement,
                host=filter_host if filter_host else None,
                severity=filter_severity,
                status=filter_status,
                search_text=filter_cve if filter_cve else (filter_title if filter_title else None)
            )

            # Results header
            with ui.row().classes('w-full items-center justify-between mb-4'):
                ui.label('Results').classes('text-sm font-semibold text-gray-600')
                ui.badge(f'{len(findings)}', color='gray').classes('text-sm')

            if not findings:
                ui.label('No vulnerabilities found').classes('text-gray-500 text-center py-8')
            else:
                # Table
                with ui.element('div').classes('w-full overflow-x-auto'):
                    with ui.element('table').classes('w-full text-sm'):
                        # Header
                        with ui.element('thead').classes('bg-gray-50 border-b'):
                            with ui.element('tr'):
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('ID')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('Host')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('Title')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('CVE')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('Severity')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('Status')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('Port')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('Proto')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('Created')

                        # Body
                        with ui.element('tbody').classes('divide-y divide-gray-200'):
                            for finding in findings:
                                with ui.element('tr').classes('hover:bg-gray-50'):
                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-900'):
                                        ui.label(str(finding['id']))
                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-900'):
                                        ui.label(finding['host'] or 'N/A')
                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-900'):
                                        ui.label(finding['title'])
                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-700'):
                                        ui.label(finding['cve_id'] or 'None')

                                    # Severity badge
                                    td_severity = ui.element('td').classes('px-4 py-3')
                                    with td_severity:
                                        ui.badge(finding['severity']).classes(
                                            f"{get_severity_badge_color(finding['severity'])} text-xs font-semibold px-2 py-1 rounded"
                                        )

                                    # Status badge
                                    td_status = ui.element('td').classes('px-4 py-3')
                                    with td_status:
                                        ui.badge(finding['status']).classes(
                                            f"{get_status_badge_color(finding['status'])} text-xs font-semibold px-2 py-1 rounded"
                                        )

                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-700'):
                                        ui.label(str(finding['port']) if finding['port'] else '')
                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-700'):
                                        ui.label(finding['protocol'] or '')
                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-500'):
                                        ui.label(finding['timestamp'][:16] if finding['timestamp'] else '')

    # Use shared navigation component
    create_navigation('Vulnerabilities')

    # Main content
    with ui.column().classes('w-full max-w-7xl mx-auto p-6 gap-6'):
        # Filters
        with ui.card().classes('w-full p-4'):
            with ui.grid(columns=3).classes('w-full gap-4 items-end mb-4'):
                host_input = ui.input(placeholder='192.168.70.13').classes('w-full')
                cve_input = ui.input(placeholder='CVE').classes('w-full')
                title_input = ui.input(placeholder='Title contains').classes('w-full')

            with ui.grid(columns=4).classes('w-full gap-4 items-end'):
                severity_select = ui.select(
                    options=['All', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW'],
                    value='All',
                    label='Severity'
                ).classes('w-full')

                status_select = ui.select(
                    options=['All', 'identified', 'verified', 'false_positive'],
                    value='All',
                    label='Status'
                ).classes('w-full')

                ui.element('div')  # Spacer

                with ui.row().classes('gap-2'):
                    ui.button('Go', on_click=apply_filters, color='primary')

        # Results
        refresh_results()

        ui.timer(10.0, refresh_results)

# ============================================================================
# PAGE: SERVICES
# ============================================================================

@ui.page('/services')
def services_page():
    """Services Enumeration Dashboard"""

    filter_host = ''
    filter_name = ''
    filter_port = ''
    filter_protocol = None
    filter_state = None

    results_container = ui.column()

    def apply_filters():
        nonlocal filter_host, filter_name, filter_port, filter_protocol, filter_state

        filter_host = host_input.value.strip()
        filter_name = name_input.value.strip()
        filter_port = port_input.value.strip()
        filter_protocol = protocol_select.value if protocol_select.value != 'All' else None
        filter_state = state_select.value if state_select.value != 'All' else None

        refresh_results()

    def reset_filters():
        host_input.value = ''
        name_input.value = ''
        port_input.value = ''
        protocol_select.value = 'All'
        state_select.value = 'All'
        apply_filters()

    def refresh_results():
        results_container.clear()

        with results_container:
            services = db.search_services(
                engagement=current_engagement,
                host=filter_host if filter_host else None,
                name=filter_name if filter_name else None,
                port=int(filter_port) if filter_port.isdigit() else None,
                protocol=filter_protocol,
                state=filter_state
            )

            # Results header
            with ui.row().classes('w-full items-center justify-between mb-4'):
                ui.label('Results').classes('text-sm font-semibold text-gray-600')
                ui.badge(f'{len(services)}', color='gray').classes('text-sm')

            if not services:
                ui.label('No services discovered yet').classes('text-gray-500 text-center py-8')
            else:
                # Table
                with ui.element('div').classes('w-full overflow-x-auto'):
                    with ui.element('table').classes('w-full text-sm'):
                        # Header
                        with ui.element('thead').classes('bg-gray-50 border-b'):
                            with ui.element('tr'):
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('ID')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('Host')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('Port')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('Protocol')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('State')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('Name')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('Product')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('Version')
                                with ui.element('th').classes('px-4 py-3 text-left text-xs font-medium text-gray-500 uppercase'):
                                    ui.label('Last Seen')

                        # Body
                        with ui.element('tbody').classes('divide-y divide-gray-200'):
                            for svc in services:
                                with ui.element('tr').classes('hover:bg-gray-50'):
                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-900'):
                                        ui.label(str(svc['id']))
                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-900'):
                                        ui.label(svc['host'])
                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-900'):
                                        ui.label(str(svc['port']))
                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-700'):
                                        ui.label(svc['protocol'])

                                    # State badge
                                    td_state = ui.element('td').classes('px-4 py-3')
                                    with td_state:
                                        state_color = 'bg-green-600 text-white' if svc['state'] == 'open' else 'bg-gray-500 text-white'
                                        ui.badge(svc['state']).classes(f"{state_color} text-xs font-semibold px-2 py-1 rounded")

                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-900'):
                                        ui.label(svc['name'] or '')
                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-700'):
                                        ui.label(svc['product'] or '')
                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-700'):
                                        ui.label(svc['version'] or '')
                                    with ui.element('td').classes('px-4 py-3 text-sm text-gray-500'):
                                        ui.label(svc['last_seen'][:16] if svc['last_seen'] else '')

    # Use shared navigation component
    create_navigation('Services')

    # Main content
    with ui.column().classes('w-full max-w-7xl mx-auto p-6 gap-6'):
        # Filters
        with ui.card().classes('w-full p-4'):
            with ui.grid(columns=3).classes('w-full gap-4 items-end mb-4'):
                host_input = ui.input(placeholder='192.168.70.13').classes('w-full')
                name_input = ui.input(placeholder='Name (e.g., http)').classes('w-full')
                port_input = ui.input(placeholder='Port').classes('w-full')

            with ui.grid(columns=4).classes('w-full gap-4 items-end'):
                protocol_select = ui.select(
                    options=['All', 'tcp', 'udp'],
                    value='All',
                    label='Protocol'
                ).classes('w-full')

                state_select = ui.select(
                    options=['All', 'open', 'closed', 'filtered'],
                    value='All',
                    label='State'
                ).classes('w-full')

                ui.element('div')  # Spacer

                with ui.row().classes('gap-2'):
                    ui.button('Go', on_click=apply_filters, color='primary')

        # Results
        refresh_results()

        ui.timer(10.0, refresh_results)

# ============================================================================
# PAGE: HOSTS
# ============================================================================

@ui.page('/hosts')
def hosts_page():
    """Hosts overview page"""

    # Use shared navigation component
    create_navigation('Hosts')

    with ui.column().classes('w-full max-w-7xl mx-auto p-6'):
        ui.label('Hosts dashboard coming soon...').classes('text-gray-500 dark:text-gray-400 text-center py-8')

# ============================================================================
# NAVIGATION & APP SETUP
# ============================================================================

# Add navigation menu to all pages
@ui.page('/nav_test')
def nav_test():
    with ui.header().classes('bg-gray-900'):
        with ui.row().classes('w-full items-center gap-4 px-4'):
            ui.label('🏛️ ATHENA').classes('text-xl font-bold text-white')
            ui.button('Commands', on_click=lambda: ui.navigate.to('/')).props('flat color=white')
            ui.button('Services', on_click=lambda: ui.navigate.to('/services')).props('flat color=white')
            ui.button('Vulnerabilities', on_click=lambda: ui.navigate.to('/vulnerabilities')).props('flat color=white')
            ui.button('Hosts', on_click=lambda: ui.navigate.to('/hosts')).props('flat color=white')

# ============================================================================
# MAIN ENTRY POINT
# ============================================================================

if __name__ in {"__main__", "__mp_main__"}:
    ui.run(
        title='ATHENA Monitor v2.0 - Strategic Penetration Testing',
        port=8080,
        reload=True,
        show=True
    )
