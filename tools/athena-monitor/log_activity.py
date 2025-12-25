#!/usr/bin/env python3
"""
Command-line interface for logging pentest activities to database
Usage: python log_activity.py <action> <parameters>
"""

import sys
import sqlite3
from datetime import datetime
from pathlib import Path

# Database path
DB_PATH = Path(__file__).parent / "pentest_tracker.db"

class PentestLogger:
    def __init__(self):
        self.db_path = str(DB_PATH)

    def create_engagement(self, name: str, client: str, engagement_type: str, scope: str = ""):
        """Create new engagement"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        try:
            cursor.execute("""
                INSERT INTO engagements (name, client, engagement_type, started_at, scope, authorization_verified)
                VALUES (?, ?, ?, ?, ?, 1)
            """, (name, client, engagement_type, datetime.now().isoformat(), scope))

            conn.commit()
            print(f"✅ Engagement created: {name}")
            return cursor.lastrowid
        except sqlite3.IntegrityError:
            print(f"⚠️  Engagement '{name}' already exists")
            return None
        finally:
            conn.close()

    def log_command(self, engagement: str, phase: str, command: str, tool: str = "",
                   target: str = "", output: str = "", duration: float = 0):
        """Log executed command"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO commands (timestamp, engagement, phase, command, tool, target, output, duration_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), engagement, phase, command, tool, target, output, duration))

        conn.commit()
        conn.close()
        print(f"✅ Command logged: {tool} → {target}")
        return cursor.lastrowid

    def log_finding(self, engagement: str, severity: str, category: str, title: str,
                   description: str = "", target: str = "", cvss_score: float = 0.0):
        """Log vulnerability finding"""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        cursor.execute("""
            INSERT INTO findings (timestamp, engagement, severity, category, title, description, target, cvss_score)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """, (datetime.now().isoformat(), engagement, severity, category, title, description, target, cvss_score))

        conn.commit()
        conn.close()
        print(f"✅ Finding logged: [{severity}] {title}")
        return cursor.lastrowid

def main():
    if len(sys.argv) < 2:
        print("Usage:")
        print("  Create engagement: python log_activity.py engagement <name> <client> <type> [scope]")
        print("  Log command: python log_activity.py command <engagement> <phase> <command> <tool> <target> [output]")
        print("  Log finding: python log_activity.py finding <engagement> <severity> <category> <title> [description] [target] [cvss]")
        sys.exit(1)

    logger = PentestLogger()
    action = sys.argv[1]

    if action == "engagement":
        name = sys.argv[2]
        client = sys.argv[3]
        eng_type = sys.argv[4]
        scope = sys.argv[5] if len(sys.argv) > 5 else ""
        logger.create_engagement(name, client, eng_type, scope)

    elif action == "command":
        engagement = sys.argv[2]
        phase = sys.argv[3]
        command = sys.argv[4]
        tool = sys.argv[5] if len(sys.argv) > 5 else ""
        target = sys.argv[6] if len(sys.argv) > 6 else ""
        output = sys.argv[7] if len(sys.argv) > 7 else ""
        logger.log_command(engagement, phase, command, tool, target, output)

    elif action == "finding":
        engagement = sys.argv[2]
        severity = sys.argv[3]
        category = sys.argv[4]
        title = sys.argv[5]
        description = sys.argv[6] if len(sys.argv) > 6 else ""
        target = sys.argv[7] if len(sys.argv) > 7 else ""
        cvss = float(sys.argv[8]) if len(sys.argv) > 8 else 0.0
        logger.log_finding(engagement, severity, category, title, description, target, cvss)

    else:
        print(f"Unknown action: {action}")
        sys.exit(1)

if __name__ == "__main__":
    main()
