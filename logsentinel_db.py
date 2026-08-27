"""
logsentinel_db.py
SQLite persistence layer for LogSentinel events.
"""

import sqlite3

DB_PATH = "logsentinel.db"


def init_db(db_path: str = DB_PATH) -> None:
    """Create the events table if it doesn't exist."""
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   TEXT,
                event_type  TEXT,
                user        TEXT,
                ip          TEXT,
                port        TEXT,
                command     TEXT,
                raw         TEXT
            )
        """)
        conn.commit()


def insert_event(event: dict, db_path: str = DB_PATH) -> None:
    """Insert a parsed event dict into the events table."""
    with sqlite3.connect(db_path) as conn:
        conn.execute("""
            INSERT INTO events (timestamp, event_type, user, ip, port, command, raw)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            event.get("timestamp", ""),
            event.get("event_type", ""),
            event.get("user",      ""),
            event.get("ip",        ""),
            event.get("port",      ""),
            event.get("command",   ""),
            event.get("raw",       ""),
        ))
        conn.commit()


def get_all_events(db_path: str = DB_PATH) -> list[dict]:
    """Return every stored event, oldest first."""
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM events ORDER BY timestamp, id"
        ).fetchall()
    return [dict(r) for r in rows]


def get_events_by_type(event_type: str, db_path: str = DB_PATH) -> list[dict]:
    """Return events filtered by type."""
    with sqlite3.connect(db_path) as conn:
        conn.row_factory = sqlite3.Row
        rows = conn.execute(
            "SELECT * FROM events WHERE event_type=? ORDER BY timestamp, id",
            (event_type,)
        ).fetchall()
    return [dict(r) for r in rows]


def get_stats(db_path: str = DB_PATH) -> dict:
    """Return aggregate statistics from the events table."""
    with sqlite3.connect(db_path) as conn:
        stats = {}

        # Count per event type
        for etype in ["failed_login", "accepted_login", "invalid_user",
                      "sudo_command", "new_user", "session_opened"]:
            stats[etype] = conn.execute(
                "SELECT COUNT(*) FROM events WHERE event_type=?", (etype,)
            ).fetchone()[0]

        stats["total"] = conn.execute(
            "SELECT COUNT(*) FROM events"
        ).fetchone()[0]

        # Top attacking IPs (failed + invalid user)
        stats["top_ips"] = conn.execute("""
            SELECT ip, COUNT(*) AS cnt
            FROM events
            WHERE event_type IN ('failed_login','invalid_user') AND ip != ''
            GROUP BY ip
            ORDER BY cnt DESC
            LIMIT 10
        """).fetchall()

        # Top targeted usernames
        stats["top_users"] = conn.execute("""
            SELECT user, COUNT(*) AS cnt
            FROM events
            WHERE event_type = 'failed_login' AND user != ''
            GROUP BY user
            ORDER BY cnt DESC
            LIMIT 10
        """).fetchall()

        # All sudo commands
        stats["sudo_commands"] = conn.execute("""
            SELECT timestamp, user, command
            FROM events
            WHERE event_type = 'sudo_command'
            ORDER BY timestamp
        """).fetchall()

        return stats


if __name__ == "__main__":
    init_db()
    print("[+] logsentinel.db initialised successfully.")
