"""
logsentinel_parser.py
Parses raw /var/log/auth.log lines into structured event dictionaries.
"""

import re
from datetime import datetime

# Auth.log timestamp format: "Aug 27 14:10:01"
TIMESTAMP_RE = re.compile(r'^(\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})')

# Regex patterns for each event type
PATTERNS = {
    "failed_login": re.compile(
        r'Failed password for (?:invalid user )?(\S+) from ([\d.a-f:]+) port (\d+)'
    ),
    "accepted_login": re.compile(
        r'Accepted (?:password|publickey) for (\S+) from ([\d.a-f:]+) port (\d+)'
    ),
    "invalid_user": re.compile(
        r'Invalid user (\S+) from ([\d.a-f:]+)'
    ),
    "sudo_command": re.compile(
        r'sudo:\s+(\S+)\s+:.*?COMMAND=(.+?)(?:\s*$)'
    ),
    "new_user": re.compile(
        r'(?:useradd|adduser).*?name=([^\s,]+)'
    ),
    "session_opened": re.compile(
        r'pam_unix\(sshd:session\): session opened for user (\S+)'
    ),
    "session_closed": re.compile(
        r'pam_unix\(sshd:session\): session closed for user (\S+)'
    ),
    "su_failed": re.compile(
        r'su.*FAILED.*for (\S+)'
    ),
    "cron_session": re.compile(
        r'pam_unix\(cron:session\): session opened for user (\S+)'
    ),
}


def parse_line(line: str) -> dict | None:
    """
    Parse one line from auth.log.
    Returns a dict with event details, or None if the line is unrecognised.
    """
    line = line.strip()
    if not line:
        return None

    result = {"raw": line}

    # --- Extract timestamp ---
    ts_match = TIMESTAMP_RE.match(line)
    if ts_match:
        try:
            ts_str = f"{datetime.now().year} {ts_match.group(1)}"
            dt = datetime.strptime(ts_str, "%Y %b %d %H:%M:%S")
            result["timestamp"] = dt.strftime("%Y-%m-%d %H:%M:%S")
        except ValueError:
            result["timestamp"] = ts_match.group(1)
    else:
        result["timestamp"] = ""

    # --- Match against known event patterns ---
    for event_type, pattern in PATTERNS.items():
        m = pattern.search(line)
        if not m:
            continue

        result["event_type"] = event_type

        if event_type == "failed_login":
            result["user"]    = m.group(1)
            result["ip"]      = m.group(2)
            result["port"]    = m.group(3)

        elif event_type == "accepted_login":
            result["user"]    = m.group(1)
            result["ip"]      = m.group(2)
            result["port"]    = m.group(3)

        elif event_type == "invalid_user":
            result["user"]    = m.group(1)
            result["ip"]      = m.group(2)

        elif event_type == "sudo_command":
            result["user"]    = m.group(1)
            result["command"] = m.group(2).strip()

        elif event_type == "new_user":
            result["user"]    = m.group(1)

        elif event_type in ("session_opened", "session_closed", "su_failed", "cron_session"):
            result["user"]    = m.group(1)

        # Fill any missing fields with empty string
        result.setdefault("user",    "")
        result.setdefault("ip",      "")
        result.setdefault("port",    "")
        result.setdefault("command", "")

        return result

    return None  # Line matched no known pattern


# ---------------------------------------------------------------------------
# Quick self-test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    samples = [
        'Aug 27 14:10:01 server sshd[1234]: Failed password for root from 192.168.1.1 port 22 ssh2',
        'Aug 27 14:10:02 server sshd[1234]: Failed password for invalid user admin from 10.0.0.5 port 22 ssh2',
        'Aug 27 14:10:03 server sshd[1234]: Accepted password for mahesh from 192.168.1.50 port 22 ssh2',
        'Aug 27 14:10:04 server sudo:   mahesh : TTY=pts/0 ; PWD=/home/mahesh ; USER=root ; COMMAND=/usr/bin/apt update',
        'Aug 27 14:10:05 server useradd[999]: new user: name=attacker, UID=1005',
        'Aug 27 14:10:06 server kernel: something random we ignore',
    ]

    for s in samples:
        result = parse_line(s)
        print(result)
