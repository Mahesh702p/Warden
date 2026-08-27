"""
warden_analyzer.py
Threat detection rules applied to stored events.
"""

from collections import defaultdict
import warden_db


BRUTE_FORCE_THRESHOLD    = 5    # failures from same IP → brute force
DISTRIBUTED_THRESHOLD    = 10   # failures against same USERNAME from different IPs → botnet
SPRAY_THRESHOLD          = 5    # one password tried against many usernames from same IP


def detect_brute_force(events: list[dict]) -> list[dict]:
    """Flag IPs with >= THRESHOLD failed login / invalid-user attempts."""
    ip_counts: dict[str, int] = defaultdict(int)
    ip_first:  dict[str, str] = {}
    ip_last:   dict[str, str] = {}

    for e in events:
        if e.get("event_type") in ("failed_login", "invalid_user"):
            ip = e.get("ip", "")
            if not ip:
                continue
            ip_counts[ip] += 1
            ts = e.get("timestamp", "")
            if ip not in ip_first:
                ip_first[ip] = ts
            ip_last[ip] = ts

    threats = []
    for ip, count in ip_counts.items():
        if count >= BRUTE_FORCE_THRESHOLD:
            severity = "CRITICAL" if count >= 50 else "HIGH" if count >= 20 else "MEDIUM"
            threats.append({
                "threat":      "BRUTE_FORCE",
                "ip":          ip,
                "count":       count,
                "severity":    severity,
                "first_seen":  ip_first.get(ip, ""),
                "last_seen":   ip_last.get(ip, ""),
                "description": f"IP {ip} made {count} failed login attempts.",
            })

    return sorted(threats, key=lambda x: x["count"], reverse=True)


def detect_credential_compromise(events: list[dict]) -> list[dict]:
    """
    Flag IPs that had >=3 failures AND then a successful login.
    Pattern = reconnaissance + eventual success = likely compromise.
    """
    ip_failures:  dict[str, int]  = defaultdict(int)
    ip_successes: dict[str, list] = defaultdict(list)

    for e in events:
        ip = e.get("ip", "")
        if not ip:
            continue
        if e.get("event_type") in ("failed_login", "invalid_user"):
            ip_failures[ip] += 1
        elif e.get("event_type") == "accepted_login":
            ip_successes[ip].append(e.get("user", ""))

    threats = []
    for ip, fail_count in ip_failures.items():
        if fail_count >= 3 and ip in ip_successes:
            threats.append({
                "threat":       "CREDENTIAL_COMPROMISE",
                "ip":           ip,
                "failures":     fail_count,
                "users_gained": list(set(ip_successes[ip])),
                "severity":     "CRITICAL",
                "description":  (
                    f"IP {ip} had {fail_count} failed attempts then "
                    f"successfully logged in as: {', '.join(set(ip_successes[ip]))}"
                ),
            })

    return threats


def detect_root_targeting(events: list[dict]) -> list[dict]:
    """Flag direct brute-force attempts targeting the root account."""
    root_attacks = [
        e for e in events
        if e.get("user") == "root"
        and e.get("event_type") in ("failed_login", "invalid_user")
    ]

    if not root_attacks:
        return []

    source_ips = list(set(e.get("ip", "") for e in root_attacks if e.get("ip")))
    return [{
        "threat":      "ROOT_ACCOUNT_TARGETING",
        "count":       len(root_attacks),
        "source_ips":  source_ips,
        "severity":    "HIGH",
        "description": (
            f"{len(root_attacks)} direct root login attempts "
            f"from {len(source_ips)} unique IP(s)."
        ),
    }]


def detect_new_user_creation(events: list[dict]) -> list[dict]:
    """Flag any new user account creation (insider threat / privilege escalation)."""
    new_users = [e for e in events if e.get("event_type") == "new_user"]
    if not new_users:
        return []

    return [{
        "threat":      "NEW_USER_CREATED",
        "users":       [e.get("user", "") for e in new_users],
        "count":       len(new_users),
        "severity":    "MEDIUM",
        "description": (
            f"{len(new_users)} new user account(s) created: "
            f"{', '.join(e.get('user','') for e in new_users)}"
        ),
    }]


def detect_sudo_activity(events: list[dict]) -> list[dict]:
    """Summarise sudo (privilege escalation) usage."""
    sudo_events = [e for e in events if e.get("event_type") == "sudo_command"]
    if not sudo_events:
        return []

    users = list(set(e.get("user", "") for e in sudo_events))
    return [{
        "threat":      "SUDO_PRIVILEGE_ESCALATION",
        "count":       len(sudo_events),
        "users":       users,
        "severity":    "LOW",
        "description": (
            f"{len(sudo_events)} sudo command(s) executed "
            f"by: {', '.join(users)}"
        ),
    }]


def detect_distributed_attack(events: list[dict]) -> list[dict]:
    """
    Detect DISTRIBUTED / BOTNET brute force.

    An attacker using 100 IPs with 2 attempts each evades per-IP detection.
    But if all 100 IPs target the SAME username, we catch it by counting
    failures per USERNAME across ALL source IPs.

    This is the attack your simple IP-based detector misses.
    """
    # Count failures per targeted username
    username_failures: dict[str, int]        = defaultdict(int)
    username_ips:      dict[str, set]        = defaultdict(set)
    username_first:    dict[str, str]        = {}
    username_last:     dict[str, str]        = {}

    for e in events:
        if e.get("event_type") not in ("failed_login", "invalid_user"):
            continue
        user = e.get("user", "")
        ip   = e.get("ip",   "")
        if not user or not ip:
            continue

        username_failures[user] += 1
        username_ips[user].add(ip)
        ts = e.get("timestamp", "")
        if user not in username_first:
            username_first[user] = ts
        username_last[user] = ts

    threats = []
    for user, total_failures in username_failures.items():
        unique_ips = len(username_ips[user])

        # Only flag when multiple different IPs are targeting the same account
        # (single IP = normal brute force already caught above)
        if total_failures >= DISTRIBUTED_THRESHOLD and unique_ips >= 3:
            severity = "CRITICAL" if unique_ips >= 20 else "HIGH" if unique_ips >= 10 else "MEDIUM"
            threats.append({
                "threat":      "DISTRIBUTED_BRUTE_FORCE",
                "user":        user,
                "count":       total_failures,
                "source_ips":  list(username_ips[user])[:10],   # show up to 10 sample IPs
                "severity":    severity,
                "first_seen":  username_first.get(user, ""),
                "last_seen":   username_last.get(user, ""),
                "description": (
                    f"Account '{user}' was targeted by {total_failures} failed login attempts "
                    f"from {unique_ips} unique IP addresses — likely a botnet or distributed attack. "
                    f"No single IP exceeded the per-IP threshold."
                ),
            })

    return sorted(threats, key=lambda x: x["count"], reverse=True)


def detect_password_spray(events: list[dict]) -> list[dict]:
    """
    Detect PASSWORD SPRAY attacks.

    Unlike brute force (many passwords → one account),
    password spray tries ONE common password against MANY accounts.
    e.g., Try 'Welcome@123' against 500 different usernames.
    This avoids account lockout policies.

    Detection: One IP targeting many different usernames.
    """
    ip_users: dict[str, set] = defaultdict(set)

    for e in events:
        if e.get("event_type") not in ("failed_login", "invalid_user"):
            continue
        ip   = e.get("ip",   "")
        user = e.get("user", "")
        if ip and user:
            ip_users[ip].add(user)

    threats = []
    for ip, users in ip_users.items():
        if len(users) >= SPRAY_THRESHOLD:
            severity = "HIGH" if len(users) >= 20 else "MEDIUM"
            threats.append({
                "threat":      "PASSWORD_SPRAY",
                "ip":          ip,
                "count":       len(users),
                "severity":    severity,
                "description": (
                    f"IP {ip} attempted login against {len(users)} different usernames "
                    f"— pattern consistent with password spray attack "
                    f"(one password tried across many accounts to avoid lockout)."
                ),
            })

    return sorted(threats, key=lambda x: x["count"], reverse=True)


def run_all_detections(db_path: str = "warden.db") -> list[dict]:
    """Run every detection module and return combined threat list."""
    events = warden_db.get_all_events(db_path)
    threats = []
    threats.extend(detect_brute_force(events))           # per-IP failures
    threats.extend(detect_distributed_attack(events))    # per-USERNAME across many IPs
    threats.extend(detect_password_spray(events))        # one IP → many usernames
    threats.extend(detect_credential_compromise(events)) # failures then success
    threats.extend(detect_root_targeting(events))
    threats.extend(detect_new_user_creation(events))
    threats.extend(detect_sudo_activity(events))
    return threats
