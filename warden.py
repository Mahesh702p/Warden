"""
warden.py
Main entry point for Warden — Security Log Analysis Engine.

Usage:
    sudo python3 warden.py                  # analyse real /var/log/auth.log
    python3 warden.py --demo                # generate synthetic log + analyse
    python3 warden.py --log /path/to/auth.log   # custom log file
"""

import sys
import os
import argparse
from datetime import datetime, timedelta
import random

from rich.console import Console
from rich.table import Table
from rich.rule import Rule
from rich.panel import Panel
from rich import print as rprint

import warden_parser
import warden_db
import warden_analyzer
import warden_report

console = Console()

LOG_PATH   = "/var/log/auth.log"
DB_PATH    = "warden.db"
REPORT_OUT = "warden_report.html"


# ---------------------------------------------------------------------------
# Demo log generator (so the tool always has something to show)
# ---------------------------------------------------------------------------
def generate_demo_log(path: str = "demo_auth.log") -> str:
    """Write a realistic synthetic auth.log and return its path."""

    ips = ["185.220.101.12", "45.33.32.156", "192.168.1.5",
           "103.45.67.89", "212.47.234.191", "10.0.0.25"]
    users = ["root", "admin", "mahesh", "ubuntu", "pi", "user", "test", "oracle"]

    base = datetime.now() - timedelta(hours=2)
    lines = []

    # Brute force from two IPs
    for i in range(60):
        ts  = (base + timedelta(seconds=i * 3)).strftime("%b %d %H:%M:%S")
        ip  = random.choice(ips[:2])
        usr = random.choice(users)
        if usr == "root" or random.random() < 0.4:
            lines.append(f"{ts} steyngun sshd[10{i:02d}]: Failed password for {usr} from {ip} port {random.randint(40000,65000)} ssh2")
        else:
            lines.append(f"{ts} steyngun sshd[10{i:02d}]: Failed password for invalid user {usr} from {ip} port {random.randint(40000,65000)} ssh2")

    # Legitimate login from a safe IP
    ts = (base + timedelta(minutes=5)).strftime("%b %d %H:%M:%S")
    lines.append(f"{ts} steyngun sshd[2000]: Accepted password for mahesh from 10.0.0.25 port 22 ssh2")
    lines.append(f"{ts} steyngun sshd[2000]: pam_unix(sshd:session): session opened for user mahesh")

    # Credential compromise: many failures then success from same attacker IP
    attacker = "185.220.101.12"
    ts2 = (base + timedelta(minutes=10)).strftime("%b %d %H:%M:%S")
    lines.append(f"{ts2} steyngun sshd[3000]: Accepted password for ubuntu from {attacker} port 52341 ssh2")

    # Sudo commands
    for i, cmd in enumerate(["/usr/bin/apt update", "/bin/cat /etc/shadow", "/usr/sbin/useradd hacker"]):
        ts3 = (base + timedelta(minutes=12 + i)).strftime("%b %d %H:%M:%S")
        lines.append(f"{ts3} steyngun sudo:   mahesh : TTY=pts/0 ; PWD=/home/mahesh ; USER=root ; COMMAND={cmd}")

    # New user creation
    ts4 = (base + timedelta(minutes=16)).strftime("%b %d %H:%M:%S")
    lines.append(f"{ts4} steyngun useradd[4000]: new user: name=hacker, UID=1005, GID=1005, home=/home/hacker, shell=/bin/bash")

    # More random failed logins
    for i in range(20):
        ts5 = (base + timedelta(minutes=20, seconds=i * 5)).strftime("%b %d %H:%M:%S")
        ip  = random.choice(ips)
        usr = random.choice(users)
        lines.append(f"{ts5} steyngun sshd[50{i:02d}]: Failed password for {usr} from {ip} port {random.randint(40000,65000)} ssh2")

    random.shuffle(lines[:60])  # shuffle the brute-force block for realism

    with open(path, "w") as f:
        f.write("\n".join(lines) + "\n")

    return path


# ---------------------------------------------------------------------------
# Core ingestion pipeline
# ---------------------------------------------------------------------------
def ingest_log(log_path: str) -> int:
    """Parse log file, store events in DB. Returns number of events stored."""
    count = 0
    skipped = 0

    with console.status(f"[cyan]Reading {log_path}...[/cyan]"):
        try:
            with open(log_path, "r", errors="replace") as f:
                for line in f:
                    event = warden_parser.parse_line(line)
                    if event:
                        warden_db.insert_event(event, DB_PATH)
                        count += 1
                    else:
                        skipped += 1
        except PermissionError:
            console.print(f"\n[bold red]Permission denied:[/bold red] cannot read {log_path}")
            console.print("Run with [bold]sudo python3 logsentinel.py[/bold]")
            sys.exit(1)
        except FileNotFoundError:
            console.print(f"\n[bold red]File not found:[/bold red] {log_path}")
            sys.exit(1)

    console.print(f"  [green]✓[/green] Parsed [bold]{count}[/bold] events  "
                  f"([dim]{skipped} lines skipped (unrecognised format)[/dim])")
    return count


# ---------------------------------------------------------------------------
# Rich terminal display
# ---------------------------------------------------------------------------
def display_stats(stats: dict) -> None:
    console.print()
    console.print(Rule("[bold cyan]Event Summary[/bold cyan]"))
    console.print()

    grid = Table.grid(expand=False, padding=(0, 4))
    grid.add_column(justify="right")
    grid.add_column()
    grid.add_column(justify="right")
    grid.add_column()

    grid.add_row(
        f"[bold red]{stats.get('failed_login', 0)}[/bold red]",  "Failed Logins",
        f"[bold green]{stats.get('accepted_login', 0)}[/bold green]", "Successful Logins",
    )
    grid.add_row(
        f"[bold orange1]{stats.get('invalid_user', 0)}[/bold orange1]", "Invalid User Attempts",
        f"[bold yellow]{stats.get('sudo_command', 0)}[/bold yellow]",  "Sudo Commands",
    )
    grid.add_row(
        f"[bold magenta]{stats.get('new_user', 0)}[/bold magenta]", "New Users Created",
        f"[bold cyan]{stats.get('total', 0)}[/bold cyan]",           "Total Events",
    )
    console.print(grid)


def display_top_ips(stats: dict) -> None:
    rows = stats.get("top_ips") or []
    if not rows:
        return

    console.print()
    console.print(Rule("[bold cyan]Top Attacking IPs[/bold cyan]"))
    t = Table(show_header=True, header_style="bold dim")
    t.add_column("Rank", width=6)
    t.add_column("IP Address",   min_width=18)
    t.add_column("Attempts",     justify="right")
    t.add_column("Risk",         width=10)

    for i, row in enumerate(rows, 1):
        ip, cnt = row[0], row[1]
        risk = "[bold red]CRITICAL[/]" if cnt >= 50 else \
               "[bold orange1]HIGH[/]"  if cnt >= 20 else \
               "[bold yellow]MEDIUM[/]" if cnt >= 5  else "[dim]LOW[/]"
        t.add_row(str(i), ip, str(cnt), risk)

    console.print(t)


def display_threats(threats: list[dict]) -> None:
    console.print()
    console.print(Rule("[bold red]Threat Detection Results[/bold red]"))

    if not threats:
        console.print("  [green]No threats detected.[/green]")
        return

    for threat in threats:
        sev   = threat.get("severity", "LOW")
        name  = threat.get("threat", "").replace("_", " ")
        desc  = threat.get("description", "")

        color = {"CRITICAL": "bold red", "HIGH": "orange1",
                 "MEDIUM": "yellow",     "LOW": "cyan"}.get(sev, "white")

        panel_title = f"[{color}]{sev}[/{color}]  [bold white]{name}[/bold white]"
        console.print(Panel(desc, title=panel_title, border_style=color.split()[-1]))


def display_sudo_log(stats: dict) -> None:
    rows = stats.get("sudo_commands") or []
    if not rows:
        return

    console.print()
    console.print(Rule("[bold cyan]Sudo Command Log[/bold cyan]"))
    t = Table(show_header=True, header_style="bold dim")
    t.add_column("Timestamp",  min_width=20)
    t.add_column("User",       min_width=12)
    t.add_column("Command")

    for row in rows:
        ts, user, cmd = row[0], row[1], row[2]
        t.add_row(ts, f"[yellow]{user}[/yellow]", f"[dim]{cmd}[/dim]")

    console.print(t)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
def main():
    parser = argparse.ArgumentParser(
        description="Warden — Security Log Analysis Engine"
    )
    parser.add_argument("--demo",    action="store_true",
                        help="Use a generated demo log instead of auth.log")
    parser.add_argument("--log",     default=LOG_PATH,
                        help=f"Path to auth log (default: {LOG_PATH})")
    parser.add_argument("--report",  default=REPORT_OUT,
                        help=f"Output path for HTML report (default: {REPORT_OUT})")
    parser.add_argument("--no-report", action="store_true",
                        help="Skip HTML report generation")
    args = parser.parse_args()

    # --- Banner ---
    console.print()
    console.print(Rule("[bold cyan]🛡️  Warden v1.0 — Security Log Analysis Engine[/bold cyan]"))
    console.print()

    # --- Choose log source ---
    if args.demo:
        log_path = generate_demo_log("demo_auth.log")
        console.print(f"  [bold yellow]Demo mode:[/bold yellow] using generated log → [cyan]{log_path}[/cyan]")
    else:
        log_path = args.log
        console.print(f"  [bold]Log file:[/bold] [cyan]{log_path}[/cyan]")

    console.print(f"  [bold]Database:[/bold] [cyan]{DB_PATH}[/cyan]")
    console.print()

    # --- Initialise DB ---
    warden_db.init_db(DB_PATH)

    # --- Ingest ---
    total = ingest_log(log_path)
    if total == 0:
        console.print("\n  [yellow]No recognisable events found in the log.[/yellow]")
        console.print("  Try running with [bold]--demo[/bold] to see a demonstration.\n")
        return

    # --- Stats ---
    stats = warden_db.get_stats(DB_PATH)
    display_stats(stats)
    display_top_ips(stats)
    display_sudo_log(stats)

    # --- Threat analysis ---
    threats = warden_analyzer.run_all_detections(DB_PATH)
    display_threats(threats)

    # --- HTML Report ---
    if not args.no_report:
        console.print()
        out = warden_report.generate_html(stats, threats, args.report)
        cwd = os.getcwd()
        console.print(Rule())
        console.print(f"\n  [bold green]✓ Report saved:[/bold green] [cyan]{os.path.join(cwd, out)}[/cyan]")
        console.print(f"  Open in browser: [cyan]xdg-open {os.path.join(cwd, out)}[/cyan]\n")

    console.print(Rule("[dim]Analysis complete[/dim]"))
    console.print()


if __name__ == "__main__":
    main()
