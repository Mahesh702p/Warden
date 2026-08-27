"""
logsentinel_report.py
Generates a self-contained HTML security report from analysis results.
"""

from datetime import datetime


SEVERITY_COLOR = {
    "CRITICAL": "#ff4444",
    "HIGH":     "#ff8800",
    "MEDIUM":   "#ffcc00",
    "LOW":      "#44aaff",
}

SEVERITY_BADGE = {
    "CRITICAL": "background:#ff4444;color:#fff",
    "HIGH":     "background:#ff8800;color:#fff",
    "MEDIUM":   "background:#ffcc00;color:#111",
    "LOW":      "background:#44aaff;color:#fff",
}


def _threat_card(threat: dict) -> str:
    sev  = threat.get("severity", "LOW")
    badge_style = SEVERITY_BADGE.get(sev, "background:#aaa;color:#fff")
    name = threat.get("threat", "UNKNOWN").replace("_", " ")
    desc = threat.get("description", "")

    extra_rows = ""
    for key in ("ip", "count", "failures", "users", "users_gained", "source_ips", "first_seen", "last_seen"):
        val = threat.get(key)
        if val:
            if isinstance(val, list):
                val = ", ".join(str(v) for v in val)
            label = key.replace("_", " ").title()
            extra_rows += f"""
            <tr>
              <td style="padding:6px 12px;color:#aaa;white-space:nowrap">{label}</td>
              <td style="padding:6px 12px;color:#eee">{val}</td>
            </tr>"""

    return f"""
    <div style="background:#1e1e2e;border:1px solid #333;border-left:4px solid {SEVERITY_COLOR.get(sev,'#aaa')};
                border-radius:8px;padding:20px;margin-bottom:16px">
      <div style="display:flex;align-items:center;gap:12px;margin-bottom:12px">
        <span style="padding:3px 10px;border-radius:4px;font-size:12px;font-weight:700;{badge_style}">{sev}</span>
        <span style="color:#fff;font-size:16px;font-weight:600">{name}</span>
      </div>
      <p style="color:#ccc;margin:0 0 12px 0">{desc}</p>
      {f'<table style="border-collapse:collapse;width:100%">{extra_rows}</table>' if extra_rows else ""}
    </div>"""


def generate_html(stats: dict, threats: list[dict], output_path: str = "logsentinel_report.html") -> str:
    """Write a complete HTML report and return the output path."""

    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    threat_cards  = "".join(_threat_card(t) for t in threats) if threats else \
        '<p style="color:#aaa;text-align:center;padding:40px">No threats detected.</p>'

    # Build top-IPs table
    top_ip_rows = ""
    for row in (stats.get("top_ips") or []):
        ip, cnt = row[0], row[1]
        top_ip_rows += f"<tr><td>{ip}</td><td style='color:#ff8800;font-weight:700'>{cnt}</td></tr>"

    # Build top-users table
    top_user_rows = ""
    for row in (stats.get("top_users") or []):
        user, cnt = row[0], row[1]
        top_user_rows += f"<tr><td>{user}</td><td style='color:#ff8800;font-weight:700'>{cnt}</td></tr>"

    # Sudo commands table
    sudo_rows = ""
    for row in (stats.get("sudo_commands") or []):
        ts, user, cmd = row[0], row[1], row[2]
        sudo_rows += f"<tr><td>{ts}</td><td>{user}</td><td style='font-family:monospace;font-size:12px'>{cmd}</td></tr>"

    threat_count  = len(threats)
    risk_level    = "CRITICAL" if any(t.get("severity") == "CRITICAL" for t in threats) else \
                    "HIGH"     if any(t.get("severity") == "HIGH"     for t in threats) else \
                    "MEDIUM"   if any(t.get("severity") == "MEDIUM"   for t in threats) else \
                    "LOW"      if threats else "NONE"
    risk_color    = SEVERITY_COLOR.get(risk_level, "#44cc88")

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Warden — Security Audit Report</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{font-family:'Segoe UI',system-ui,sans-serif;background:#13131f;color:#ddd;min-height:100vh}}
  a{{color:#4af}}
  table{{width:100%;border-collapse:collapse}}
  th{{text-align:left;padding:10px 12px;color:#aaa;font-weight:600;font-size:13px;
      border-bottom:1px solid #333;background:#1a1a2a}}
  td{{padding:9px 12px;border-bottom:1px solid #222;font-size:14px}}
  tr:hover td{{background:#1e1e30}}
  .card{{background:#1e1e2e;border:1px solid #2a2a3a;border-radius:10px;padding:24px;margin-bottom:20px}}
  .stat-grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(160px,1fr));gap:16px;margin-bottom:24px}}
  .stat-box{{background:#1e1e2e;border:1px solid #2a2a3a;border-radius:10px;padding:20px;text-align:center}}
  .stat-num{{font-size:32px;font-weight:700;color:#4af}}
  .stat-label{{font-size:13px;color:#aaa;margin-top:4px}}
</style>
</head>
<body>

<!-- Header -->
<div style="background:linear-gradient(135deg,#0d1b2a,#1a0a2e);padding:40px;border-bottom:1px solid #2a2a3a">
  <div style="max-width:960px;margin:0 auto">
    <div style="display:flex;align-items:center;gap:16px;margin-bottom:8px">
      <span style="font-size:28px">🛡️</span>
      <h1 style="font-size:26px;color:#fff;font-weight:700">Warden</h1>
      <span style="background:#1e3a5f;color:#4af;padding:4px 12px;border-radius:20px;font-size:13px">Security Audit Report</span>
    </div>
    <p style="color:#888;font-size:14px">Generated: {generated_at} &nbsp;|&nbsp; Engine: v1.0</p>
  </div>
</div>

<div style="max-width:960px;margin:0 auto;padding:32px 24px">

  <!-- Risk Banner -->
  <div style="background:#1e1e2e;border:1px solid #333;border-left:5px solid {risk_color};
              border-radius:10px;padding:20px 24px;margin-bottom:28px;display:flex;
              align-items:center;justify-content:space-between">
    <div>
      <div style="font-size:13px;color:#aaa;margin-bottom:4px">Overall Risk Level</div>
      <div style="font-size:22px;font-weight:700;color:{risk_color}">{risk_level}</div>
    </div>
    <div style="text-align:right">
      <div style="font-size:13px;color:#aaa;margin-bottom:4px">Threats Detected</div>
      <div style="font-size:22px;font-weight:700;color:#fff">{threat_count}</div>
    </div>
  </div>

  <!-- Stats Grid -->
  <div class="stat-grid">
    <div class="stat-box">
      <div class="stat-num" style="color:#ff4444">{stats.get('failed_login',0)}</div>
      <div class="stat-label">Failed Logins</div>
    </div>
    <div class="stat-box">
      <div class="stat-num" style="color:#ff6600">{stats.get('invalid_user',0)}</div>
      <div class="stat-label">Invalid Users</div>
    </div>
    <div class="stat-box">
      <div class="stat-num" style="color:#44cc88">{stats.get('accepted_login',0)}</div>
      <div class="stat-label">Successful Logins</div>
    </div>
    <div class="stat-box">
      <div class="stat-num" style="color:#ffcc00">{stats.get('sudo_command',0)}</div>
      <div class="stat-label">Sudo Commands</div>
    </div>
    <div class="stat-box">
      <div class="stat-num" style="color:#cc44ff">{stats.get('new_user',0)}</div>
      <div class="stat-label">New Users Created</div>
    </div>
    <div class="stat-box">
      <div class="stat-num" style="color:#4af">{stats.get('total',0)}</div>
      <div class="stat-label">Total Events</div>
    </div>
  </div>

  <!-- Threats -->
  <div class="card">
    <h2 style="color:#fff;margin-bottom:20px;font-size:18px">⚠️  Threat Analysis</h2>
    {threat_cards}
  </div>

  <!-- Top Attacking IPs -->
  {'<div class="card"><h2 style="color:#fff;margin-bottom:16px;font-size:18px">🌐 Top Attacking IPs</h2><table><tr><th>IP Address</th><th>Attempts</th></tr>' + top_ip_rows + '</table></div>' if top_ip_rows else ''}

  <!-- Top Targeted Users -->
  {'<div class="card"><h2 style="color:#fff;margin-bottom:16px;font-size:18px">👤 Top Targeted Usernames</h2><table><tr><th>Username</th><th>Failed Attempts</th></tr>' + top_user_rows + '</table></div>' if top_user_rows else ''}

  <!-- Sudo Activity -->
  {'<div class="card"><h2 style="color:#fff;margin-bottom:16px;font-size:18px">🔑 Sudo Command Log</h2><table><tr><th>Timestamp</th><th>User</th><th>Command</th></tr>' + sudo_rows + '</table></div>' if sudo_rows else ''}

  <!-- Footer -->
  <div style="text-align:center;padding:24px;color:#555;font-size:13px">
    LogSentinel v1.0 — Security Log Analysis Engine &nbsp;|&nbsp; {generated_at}
  </div>

</div>
</body>
</html>"""

    with open(output_path, "w") as f:
        f.write(html)

    return output_path
