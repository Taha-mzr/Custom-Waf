#!/usr/bin/env python3

import json
import re
from http.server import BaseHTTPRequestHandler, HTTPServer
from datetime import datetime

LOG_FILE = "/home/wafserver/waf/waf.log"
RULES_FILE = "/home/wafserver/waf/rules.json"
WAF_PORT = 8080
DASHBOARD_PORT = 9000
TARGET = "http://127.0.0.1:3000"

def read_logs():
    try:
        with open(LOG_FILE, "r") as f:
            return f.readlines()
    except:
        return []

def get_stats(logs):
    total = len(logs)
    sqli = sum(1 for l in logs if "SQLi" in l)
    xss = sum(1 for l in logs if "XSS" in l)
    return total, sqli, xss

def get_rules_count():
    try:
        with open(RULES_FILE, "r") as f:
            data = json.load(f)
        return len(data["rules"])
    except:
        return 0

def render_log_row(log):
    log = log.strip()
    color = "#e74c3c" if "SQLi" in log else "#f39c12" if "XSS" in log else "#e74c3c"
    # Extract fields
    ts = re.search(r'\[(.*?)\]', log)
    ip = re.search(r'IP: ([\d.]+)', log)
    rule = re.search(r'Rule: ([\w-]+ \([^)]+\))', log)
    payload = re.search(r'Payload: (.+)', log)
    location = re.search(r'Location: (\S+)', log)

    ts = ts.group(1) if ts else "?"
    ip = ip.group(1) if ip else "?"
    rule = rule.group(1) if rule else "?"
    payload = payload.group(1)[:60] if payload else "?"
    location = location.group(1) if location else "?"

    return f"""
    <tr>
        <td style="color:#aaa">{ts}</td>
        <td style="color:#e74c3c;font-weight:bold">{ip}</td>
        <td style="color:{color}">{rule}</td>
        <td style="color:#f39c12">{location}</td>
        <td style="color:#eee;font-family:monospace;font-size:12px">{payload}</td>
    </tr>
    """

def render_dashboard():
    logs = read_logs()
    total, sqli, xss = get_stats(logs)
    rules_count = get_rules_count()
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    log_rows = "".join(render_log_row(l) for l in reversed(logs[-50:]))
    if not log_rows:
        log_rows = '<tr><td colspan="5" style="text-align:center;color:#555;padding:30px">Aucune attaque bloquée pour le moment</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="3">
    <title>WAF Dashboard</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ background: #0d1117; color: #eee; font-family: Arial, sans-serif; padding: 20px; }}

        .header {{
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 20px 30px;
            background: #161b22;
            border-radius: 12px;
            border: 1px solid #30363d;
            margin-bottom: 20px;
        }}
        .header h1 {{ font-size: 24px; color: #58a6ff; }}
        .header .time {{ color: #555; font-size: 13px; }}
        .status-badge {{
            background: #1a7f37;
            color: #fff;
            padding: 6px 16px;
            border-radius: 20px;
            font-size: 13px;
            font-weight: bold;
        }}

        .cards {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 15px;
            margin-bottom: 20px;
        }}
        .card {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 20px;
            text-align: center;
        }}
        .card .icon {{ font-size: 32px; margin-bottom: 10px; }}
        .card .value {{ font-size: 36px; font-weight: bold; margin-bottom: 5px; }}
        .card .label {{ color: #555; font-size: 13px; }}
        .card.red .value {{ color: #e74c3c; }}
        .card.blue .value {{ color: #58a6ff; }}
        .card.orange .value {{ color: #f39c12; }}
        .card.green .value {{ color: #2ecc71; }}

        .info-bar {{
            display: flex;
            gap: 15px;
            margin-bottom: 20px;
        }}
        .info-item {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 8px;
            padding: 12px 20px;
            flex: 1;
            font-size: 13px;
        }}
        .info-item span {{ color: #555; }}
        .info-item strong {{ color: #58a6ff; }}

        .logs-section {{
            background: #161b22;
            border: 1px solid #30363d;
            border-radius: 12px;
            padding: 20px;
        }}
        .logs-section h2 {{
            font-size: 16px;
            color: #58a6ff;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 1px solid #30363d;
        }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{
            text-align: left;
            padding: 10px 15px;
            color: #555;
            font-size: 12px;
            text-transform: uppercase;
            border-bottom: 1px solid #30363d;
        }}
        td {{
            padding: 12px 15px;
            font-size: 13px;
            border-bottom: 1px solid #1c2128;
        }}
        tr:hover td {{ background: #1c2128; }}

        .refresh {{ color: #555; font-size: 12px; text-align: center; margin-top: 15px; }}
    </style>
</head>
<body>

    <div class="header">
        <div>
            <h1>🛡️ WAF Dashboard — ENSAM 2026</h1>
            <div class="time">Dernière mise à jour : {now}</div>
        </div>
        <div class="status-badge">● ACTIF</div>
    </div>

    <div class="cards">
        <div class="card red">
            <div class="icon">🚫</div>
            <div class="value">{total}</div>
            <div class="label">Total bloqué</div>
        </div>
        <div class="card blue">
            <div class="icon">💉</div>
            <div class="value">{sqli}</div>
            <div class="label">SQLi bloquées</div>
        </div>
        <div class="card orange">
            <div class="icon">⚡</div>
            <div class="value">{xss}</div>
            <div class="label">XSS bloquées</div>
        </div>
        <div class="card green">
            <div class="icon">📋</div>
            <div class="value">{rules_count}</div>
            <div class="label">Règles actives</div>
        </div>
    </div>

    <div class="info-bar">
        <div class="info-item"><span>Port WAF : </span><strong>:{WAF_PORT}</strong></div>
        <div class="info-item"><span>Cible : </span><strong>{TARGET}</strong></div>
        <div class="info-item"><span>Log file : </span><strong>{LOG_FILE}</strong></div>
    </div>

    <div class="logs-section">
        <h2>📝 Dernières attaques bloquées (auto-refresh 3s)</h2>
        <table>
            <thead>
                <tr>
                    <th>Timestamp</th>
                    <th>IP Attaquant</th>
                    <th>Règle déclenchée</th>
                    <th>Location</th>
                    <th>Payload</th>
                </tr>
            </thead>
            <tbody>
                {log_rows}
            </tbody>
        </table>
    </div>

    <div class="refresh">🔄 Actualisation automatique toutes les 3 secondes</div>

</body>
</html>"""

class DashboardHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def do_GET(self):
        html = render_dashboard().encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(html)))
        self.end_headers()
        self.wfile.write(html)

if __name__ == "__main__":
    print(f"📊 Dashboard démarré sur 0.0.0.0:{DASHBOARD_PORT}")
    print(f"🌐 Accès : http://192.168.11.133:{DASHBOARD_PORT}")
    server = HTTPServer(("0.0.0.0", DASHBOARD_PORT), DashboardHandler)
    server.serve_forever()
