#!/usr/bin/env python3

import json
import logging
import re
import threading
import urllib.parse
import urllib.request
import urllib.error
from datetime import datetime
from http.server import BaseHTTPRequestHandler, HTTPServer

# ─── Configuration ───
WAF_HOST = "0.0.0.0"
WAF_PORT = 8080
DASHBOARD_PORT = 9000
TARGET = "http://127.0.0.1:3000"
RULES_FILE = "/home/wafserver/waf/rules.json"
LOG_FILE = "/home/wafserver/waf/waf.log"
BLOCK_PAGE = "/home/wafserver/waf/block.html"
SERVER_IP = "192.168.11.133"

# ─── Logging ───
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(message)s"
)

# ─── Chargement des règles ───
def load_rules():
    with open(RULES_FILE, "r") as f:
        data = json.load(f)
    return [(r["id"], r["name"], re.compile(r["pattern"])) for r in data["rules"]]

RULES = load_rules()

# ─── Inspection ───
def inspect(value):
    decoded = urllib.parse.unquote_plus(str(value))
    for rule_id, rule_name, pattern in RULES:
        match = pattern.search(decoded)
        if match:
            return rule_id, rule_name, match.group(0)
    return None, None, None

def inspect_all(uri, headers, body):
    rule_id, rule_name, payload = inspect(uri)
    if rule_id:
        return rule_id, rule_name, payload, "URI"
    for key, value in headers.items():
        rule_id, rule_name, payload = inspect(value)
        if rule_id:
            return rule_id, rule_name, payload, f"Header:{key}"
    if body:
        rule_id, rule_name, payload = inspect(body)
        if rule_id:
            return rule_id, rule_name, payload, "Body"
    return None, None, None, None

# ─── Logging des attaques ───
def log_attack(ip, method, uri, rule_id, rule_name, payload, location):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_entry = (
        f"[{timestamp}] BLOCKED | "
        f"IP: {ip} | "
        f"Method: {method} | "
        f"URI: {uri} | "
        f"Location: {location} | "
        f"Rule: {rule_id} ({rule_name}) | "
        f"Payload: {payload}"
    )
    logging.info(log_entry)
    print(log_entry)

# ─── Dashboard ───
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

def render_log_row(log):
    log = log.strip()
    color = "#e74c3c" if "SQLi" in log else "#f39c12"
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
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{ background:#0d1117; color:#eee; font-family:Arial,sans-serif; padding:20px; }}
        .header {{ display:flex; align-items:center; justify-content:space-between; padding:20px 30px; background:#161b22; border-radius:12px; border:1px solid #30363d; margin-bottom:20px; }}
        .header h1 {{ font-size:24px; color:#58a6ff; }}
        .header .time {{ color:#555; font-size:13px; margin-top:5px; }}
        .status-badge {{ background:#1a7f37; color:#fff; padding:6px 16px; border-radius:20px; font-size:13px; font-weight:bold; }}
        .cards {{ display:grid; grid-template-columns:repeat(4,1fr); gap:15px; margin-bottom:20px; }}
        .card {{ background:#161b22; border:1px solid #30363d; border-radius:12px; padding:20px; text-align:center; }}
        .card .icon {{ font-size:32px; margin-bottom:10px; }}
        .card .value {{ font-size:36px; font-weight:bold; margin-bottom:5px; }}
        .card .label {{ color:#555; font-size:13px; }}
        .card.red .value {{ color:#e74c3c; }}
        .card.blue .value {{ color:#58a6ff; }}
        .card.orange .value {{ color:#f39c12; }}
        .card.green .value {{ color:#2ecc71; }}
        .info-bar {{ display:flex; gap:15px; margin-bottom:20px; }}
        .info-item {{ background:#161b22; border:1px solid #30363d; border-radius:8px; padding:12px 20px; flex:1; font-size:13px; }}
        .info-item span {{ color:#555; }}
        .info-item strong {{ color:#58a6ff; }}
        .logs-section {{ background:#161b22; border:1px solid #30363d; border-radius:12px; padding:20px; }}
        .logs-section h2 {{ font-size:16px; color:#58a6ff; margin-bottom:15px; padding-bottom:10px; border-bottom:1px solid #30363d; }}
        table {{ width:100%; border-collapse:collapse; }}
        th {{ text-align:left; padding:10px 15px; color:#555; font-size:12px; text-transform:uppercase; border-bottom:1px solid #30363d; }}
        td {{ padding:12px 15px; font-size:13px; border-bottom:1px solid #1c2128; }}
        tr:hover td {{ background:#1c2128; }}
        .refresh {{ color:#555; font-size:12px; text-align:center; margin-top:15px; }}
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
        <div class="card red"><div class="icon">🚫</div><div class="value">{total}</div><div class="label">Total bloqué</div></div>
        <div class="card blue"><div class="icon">💉</div><div class="value">{sqli}</div><div class="label">SQLi bloquées</div></div>
        <div class="card orange"><div class="icon">⚡</div><div class="value">{xss}</div><div class="label">XSS bloquées</div></div>
        <div class="card green"><div class="icon">📋</div><div class="value">{len(RULES)}</div><div class="label">Règles actives</div></div>
    </div>
    <div class="info-bar">
        <div class="info-item"><span>Port WAF : </span><strong>:{WAF_PORT}</strong></div>
        <div class="info-item"><span>Cible : </span><strong>{TARGET}</strong></div>
        <div class="info-item"><span>Log : </span><strong>{LOG_FILE}</strong></div>
    </div>
    <div class="logs-section">
        <h2>📝 Dernières attaques bloquées (auto-refresh 3s)</h2>
        <table>
            <thead><tr><th>Timestamp</th><th>IP Attaquant</th><th>Règle</th><th>Location</th><th>Payload</th></tr></thead>
            <tbody>{log_rows}</tbody>
        </table>
    </div>
    <div class="refresh">🔄 Actualisation automatique toutes les 3 secondes</div>
</body>
</html>"""

# ─── WAF Handler ───
class WAFHandler(BaseHTTPRequestHandler):
    def log_message(self, format, *args):
        pass

    def get_body(self):
        length = int(self.headers.get("Content-Length", 0))
        if length > 0:
            return self.rfile.read(length).decode("utf-8", errors="ignore")
        return ""

    def block(self, ip, method, uri, rule_id, rule_name, payload, location):
        log_attack(ip, method, uri, rule_id, rule_name, payload, location)
        with open(BLOCK_PAGE, "rb") as f:
            content = f.read()
        self.send_response(403)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(content)))
        self.send_header("X-WAF-Block", rule_id)
        self.end_headers()
        self.wfile.write(content)

    def forward(self, method, uri, headers, body):
        url = TARGET + uri
        req_headers = {k: v for k, v in headers.items()
                      if k.lower() not in ("host", "connection")}
        req_headers["Host"] = "127.0.0.1:3000"
        data = body.encode("utf-8") if body else None
        req = urllib.request.Request(url, data=data, headers=req_headers, method=method)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                resp_body = resp.read()
                self.send_response(resp.status)
                for key, value in resp.headers.items():
                    if key.lower() not in ("transfer-encoding", "connection"):
                        self.send_header(key, value)
                self.end_headers()
                self.wfile.write(resp_body)
        except urllib.error.HTTPError as e:
            resp_body = e.read()
            self.send_response(e.code)
            self.end_headers()
            self.wfile.write(resp_body)
        except Exception:
            self.send_response(502)
            self.end_headers()
            self.wfile.write(b"502 Bad Gateway")

    def handle_request(self, method):
        ip = self.client_address[0]
        uri = self.path
        headers = dict(self.headers)
        body = self.get_body() if method == "POST" else ""
        rule_id, rule_name, payload, location = inspect_all(uri, headers, body)
        if rule_id:
            self.block(ip, method, uri, rule_id, rule_name, payload, location)
        else:
            self.forward(method, uri, headers, body)

    def do_GET(self): self.handle_request("GET")
    def do_POST(self): self.handle_request("POST")
    def do_PUT(self): self.handle_request("PUT")
    def do_DELETE(self): self.handle_request("DELETE")
    def do_OPTIONS(self): self.handle_request("OPTIONS")

# ─── Dashboard Handler ───
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

# ─── Démarrage ───
if __name__ == "__main__":
    waf_server = HTTPServer((WAF_HOST, WAF_PORT), WAFHandler)
    dashboard_server = HTTPServer((WAF_HOST, DASHBOARD_PORT), DashboardHandler)

    t_dashboard = threading.Thread(target=dashboard_server.serve_forever)
    t_dashboard.daemon = True
    t_dashboard.start()

    print(f"🛡️  WAF démarré sur {WAF_HOST}:{WAF_PORT}")
    print(f"🎯  Cible : {TARGET}")
    print(f"📋  Règles chargées : {len(RULES)}")
    print(f"📊  Dashboard : http://{SERVER_IP}:{DASHBOARD_PORT}")
    print(f"📝  Logs : {LOG_FILE}")
    print(f"─────────────────────────────────────")

    waf_server.serve_forever()
