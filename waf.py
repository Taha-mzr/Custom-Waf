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

# Configuration
WAF_HOST = "0.0.0.0"
WAF_PORT = 8080
DASHBOARD_PORT = 9000
TARGET = "http://127.0.0.1:3000"
RULES_FILE = "/home/wafserver/waf/rules.json"
LOG_FILE = "/home/wafserver/waf/waf.log"
BLOCK_PAGE = "/home/wafserver/waf/block.html"
#Logging 
logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format="%(message)s"
)

#Chargement des règles
def load_rules():
    with open(RULES_FILE, "r") as f:
        data = json.load(f)
    return [(r["id"], r["name"], re.compile(r["pattern"])) for r in data["rules"]]

RULES = load_rules()

#Inspection
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

#Logging des attaques
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

# Dashboard
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
    ts       = re.search(r'\[(.*?)\]', log)
    ip       = re.search(r'IP: ([\d.]+)', log)
    rule     = re.search(r'Rule: ([\w-]+ \([^)]+\))', log)
    payload  = re.search(r'Payload: (.+)', log)
    location = re.search(r'Location: (\S+)', log)
    ts       = ts.group(1)      if ts      else "?"
    ip       = ip.group(1)      if ip      else "?"
    rule     = rule.group(1)    if rule    else "?"
    payload  = payload.group(1)[:55] if payload else "?"
    location = location.group(1) if location else "?"
    rule_color = "#e05c5c" if "SQLi" in rule else "#e09a3a"
    loc_color  = "#7aabcc" if "Header" in location else "#aaa"
    return f"""<tr>
        <td>{ts}</td>
        <td style="color:#e05c5c;font-weight:600">{ip}</td>
        <td style="color:{rule_color}">{rule}</td>
        <td style="color:{loc_color}">{location}</td>
        <td style="font-family:monospace;font-size:12px;color:#ccc">{payload}</td>
    </tr>"""

def render_dashboard():
    logs = read_logs()
    total, sqli, xss = get_stats(logs)
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_rows = "".join(render_log_row(l) for l in reversed(logs[-50:]))
    if not log_rows:
        log_rows = '<tr><td colspan="5" style="text-align:center;color:#555;padding:30px">Aucune attaque bloquee</td></tr>'

    return f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="refresh" content="3">
    <title>WAF Dashboard</title>
    <style>
        * {{ margin:0; padding:0; box-sizing:border-box; }}
        body {{
            background: #0d1117;
            color: #c9d1d9;
            font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Arial, sans-serif;
            font-size: 14px;
            padding: 24px;
        }}

        .header {{
            display: flex;
            align-items: flex-start;
            justify-content: space-between;
            padding: 20px 24px;
            background: #161b22;
            border: 1px solid #21262d;
            border-radius: 8px;
            margin-bottom: 20px;
        }}
        .header-title {{
            font-size: 18px;
            font-weight: 600;
            color: #e6edf3;
            margin-bottom: 4px;
        }}
        .header-sub {{ color: #7d8590; font-size: 12px; }}
        .badge-active {{
            background: #1a4731;
            color: #3fb950;
            border: 1px solid #2ea043;
            padding: 4px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }}

        .cards {{
            display: grid;
            grid-template-columns: repeat(4, 1fr);
            gap: 16px;
            margin-bottom: 20px;
        }}
        .card {{
            background: #161b22;
            border: 1px solid #21262d;
            border-radius: 8px;
            padding: 20px 24px;
        }}
        .card-label {{
            font-size: 12px;
            color: #7d8590;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            margin-bottom: 10px;
        }}
        .card-value {{
            font-size: 32px;
            font-weight: 700;
            line-height: 1;
        }}
        .card-value.red    {{ color: #e05c5c; }}
        .card-value.blue   {{ color: #58a6ff; }}
        .card-value.orange {{ color: #e09a3a; }}
        .card-value.green  {{ color: #3fb950; }}

        .info-bar {{
            display: flex;
            gap: 12px;
            margin-bottom: 20px;
        }}
        .info-item {{
            background: #161b22;
            border: 1px solid #21262d;
            border-radius: 6px;
            padding: 10px 16px;
            flex: 1;
            font-size: 12px;
            color: #7d8590;
        }}
        .info-item span {{ color: #58a6ff; font-weight: 600; }}

        .logs-section {{
            background: #161b22;
            border: 1px solid #21262d;
            border-radius: 8px;
            overflow: hidden;
        }}
        .logs-header {{
            padding: 14px 20px;
            border-bottom: 1px solid #21262d;
            font-size: 13px;
            font-weight: 600;
            color: #e6edf3;
        }}
        table {{ width: 100%; border-collapse: collapse; }}
        th {{
            text-align: left;
            padding: 10px 16px;
            font-size: 11px;
            font-weight: 600;
            color: #7d8590;
            text-transform: uppercase;
            letter-spacing: 0.5px;
            border-bottom: 1px solid #21262d;
            background: #0d1117;
        }}
        td {{
            padding: 11px 16px;
            font-size: 13px;
            border-bottom: 1px solid #161b22;
            color: #c9d1d9;
        }}
        tr:hover td {{ background: #1c2128; }}

        .footer {{
            text-align: center;
            margin-top: 16px;
            font-size: 11px;
            color: #3d444d;
        }}
    </style>
</head>
<body>

<div class="header">
    <div>
        <div class="header-title">WAF Dashboard — ENSAM Casablanca 2026</div>
        <div class="header-sub">Derniere mise a jour : {now}</div>
    </div>
    <div class="badge-active">ACTIF</div>
</div>

<div class="cards">
    <div class="card">
        <div class="card-label">Total bloque</div>
        <div class="card-value red">{total}</div>
    </div>
    <div class="card">
        <div class="card-label">SQLi bloquees</div>
        <div class="card-value blue">{sqli}</div>
    </div>
    <div class="card">
        <div class="card-label">XSS bloquees</div>
        <div class="card-value orange">{xss}</div>
    </div>
    <div class="card">
        <div class="card-label">Regles actives</div>
        <div class="card-value green">{len(RULES)}</div>
    </div>
</div>

<div class="info-bar">
    <div class="info-item">Port WAF : <span>:{WAF_PORT}</span></div>
    <div class="info-item">Cible : <span>{TARGET}</span></div>
    <div class="info-item">Log : <span>{LOG_FILE}</span></div>
</div>

<div class="logs-section">
    <div class="logs-header">Dernieres attaques bloquees — actualisation toutes les 3s</div>
    <table>
        <thead>
            <tr>
                <th>Timestamp</th>
                <th>IP Attaquant</th>
                <th>Regle</th>
                <th>Location</th>
                <th>Payload</th>
            </tr>
        </thead>
        <tbody>{log_rows}</tbody>
    </table>
</div>

<div class="footer">Custom WAF — ENSAM Casablanca 2026 — Auto-refresh 3s</div>

</body>
</html>"""

#WAF Handler
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

    def do_GET(self):  self.handle_request("GET")
    def do_POST(self): self.handle_request("POST")
    def do_PUT(self):  self.handle_request("PUT")
    def do_DELETE(self): self.handle_request("DELETE")
    def do_OPTIONS(self): self.handle_request("OPTIONS")

#  Dashboard Handler
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

# Démarrage 
if __name__ == "__main__":
    waf_server       = HTTPServer((WAF_HOST, WAF_PORT), WAFHandler)
    dashboard_server = HTTPServer((WAF_HOST, DASHBOARD_PORT), DashboardHandler)

    t_dashboard = threading.Thread(target=dashboard_server.serve_forever)
    t_dashboard.daemon = True
    t_dashboard.start()

    print(f"WAF demarre sur {WAF_HOST}:{WAF_PORT}")
    print(f"Cible : {TARGET}")
    print(f"Regles chargees : {len(RULES)}")
    print(f"Dashboard : http://wafserver-ip:{DASHBOARD_PORT}")
    print(f"Logs : {LOG_FILE}")
    print(f"─────────────────────────────────────")

    waf_server.serve_forever()
