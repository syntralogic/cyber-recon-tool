#!/usr/bin/env python3
"""
RECON WEB — Flask Backend
Wraps recon.py logic into a streaming REST API, with account auth.
"""

import os
import socket
import ipaddress
import concurrent.futures
import json
import subprocess
import time
from datetime import datetime

from flask import (
    Flask, request, jsonify, Response, render_template,
    redirect, url_for, flash, stream_with_context
)
from flask_cors import CORS
from flask_login import (
    LoginManager, UserMixin, login_user, logout_user,
    login_required, current_user
)
from werkzeug.security import generate_password_hash, check_password_hash

import db

try:
    import requests as req_lib
    req_lib.packages.urllib3.disable_warnings()
except ImportError:
    req_lib = None

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev-only-change-me-in-render-env-vars")
CORS(app, supports_credentials=True)

db.init_db()

login_manager = LoginManager(app)
login_manager.login_view = "login"
login_manager.login_message = "Please sign in to continue."
login_manager.login_message_category = "info"


class User(UserMixin):
    def __init__(self, row):
        self.id = row["id"]
        self.username = row["username"]
        self.email = row["email"]


@login_manager.user_loader
def load_user(user_id):
    row = db.get_user_by_id(user_id)
    return User(row) if row else None


# ── CLOUDFLARE RANGES ───────────────────────────
CF_RANGES = [
    "173.245.48.0/20", "103.21.244.0/22", "103.22.200.0/22",
    "103.31.4.0/22", "141.101.64.0/18", "108.162.192.0/18",
    "190.93.240.0/20", "188.114.96.0/20", "197.234.240.0/22",
    "198.41.128.0/17", "162.158.0.0/15", "104.16.0.0/13",
    "104.24.0.0/14", "172.64.0.0/13", "131.0.72.0/22",
]

SUBDOMAINS = [
    "www", "mail", "webmail", "smtp", "pop", "imap", "ftp",
    "dev", "staging", "test", "beta", "api", "admin", "cpanel",
    "whm", "vpn", "remote", "portal", "login", "dashboard",
    "blog", "shop", "store", "cdn", "static", "media", "images",
    "secure", "payments", "pay", "m", "mobile", "app",
    "ns1", "ns2", "dns", "mx", "mx1", "mx2",
    "autodiscover", "exchange", "owa", "intranet", "internal",
    "helpdesk", "support", "ticket", "crm", "erp", "jira",
    "gitlab", "git", "jenkins", "ci", "build", "monitor",
    "db", "database", "backup", "old", "legacy", "archive",
    "server", "host", "cloud", "office", "files", "download",
]

ADMIN_PATHS = [
    "/admin", "/admin/", "/admin/login", "/administrator",
    "/adminpanel", "/admin-panel", "/superadmin",
    "/login", "/login.php", "/login.html", "/signin",
    "/wp-login.php", "/wp-admin", "/wp-admin/",
    "/cpanel", "/cpanel/", "/whm", "/webmail",
    "/dashboard", "/console", "/manage", "/portal",
    "/phpmyadmin", "/phpmyadmin/", "/pma", "/adminer.php",
    "/api", "/api/v1", "/api/v2", "/swagger", "/graphql",
    "/config", "/setup", "/install", "/phpinfo.php", "/.env",
    "/kibana", "/grafana", "/jenkins", "/gitlab",
    "/backup", "/old", "/dev", "/staging",
]


# ── HELPERS ─────────────────────────────────────
def is_cloudflare(ip):
    try:
        addr = ipaddress.ip_address(ip)
        return any(addr in ipaddress.ip_network(c) for c in CF_RANGES)
    except Exception:
        return False


def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except Exception:
        return False


def resolve(sub):
    try:
        return socket.gethostbyname(sub)
    except Exception:
        return None


def http_check(sub):
    if not req_lib:
        return {}
    out = {}
    for scheme in ["https", "http"]:
        try:
            r = req_lib.get(f"{scheme}://{sub}", timeout=5, verify=False,
                             allow_redirects=True,
                             headers={"User-Agent": "Mozilla/5.0 (ReconBot/3.0)"})
            server = r.headers.get("Server", "Unknown")
            cf_ray = r.headers.get("CF-RAY", "")
            is_cf = "cloudflare" in server.lower() or bool(cf_ray)
            out[scheme] = {"status": r.status_code, "server": server, "is_cf": is_cf}
        except Exception as e:
            out[scheme] = {"error": str(e)[:60]}
    return out


def mx_check(domain):
    try:
        res = subprocess.run(["nslookup", "-type=MX", domain],
                              capture_output=True, text=True, timeout=10)
        recs = [l.strip() for l in res.stdout.splitlines()
                if "mail exchanger" in l.lower()]
        return recs or ["No MX records found"]
    except Exception as e:
        return [f"Error: {e}"]


def scan_sub(args):
    word, domain = args
    sub = f"{word}.{domain}"
    ip = resolve(sub)
    if not ip:
        return None
    cf = is_cloudflare(ip)
    priv = is_private(ip)
    hdrs = http_check(sub)
    exposed = any(
        "error" not in d and not d.get("is_cf") and not cf
        for d in hdrs.values()
    )
    return {"sub": sub, "ip": ip, "cf": cf, "priv": priv,
            "exposed": exposed, "hdrs": hdrs}


def check_admin_path(args):
    base_url, path = args
    if not req_lib:
        return None
    url = base_url.rstrip("/") + path
    try:
        r = req_lib.get(url, timeout=4, verify=False, allow_redirects=True,
                         headers={"User-Agent": "Mozilla/5.0 (ReconBot/3.0)"})
        if r.status_code in [200, 201, 301, 302, 403]:
            title = ""
            try:
                if b"<title>" in r.content.lower():
                    title = r.text.lower().split("<title>")[1].split("</title>")[0].strip()[:60]
            except Exception:
                pass
            return {"url": url, "status": r.status_code,
                    "server": r.headers.get("Server", "Unknown"),
                    "title": title, "size": len(r.content)}
    except Exception:
        pass
    return None


# ── AUTH ROUTES ─────────────────────────────────
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        email = (request.form.get("email") or "").strip().lower()
        password = request.form.get("password") or ""
        confirm = request.form.get("confirm") or ""

        error = None
        if not username or not email or not password:
            error = "All fields are required."
        elif len(username) < 3:
            error = "Username must be at least 3 characters."
        elif len(password) < 6:
            error = "Password must be at least 6 characters."
        elif password != confirm:
            error = "Passwords do not match."

        if not error:
            pw_hash = generate_password_hash(password)
            ok, err_msg = db.create_user(username, email, pw_hash)
            if ok:
                row = db.get_user_by_username(username)
                login_user(User(row))
                return redirect(url_for("index"))
            error = err_msg

        flash(error, "error")

    return render_template("signup.html")


@app.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("index"))

    if request.method == "POST":
        username = (request.form.get("username") or "").strip()
        password = request.form.get("password") or ""
        row = db.get_user_by_username(username)

        if row and check_password_hash(row["password_hash"], password):
            login_user(User(row), remember=True)
            next_page = request.args.get("next")
            return redirect(next_page or url_for("index"))

        flash("Invalid username or password.", "error")

    return render_template("login.html")


@app.route("/logout")
@login_required
def logout():
    logout_user()
    return redirect(url_for("login"))


# ── APP ROUTES ──────────────────────────────────
@app.route("/")
@login_required
def index():
    history = db.get_history(current_user.id, limit=10)
    return render_template("dashboard.html", history=history)


@app.route("/api/scan", methods=["POST"])
@login_required
def scan():
    data = request.json or {}
    domain = (data.get("domain", "") or "").strip().lower()
    do_admin = data.get("admin", False)
    user_id = current_user.id

    if not domain:
        return jsonify({"error": "Domain required"}), 400

    domain = domain.replace("http://", "").replace("https://", "").split("/")[0]

    def generate():
        yield f"data: {json.dumps({'type':'start','domain':domain,'time':datetime.now().strftime('%H:%M:%S')})}\n\n"
        time.sleep(0.1)

        # ── Subdomain scan ──
        yield f"data: {json.dumps({'type':'phase','phase':'subdomains'})}\n\n"
        found, exposed_list, bypasses = [], [], []

        with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
            for res in ex.map(scan_sub, [(w, domain) for w in SUBDOMAINS]):
                if res:
                    found.append(res)
                    if res["priv"]:
                        exposed_list.append({**res, "reason": "Private IP"})
                    if res["exposed"] and not res["cf"]:
                        bypasses.append(res)
                    yield f"data: {json.dumps({'type':'subdomain','data':res})}\n\n"

        # ── MX records ──
        yield f"data: {json.dumps({'type':'phase','phase':'mx'})}\n\n"
        mx = mx_check(domain)
        yield f"data: {json.dumps({'type':'mx','records':mx})}\n\n"

        # ── Admin panel scan ──
        if do_admin:
            yield f"data: {json.dumps({'type':'phase','phase':'admin'})}\n\n"
            for scheme in ["https", "http"]:
                base = f"{scheme}://{domain}"
                with concurrent.futures.ThreadPoolExecutor(max_workers=15) as ex:
                    results = list(ex.map(check_admin_path,
                                           [(base, p) for p in ADMIN_PATHS]))
                for r in results:
                    if r:
                        yield f"data: {json.dumps({'type':'admin','data':r})}\n\n"
                break  # Try https first, skip http for speed

        # ── Save to history ──
        try:
            db.save_scan(user_id, domain, len(found), len(exposed_list), len(bypasses))
        except Exception:
            pass

        # ── Summary ──
        yield f"data: {json.dumps({'type':'done','summary':{'subdomains':len(found),'exposed':len(exposed_list),'bypasses':len(bypasses)},'time':datetime.now().strftime('%H:%M:%S')})}\n\n"

    return Response(stream_with_context(generate()), mimetype="text/event-stream",
                     headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"})


@app.route("/api/dns", methods=["POST"])
@login_required
def dns_lookup():
    domain = (request.json or {}).get("domain", "").strip()
    if not domain:
        return jsonify({"error": "Domain required"}), 400
    ip = resolve(domain)
    if not ip:
        return jsonify({"resolved": False, "domain": domain})
    return jsonify({
        "resolved": True, "domain": domain, "ip": ip,
        "cloudflare": is_cloudflare(ip), "private": is_private(ip)
    })


@app.route("/api/history")
@login_required
def history():
    rows = db.get_history(current_user.id, limit=25)
    return jsonify([dict(r) for r in rows])


if __name__ == "__main__":
    app.run(debug=False, host="0.0.0.0", port=5000)
