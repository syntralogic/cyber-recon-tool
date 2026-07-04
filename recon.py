#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════╗
║          SUBDOMAIN RECON + ADMIN PANEL FINDER                ║
║         Authorized Penetration Testing Only                 ║
╚══════════════════════════════════════════════════════════════╝
"""

import socket
import subprocess
import sys
import ipaddress
import concurrent.futures
from datetime import datetime

try:
    import requests
    requests.packages.urllib3.disable_warnings()
except ImportError:
    print("[-] Run: pip install requests")
    sys.exit(1)

# ══════════════════════════════════════════════
#  COLORS
# ══════════════════════════════════════════════
R    = "\033[91m"
G    = "\033[92m"
Y    = "\033[93m"
B    = "\033[94m"
M    = "\033[95m"
C    = "\033[96m"
W    = "\033[97m"
DIM  = "\033[2m"
BOLD = "\033[1m"
RST  = "\033[0m"

# ══════════════════════════════════════════════
#  CLOUDFLARE RANGES
# ══════════════════════════════════════════════
CF_RANGES = [
    "173.245.48.0/20","103.21.244.0/22","103.22.200.0/22",
    "103.31.4.0/22","141.101.64.0/18","108.162.192.0/18",
    "190.93.240.0/20","188.114.96.0/20","197.234.240.0/22",
    "198.41.128.0/17","162.158.0.0/15","104.16.0.0/13",
    "104.24.0.0/14","172.64.0.0/13","131.0.72.0/22",
]

# ══════════════════════════════════════════════
#  WORDLISTS
# ══════════════════════════════════════════════
SUBDOMAINS = [
    "www","mail","webmail","smtp","pop","imap","ftp",
    "dev","staging","test","beta","api","admin","cpanel",
    "whm","vpn","remote","portal","login","dashboard",
    "blog","shop","store","cdn","static","media","images",
    "secure","payments","pay","m","mobile","app",
    "ns1","ns2","dns","mx","mx1","mx2",
    "autodiscover","exchange","owa","intranet","internal",
    "helpdesk","support","ticket","crm","erp","jira",
    "gitlab","git","jenkins","ci","build","monitor",
    "db","database","backup","old","legacy","archive",
    "server","host","cloud","office","files","download",
]

ADMIN_PATHS = [
    # ── General Admin ──
    "/admin", "/admin/", "/admin/login", "/admin/index.php",
    "/administrator", "/administrator/index.php",
    "/adminpanel", "/admin-panel", "/admin_panel",
    "/superadmin", "/super-admin",
    # ── Login Pages ──
    "/login", "/login.php", "/login.html", "/signin",
    "/user/login", "/account/login", "/auth/login",
    "/wp-login.php", "/wp-admin", "/wp-admin/",
    # ── CMS ──
    "/joomla/administrator", "/administrator/",
    "/drupal/admin", "/typo3/", "/modx/manager/",
    "/umbraco/", "/craft/admin", "/statamic/cp",
    # ── Control Panels ──
    "/cpanel", "/cpanel/", "/whm", "/webmail",
    "/plesk", "/directadmin", "/panel", "/hosting",
    # ── Dashboards ──
    "/dashboard", "/dashboard/", "/console",
    "/manage", "/management", "/manager",
    "/portal", "/controlpanel", "/control",
    # ── Config / Setup ──
    "/config", "/configuration", "/setup", "/install",
    "/phpinfo.php", "/info.php", "/test.php",
    "/.env", "/config.php", "/settings.php",
    # ── Database ──
    "/phpmyadmin", "/phpmyadmin/", "/pma", "/mysql",
    "/adminer.php", "/adminer/", "/db",
    # ── API ──
    "/api", "/api/v1", "/api/v2", "/api/admin",
    "/swagger", "/swagger-ui", "/api-docs",
    "/graphql", "/graphiql",
    # ── Monitoring ──
    "/kibana", "/grafana", "/nagios", "/zabbix",
    "/jenkins", "/gitlab", "/sonar",
    # ── Common Backup/Old ──
    "/backup", "/old", "/dev", "/test",
    "/staging", "/beta",
]

# ══════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════
def banner(domain=""):
    print(f"\n{C}{'═'*62}{RST}")
    print(f"{BOLD}{C}   ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗{RST}")
    print(f"{BOLD}{C}   ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║{RST}")
    print(f"{BOLD}{C}   ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║{RST}")
    print(f"{BOLD}{C}   ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║{RST}")
    print(f"{BOLD}{C}   ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║{RST}")
    print(f"{BOLD}{C}   ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝{RST}")
    print(f"{C}{'═'*62}{RST}")
    print(f"{BOLD}{Y}   Subdomain Recon + Admin Panel Finder{RST}")
    print(f"{DIM}{W}   For Authorized Penetration Testing Only{RST}")
    print(f"{C}{'═'*62}{RST}")
    if domain:
        print(f"   {W}Target  : {BOLD}{G}{domain}{RST}")
    print(f"   {W}Time    : {DIM}{datetime.now().strftime('%Y-%m-%d  %H:%M:%S')}{RST}")
    print(f"{C}{'═'*62}{RST}\n")

# ══════════════════════════════════════════════
#  HELPERS
# ══════════════════════════════════════════════
def is_cloudflare(ip):
    try:
        addr = ipaddress.ip_address(ip)
        for cidr in CF_RANGES:
            if addr in ipaddress.ip_network(cidr):
                return True
    except ValueError:
        pass
    return False

def is_private(ip):
    try:
        return ipaddress.ip_address(ip).is_private
    except ValueError:
        return False

def resolve(sub):
    try:
        return socket.gethostbyname(sub)
    except socket.gaierror:
        return None

def http_check(sub):
    out = {}
    for scheme in ["https","http"]:
        try:
            r = requests.get(
                f"{scheme}://{sub}", timeout=5,
                verify=False, allow_redirects=True,
                headers={"User-Agent":"Mozilla/5.0 (ReconBot/3.0)"}
            )
            server = r.headers.get("Server","Unknown")
            cf_ray = r.headers.get("CF-RAY","")
            is_cf  = "cloudflare" in server.lower() or bool(cf_ray)
            out[scheme] = {"status":r.status_code,"server":server,
                           "cf_ray":cf_ray,"is_cf":is_cf}
        except requests.exceptions.SSLError:
            out[scheme] = {"error":"SSL Error"}
        except requests.exceptions.ConnectionError:
            out[scheme] = {"error":"Connection Refused"}
        except requests.exceptions.Timeout:
            out[scheme] = {"error":"Timeout"}
        except Exception as e:
            out[scheme] = {"error":str(e)[:40]}
    return out

def direct_ip_check(ip, domain):
    for scheme in ["https","http"]:
        try:
            r = requests.get(
                f"{scheme}://{ip}", timeout=5, verify=False,
                headers={"Host":domain,"User-Agent":"Mozilla/5.0"}
            )
            if r.status_code == 200:
                return True, r.status_code, scheme
        except Exception:
            continue
    return False, None, None

def mx_check(domain):
    try:
        res = subprocess.run(["nslookup","-type=MX",domain],
                             capture_output=True,text=True,timeout=10)
        recs = [l.strip() for l in res.stdout.splitlines()
                if "mail exchanger" in l.lower() or "MX" in l]
        return recs or ["No MX records found"]
    except Exception as e:
        return [f"Error: {e}"]

# ══════════════════════════════════════════════
#  ADMIN PANEL FINDER
# ══════════════════════════════════════════════
def find_admin(base_url):
    found = []
    def check(path):
        url = base_url.rstrip("/") + path
        try:
            r = requests.get(
                url, timeout=5, verify=False,
                allow_redirects=True,
                headers={"User-Agent":"Mozilla/5.0 (ReconBot/3.0)"}
            )
            server = r.headers.get("Server","Unknown")
            title  = ""
            if b"<title>" in r.content.lower():
                try:
                    t = r.text.lower().split("<title>")[1].split("</title>")[0].strip()
                    title = t[:50]
                except:
                    pass
            return {
                "url":    url,
                "status": r.status_code,
                "server": server,
                "title":  title,
                "size":   len(r.content),
            }
        except Exception:
            return None

    with concurrent.futures.ThreadPoolExecutor(max_workers=20) as ex:
        results = list(ex.map(check, ADMIN_PATHS))

    for res in results:
        if res and res["status"] in [200, 201, 301, 302, 403]:
            found.append(res)
    return found

def print_admin_results(results, domain):
    print(f"\n  {C}{'═'*60}{RST}")
    print(f"  {BOLD}{M}  🔍  ADMIN PANEL SCAN — {domain}{RST}")
    print(f"  {C}{'═'*60}{RST}\n")

    if not results:
        print(f"  {DIM}  No admin panels found.{RST}\n")
        return

    for r in results:
        st = r["status"]
        if st == 200:
            sc  = G
            tag = f"{G}{BOLD}[✔ FOUND — ACCESSIBLE]{RST}"
        elif st in [301, 302]:
            sc  = Y
            tag = f"{Y}[➜ REDIRECT]{RST}"
        elif st == 403:
            sc  = R
            tag = f"{R}[✖ FORBIDDEN — EXISTS]{RST}"
        else:
            sc  = W
            tag = f"{W}[? {st}]{RST}"

        title = f"  {DIM}Title: {r['title']}{RST}" if r["title"] else ""
        print(f"  {C}┌─{RST} {BOLD}{W}{r['url']}{RST}")
        print(f"  {C}│{RST}  Status : {sc}{BOLD}{st}{RST}  {tag}")
        print(f"  {C}│{RST}  Server : {W}{r['server']}{RST}  Size: {DIM}{r['size']} bytes{RST}{title}")
        print(f"  {C}└{'─'*52}{RST}\n")

# ══════════════════════════════════════════════
#  SCAN ONE SUBDOMAIN
# ══════════════════════════════════════════════
def scan_sub(args):
    word, domain = args
    sub = f"{word}.{domain}"
    ip  = resolve(sub)
    if not ip:
        return None

    cf   = is_cloudflare(ip)
    priv = is_private(ip)
    hdrs = http_check(sub)

    exposed = False
    sinfo   = ""
    for s, d in hdrs.items():
        if "error" not in d:
            if not d["is_cf"] and not cf:
                exposed = True
            sinfo = d.get("server","")
            break

    direct, dstat, dscheme = False, None, None
    if not cf:
        direct, dstat, dscheme = direct_ip_check(ip, domain)

    return {
        "sub":sub,"ip":ip,"cf":cf,"priv":priv,
        "exposed":exposed,"sinfo":sinfo,"hdrs":hdrs,
        "direct":direct,"dstat":dstat,"dscheme":dscheme,
    }

def show_sub(r):
    ip = r["ip"]
    if r["cf"]:
        tag = f"{G}[✔ Cloudflare Protected]{RST}"
    elif r["priv"]:
        tag = f"{R}{BOLD}[⚠ INTERNAL IP EXPOSED!]{RST}"
    else:
        tag = f"{Y}[◉ Public IP]{RST}"

    print(f"  {BOLD}{C}┌─ {r['sub']}{RST}")
    print(f"  {C}│{RST}  IP ──▶ {BOLD}{W}{ip}{RST}  {tag}")

    for scheme, d in r["hdrs"].items():
        lbl = scheme.upper().ljust(5)
        if "error" in d:
            print(f"  {C}│{RST}  {lbl} ──▶ {DIM}{d['error']}{RST}")
        else:
            st   = d["status"]
            srv  = d["server"]
            ray  = f"  {DIM}CF-RAY: {d['cf_ray']}{RST}" if d["cf_ray"] else ""
            sc   = G if st==200 else (Y if st<400 else R)
            stag = f"{G}[Cloudflare]{RST}" if d["is_cf"] else f"{R}[Vulnerable Origin Server]{RST}"
            print(f"  {C}│{RST}  {lbl} ──▶ {sc}{st}{RST}  {W}{srv}{RST}  {stag}{ray}")

    if r["direct"]:
        print(f"  {C}│{RST}  {R}{BOLD}⚠  Direct IP Access Allowed! ({r['dscheme']}://{ip} → {r['dstat']}){RST}")
        print(f"  {C}│{RST}  {R}   → [MISCONFIGURED: Direct IP Not Blocked!]{RST}")

    if r["exposed"] and not r["cf"]:
        print(f"  {C}│{RST}  {M}{BOLD}★  Origin Server Exposed — Possible CF Bypass!{RST}")

    print(f"  {C}└{'─'*52}{RST}\n")

# ══════════════════════════════════════════════
#  MAIN
# ══════════════════════════════════════════════
def main():
    banner()

    domain = input(f"  {BOLD}{C}[?]{RST} {W}Target domain       : {RST}").strip()
    if not domain:
        print(f"  {R}[-] No domain entered.{RST}")
        sys.exit(1)

    do_admin = input(
        f"  {BOLD}{C}[?]{RST} {W}Run admin panel scan? {DIM}(y/n){RST} "
    ).strip().lower() == "y"

    wpath = input(
        f"  {BOLD}{C}[?]{RST} {W}Wordlist path        : {DIM}(Enter = built-in){RST} "
    ).strip()

    if wpath:
        try:
            with open(wpath) as f:
                words = [l.strip() for l in f if l.strip()]
            print(f"\n  {G}[+] Loaded {len(words)} words from {wpath}{RST}")
        except FileNotFoundError:
            print(f"\n  {R}[-] File not found — using built-in list{RST}")
            words = SUBDOMAINS
    else:
        words = SUBDOMAINS
        print(f"\n  {Y}[*] Using built-in wordlist ({len(words)} entries){RST}")

    banner(domain)

    # ── SUBDOMAIN SCAN ──────────────────────────
    print(f"  {C}[*] Scanning subdomains...{RST}\n")
    found, exposed_list, bypasses = [], [], []

    with concurrent.futures.ThreadPoolExecutor(max_workers=25) as ex:
        for res in ex.map(scan_sub, [(w,domain) for w in words]):
            if res:
                found.append(res)
                show_sub(res)
                if res["priv"] or res["direct"]:
                    exposed_list.append(res)
                if res["exposed"] and not res["cf"]:
                    bypasses.append(res)

    # ── MX RECORDS ──────────────────────────────
    print(f"\n  {C}{'═'*60}{RST}")
    print(f"  {BOLD}{Y}  ✉  MX RECORD CHECK{RST}")
    print(f"  {C}{'═'*60}{RST}")
    for mx in mx_check(domain):
        print(f"     {W}{mx}{RST}")

    # ── ADMIN PANEL SCAN ────────────────────────
    if do_admin:
        for scheme in ["https","http"]:
            base = f"{scheme}://{domain}"
            print(f"\n  {C}[*] Scanning admin panels on {base} ...{RST}")
            admin_results = find_admin(base)
            print_admin_results(admin_results, domain)

        # Also scan found subdomains
        scan_subs = input(
            f"\n  {BOLD}{C}[?]{RST} {W}Scan admin panels on found subdomains too? {DIM}(y/n){RST} "
        ).strip().lower()
        if scan_subs == "y":
            for r in found:
                if not r["cf"]:  # Skip CF protected (won't show real panels)
                    for d in r["hdrs"].values():
                        if "error" not in d and d["status"] == 200:
                            for scheme in ["https","http"]:
                                base = f"{scheme}://{r['sub']}"
                                print(f"\n  {C}[*] Scanning {base} ...{RST}")
                                ar = find_admin(base)
                                print_admin_results(ar, r["sub"])
                            break

    # ── SUMMARY ─────────────────────────────────
    print(f"\n  {C}{'═'*60}{RST}")
    print(f"  {BOLD}{W}       SCAN SUMMARY{RST}")
    print(f"  {C}{'═'*60}{RST}")
    print(f"  {G}  ✔  Total Subdomains Found   :  {BOLD}{len(found)}{RST}")
    print(f"  {R}  ⚠  Exposed / Misconfigured  :  {BOLD}{len(exposed_list)}{RST}")
    print(f"  {M}  ★  Possible CF Bypasses     :  {BOLD}{len(bypasses)}{RST}")

    if bypasses:
        print(f"\n  {M}{BOLD}  ★  CLOUDFLARE BYPASS TARGETS:{RST}")
        for r in bypasses:
            print(f"      {C}→{RST} {W}{r['sub']}{RST}  {DIM}[{r['ip']}]{RST}  Server: {Y}{r['sinfo']}{RST}")

    if exposed_list:
        print(f"\n  {R}{BOLD}  ⚠  EXPOSED / MISCONFIGURED:{RST}")
        for r in exposed_list:
            t = "Private IP" if r["priv"] else "Direct IP Access"
            print(f"      {C}→{RST} {W}{r['sub']}{RST}  {DIM}[{r['ip']}]{RST}  {R}[{t}]{RST}")

    print(f"\n  {C}{'═'*60}{RST}")
    print(f"  {DIM}  Scan complete : {datetime.now().strftime('%H:%M:%S')}{RST}")
    print(f"  {C}{'═'*60}{RST}\n")

if __name__ == "__main__":
    main()
