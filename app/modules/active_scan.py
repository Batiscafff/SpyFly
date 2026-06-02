"""
Active scanner module.
Runs only when scan_mode == "full" (requires authorization).

Functions:
  run_nmap()      — port scan + service versions + OS guess
  run_ssl_check() — certificate details, cipher, protocol version
  run_dns_brute() — subdomain enumeration via built-in wordlist
"""

import ipaddress
import socket
import ssl
import time
from datetime import datetime

import requests
import urllib3

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


# ─── Helpers ──────────────────────────────────────────────────────────────────

def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


# ─── nmap ─────────────────────────────────────────────────────────────────────

DEFAULT_PORTS = "21,22,23,25,53,80,110,143,443,445,3306,3389,5432,5900,6379,8080,8443,27017"


def _sanitize_ports(ports: str) -> str:
    import re
    p = ports.strip()
    if not p:
        return DEFAULT_PORTS
    if re.fullmatch(r'[\d,\-]+', p):
        return p
    return DEFAULT_PORTS


def _count_ports_in_spec(spec: str) -> int:
    total = 0
    for part in spec.split(','):
        part = part.strip()
        if '-' in part:
            try:
                lo, hi = part.split('-', 1)
                total += max(0, int(hi) - int(lo) + 1)
            except ValueError:
                pass
        elif part.isdigit():
            total += 1
    return total


def run_nmap(target: str, dry_run: bool, ports: str = "") -> dict:
    if dry_run:
        return {
            "ports": [
                {"port": 22,  "protocol": "tcp", "state": "open", "service": "ssh",   "version": "OpenSSH 8.9p1"},
                {"port": 80,  "protocol": "tcp", "state": "open", "service": "http",  "version": "nginx 1.18.0"},
                {"port": 443, "protocol": "tcp", "state": "open", "service": "https", "version": "nginx 1.18.0"},
            ],
            "os_guess": "Linux 5.4",
        }

    ports_spec = _sanitize_ports(ports)
    try:
        import nmap as nmap_lib
        nm = nmap_lib.PortScanner()
        nm.scan(target, arguments=f"-sV -T4 -p {ports_spec}")

        all_hosts = nm.all_hosts()
        if target in all_hosts:
            host_key = target
        elif all_hosts:
            # nmap resolved the domain to an IP — use whichever host was scanned
            host_key = all_hosts[0]
        else:
            return {"ports": [], "os_guess": None, "ports_spec": ports_spec}

        host = nm[host_key]
        port_list = []
        for proto in host.all_protocols():
            for port_num, data in sorted(host[proto].items()):
                port_list.append({
                    "port": port_num,
                    "protocol": proto,
                    "state": data["state"],
                    "service": data["name"],
                    "version": (
                        f"{data.get('product', '')} {data.get('version', '')}".strip() or None
                    ),
                })

        os_guess = None
        if host.get("osmatch"):
            os_guess = host["osmatch"][0]["name"]

        total_scanned = _count_ports_in_spec(ports_spec)
        not_shown = max(0, total_scanned - len(port_list))
        return {
            "ports": port_list,
            "os_guess": os_guess,
            "ports_spec": ports_spec,
            "total_scanned": total_scanned,
            "not_shown_closed": not_shown,
        }
    except Exception as exc:
        return {"error": str(exc), "ports_spec": ports_spec}


# ─── SSL / TLS ────────────────────────────────────────────────────────────────

def run_ssl_check(target: str, dry_run: bool) -> dict:
    if dry_run:
        return {
            "subject": {"commonName": target, "organizationName": "Example Inc."},
            "issuer": {"commonName": "Let's Encrypt Authority X3", "organizationName": "Let's Encrypt"},
            "not_before": "2025-01-01",
            "not_after": "2025-04-01",
            "expired": False,
            "days_remaining": 120,
            "protocol": "TLSv1.3",
            "cipher": "TLS_AES_256_GCM_SHA384",
            "san": [target, f"www.{target}"],
        }

    hostname = target if not _is_ip(target) else target
    try:
        ctx = ssl.create_default_context()
        # Allow IP addresses (skip hostname verification for IPs)
        if _is_ip(target):
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE

        with ctx.wrap_socket(
            socket.create_connection((hostname, 443), timeout=10),
            server_hostname=None if _is_ip(target) else hostname,
        ) as s:
            cert = s.getpeercert()
            cipher_info = s.cipher()
            protocol = s.version()

        not_before = cert.get("notBefore", "")
        not_after = cert.get("notAfter", "")

        # Parse expiry
        days_remaining = None
        expired = False
        try:
            expiry_dt = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
            delta = expiry_dt - datetime.utcnow()
            days_remaining = delta.days
            expired = delta.days < 0
        except Exception:
            pass

        # Subject / Issuer as dicts
        def _rdns(rdns_list):
            d = {}
            for part in rdns_list:
                for k, v in part:
                    d[k] = v
            return d

        subject = _rdns(cert.get("subject", []))
        issuer = _rdns(cert.get("issuer", []))

        # SAN
        san = []
        for type_, value in cert.get("subjectAltName", []):
            if type_ == "DNS":
                san.append(value)

        return {
            "subject": subject,
            "issuer": issuer,
            "not_before": not_before,
            "not_after": not_after,
            "expired": expired,
            "days_remaining": days_remaining,
            "protocol": protocol,
            "cipher": cipher_info[0] if cipher_info else None,
            "san": san[:20],
        }
    except ssl.SSLError as exc:
        return {"error": f"SSL error: {exc}"}
    except ConnectionRefusedError:
        return {"no_ssl": True, "error": "no_ssl"}
    except socket.timeout:
        return {"no_ssl": True, "error": "timeout"}
    except OSError as exc:
        import errno as _errno
        if exc.errno == _errno.ECONNREFUSED:
            return {"no_ssl": True, "error": "no_ssl"}
        return {"error": f"Connection failed: {exc}"}
    except Exception as exc:
        return {"error": str(exc)}


# ─── DNS brute-force ──────────────────────────────────────────────────────────

DNS_WORDLIST = [
    "www", "mail", "smtp", "pop", "imap", "ftp", "sftp",
    "api", "app", "dev", "staging", "test", "prod", "beta",
    "admin", "panel", "dashboard", "portal", "login", "auth",
    "vpn", "remote", "ssh", "git", "gitlab", "github", "jira",
    "confluence", "wiki", "docs", "blog", "shop", "store",
    "cdn", "static", "assets", "media", "img", "images",
    "ns1", "ns2", "dns1", "dns2", "mx", "mx1", "mx2",
    "webmail", "owa", "autodiscover", "exchange",
    "monitor", "nagios", "grafana", "kibana", "elastic",
    "jenkins", "ci", "build", "deploy",
    "db", "database", "mysql", "postgres", "redis", "mongo",
    "backup", "files", "upload", "download",
    "mobile", "m", "wap", "status", "health",
    "internal", "intranet", "corp", "vpn2", "remote2",
]


def run_dns_brute(domain: str, dry_run: bool) -> dict:
    if dry_run:
        return {
            "found": [
                {"subdomain": f"www.{domain}", "ip": "1.2.3.4"},
                {"subdomain": f"api.{domain}", "ip": "1.2.3.5"},
                {"subdomain": f"mail.{domain}", "ip": "1.2.3.6"},
            ],
            "total_checked": len(DNS_WORDLIST),
        }

    if _is_ip(domain):
        return {"error": "DNS brute-force requires a domain, not an IP"}

    found = []
    for word in DNS_WORDLIST:
        fqdn = f"{word}.{domain}"
        try:
            ip = socket.gethostbyname(fqdn)
            found.append({"subdomain": fqdn, "ip": ip})
        except socket.gaierror:
            pass

    return {"found": found, "total_checked": len(DNS_WORDLIST)}


# ─── HTTP Security Headers ────────────────────────────────────────────────────

_SECURITY_HEADERS = [
    {
        "name": "Strict-Transport-Security",
        "severity": "HIGH",
        "description": "Missing HSTS — browser may downgrade to HTTP, enabling MITM attacks",
    },
    {
        "name": "Content-Security-Policy",
        "severity": "HIGH",
        "description": "Missing CSP — no protection against XSS and data injection",
    },
    {
        "name": "X-Frame-Options",
        "severity": "MEDIUM",
        "description": "Missing X-Frame-Options — page may be embedded in iframes (clickjacking risk)",
    },
    {
        "name": "X-Content-Type-Options",
        "severity": "MEDIUM",
        "description": "Missing X-Content-Type-Options — browser may MIME-sniff response content type",
    },
    {
        "name": "Referrer-Policy",
        "severity": "LOW",
        "description": "Missing Referrer-Policy — full URL may leak to third parties via Referer header",
    },
    {
        "name": "Permissions-Policy",
        "severity": "LOW",
        "description": "Missing Permissions-Policy — browser features (camera, mic, etc.) not restricted",
    },
]

_INFO_DISCLOSURE_HEADERS = ["Server", "X-Powered-By", "X-AspNet-Version", "X-AspNetMvc-Version"]


def run_http_headers(target: str, dry_run: bool) -> dict:
    if dry_run:
        return {
            "url": f"https://{target}",
            "status_code": 200,
            "missing": [
                {
                    "name": "Content-Security-Policy",
                    "severity": "HIGH",
                    "description": "Missing CSP — no protection against XSS and data injection",
                },
                {
                    "name": "Referrer-Policy",
                    "severity": "LOW",
                    "description": "Missing Referrer-Policy — full URL may leak to third parties via Referer header",
                },
            ],
            "present": [
                {"name": "Strict-Transport-Security", "value": "max-age=31536000; includeSubDomains"},
                {"name": "X-Frame-Options",           "value": "SAMEORIGIN"},
                {"name": "X-Content-Type-Options",    "value": "nosniff"},
                {"name": "Permissions-Policy",        "value": "geolocation=(), microphone=()"},
            ],
            "info_disclosure": [
                {"name": "Server", "value": "nginx/1.18.0"},
            ],
        }

    urls_to_try = (
        [f"http://{target}"]
        if _is_ip(target)
        else [f"https://{target}", f"http://{target}"]
    )

    resp = None
    checked_url = None
    last_err = None
    for url in urls_to_try:
        try:
            resp = requests.get(
                url, timeout=10, allow_redirects=True,
                verify=(not _is_ip(target)),
                headers={"User-Agent": "Mozilla/5.0"},
            )
            checked_url = url
            break
        except requests.exceptions.SSLError:
            try:
                resp = requests.get(
                    url, timeout=10, allow_redirects=True, verify=False,
                    headers={"User-Agent": "Mozilla/5.0"},
                )
                checked_url = url
                break
            except Exception as exc:
                last_err = exc
        except Exception as exc:
            last_err = exc

    if resp is None:
        return {"error": f"HTTP request failed: {last_err}"}

    headers_lc = {k.lower(): v for k, v in resp.headers.items()}

    missing = []
    present = []
    for spec in _SECURITY_HEADERS:
        if spec["name"].lower() in headers_lc:
            present.append({
                "name":  spec["name"],
                "value": headers_lc[spec["name"].lower()][:300],
            })
        else:
            missing.append({
                "name":        spec["name"],
                "severity":    spec["severity"],
                "description": spec["description"],
            })

    info_disclosure = [
        {"name": h, "value": headers_lc[h.lower()][:300]}
        for h in _INFO_DISCLOSURE_HEADERS
        if h.lower() in headers_lc
    ]

    return {
        "url":              checked_url,
        "status_code":      resp.status_code,
        "missing":          missing,
        "present":          present,
        "info_disclosure":  info_disclosure,
    }


# ─── Orchestrator ─────────────────────────────────────────────────────────────

def run_active_scan(app, target: str, dry_run: bool, ports: str = "") -> dict:
    results: dict = {}

    results["nmap"] = run_nmap(target, dry_run, ports)
    time.sleep(0.2)

    results["ssl"] = run_ssl_check(target, dry_run)
    time.sleep(0.2)

    results["http_headers"] = run_http_headers(target, dry_run)
    time.sleep(0.2)

    if not _is_ip(target):
        results["dns_brute"] = run_dns_brute(target, dry_run)
    else:
        results["dns_brute"] = None

    return results
