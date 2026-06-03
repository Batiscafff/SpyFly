"""
Passive OSINT module.
Collects data from: Shodan, VirusTotal, AbuseIPDB, crt.sh, WHOIS.
Each function returns a dict with results or {"error": "..."} on failure.
"""

import concurrent.futures
import ipaddress
import json
import socket
import time

import requests


def _is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def _resolve_ip(target: str) -> str:
    if _is_ip(target):
        return target
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        return target


# ─── Shodan ───────────────────────────────────────────────────────────────────

def run_shodan(api_key: str, ip: str, dry_run: bool) -> dict:
    if dry_run:
        return {
            "org": "Amazon.com Inc.", "isp": "Amazon.com, Inc.",
            "country": "United States", "city": "Ashburn", "os": None,
            "ports": [22, 80, 443], "vulns": ["CVE-2021-41773"],
            "last_update": "2025-01-15",
            "banners": [
                {"port": 80, "banner": "HTTP/1.1 200 OK\nServer: nginx/1.18.0\n"},
                {"port": 22, "banner": "SSH-2.0-OpenSSH_8.2p1 Ubuntu-4ubuntu0.5\n"},
            ],
        }

    if not api_key:
        return {"error": "SHODAN_API_KEY not configured"}

    def _fetch():
        import shodan as shodan_lib
        api = shodan_lib.Shodan(api_key)
        return api.host(ip)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(_fetch)
            data = future.result(timeout=15)
        banners = []
        for item in data.get("data", [])[:5]:
            banners.append({"port": item.get("port"), "banner": item.get("data", "")[:300]})
        return {
            "org": data.get("org"),
            "isp": data.get("isp"),
            "country": data.get("country_name"),
            "city": data.get("city"),
            "os": data.get("os"),
            "ports": data.get("ports", []),
            "vulns": list(data.get("vulns", {}).keys()),
            "last_update": data.get("last_update", "")[:10],
            "banners": banners,
        }
    except concurrent.futures.TimeoutError:
        return {"error": "Shodan timeout (>15s)"}
    except Exception as exc:
        return {"error": str(exc)}


# ─── VirusTotal ───────────────────────────────────────────────────────────────

def run_virustotal(api_key: str, ip: str, dry_run: bool) -> dict:
    if dry_run:
        return {
            "malicious": 0, "suspicious": 0, "total_engines": 87,
            "reputation": 0, "country": "US", "as_owner": "Amazon.com",
            "votes_harmless": 5, "votes_malicious": 0,
        }

    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY not configured"}

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
            headers={"x-apikey": api_key}, timeout=15,
        )
        if resp.status_code == 404:
            return {"error": "IP not found in VirusTotal"}
        if resp.status_code == 429:
            return {"error": "VirusTotal rate limit (4 req/min on free plan)"}
        resp.raise_for_status()
        attr = resp.json().get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        votes = attr.get("total_votes", {})
        return {
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "total_engines": sum(stats.values()),
            "reputation": attr.get("reputation", 0),
            "country": attr.get("country"),
            "as_owner": attr.get("as_owner"),
            "votes_harmless": votes.get("harmless", 0),
            "votes_malicious": votes.get("malicious", 0),
        }
    except Exception as exc:
        return {"error": str(exc)}


# ─── AbuseIPDB ────────────────────────────────────────────────────────────────

def run_abuseipdb(api_key: str, ip: str, dry_run: bool) -> dict:
    if dry_run:
        return {
            "score": 0, "total_reports": 0, "num_distinct_users": 0,
            "is_public": True, "country_code": "US", "isp": "Amazon.com",
            "domain": "amazon.com",
        }

    if not api_key:
        return {"error": "ABUSEIPDB_API_KEY not configured"}

    try:
        resp = requests.get(
            "https://api.abuseipdb.com/api/v2/check",
            headers={"Key": api_key, "Accept": "application/json"},
            params={"ipAddress": ip, "maxAgeInDays": 90},
            timeout=15,
        )
        resp.raise_for_status()
        d = resp.json().get("data", {})
        return {
            "score": d.get("abuseConfidenceScore", 0),
            "total_reports": d.get("totalReports", 0),
            "num_distinct_users": d.get("numDistinctUsers", 0),
            "is_public": d.get("isPublic", True),
            "country_code": d.get("countryCode"),
            "isp": d.get("isp"),
            "domain": d.get("domain"),
        }
    except Exception as exc:
        return {"error": str(exc)}


# ─── crt.sh ───────────────────────────────────────────────────────────────────

def run_crtsh(domain: str, dry_run: bool) -> dict:
    if dry_run:
        return {"domains": [
            {"name": f"www.{domain}", "issuer": "Let's Encrypt", "not_before": "2025-01-01"},
            {"name": f"mail.{domain}", "issuer": "Let's Encrypt", "not_before": "2025-02-01"},
            {"name": f"api.{domain}", "issuer": "DigiCert", "not_before": "2025-03-01"},
        ]}

    try:
        resp = requests.get(
            f"https://crt.sh/?q=%.{domain}&output=json",
            timeout=20, headers={"User-Agent": "Mozilla/5.0"},
        )
        resp.raise_for_status()
        seen: set = set()
        domains = []
        for entry in resp.json():
            for name in entry.get("name_value", "").split("\n"):
                name = name.strip().lower()
                if name and name not in seen and "*" not in name:
                    seen.add(name)
                    domains.append({
                        "name": name,
                        "issuer": entry.get("issuer_name", "")[:60],
                        "not_before": entry.get("not_before", "")[:10],
                    })
        domains.sort(key=lambda d: d["name"])
        return {"domains": domains}
    except Exception as exc:
        return {"error": str(exc)}


# ─── Wayback Machine ──────────────────────────────────────────────────────────

def run_wayback(target: str, dry_run: bool) -> dict:
    if dry_run:
        return {
            "available": True,
            "first_seen": "2019-08-12",
            "last_seen": "2026-05-20",
            "snapshot_url": f"https://web.archive.org/web/*/{target}",
        }

    from datetime import datetime

    CDX = "https://web.archive.org/cdx/search/cdx"
    headers = {"User-Agent": "Mozilla/5.0"}
    TIMEOUT = 45

    def _parse_ts(ts: str) -> str:
        try:
            return datetime.strptime(ts, "%Y%m%d%H%M%S").strftime("%Y-%m-%d")
        except Exception:
            return None

    def _fetch_first():
        return requests.get(CDX, params={
            "url": target, "output": "json", "limit": 1, "fl": "timestamp",
        }, timeout=TIMEOUT, headers=headers)

    def _fetch_last():
        # Availability API returns the closest (most recent) snapshot reliably
        return requests.get(
            "https://archive.org/wayback/available",
            params={"url": target},
            timeout=TIMEOUT, headers=headers,
        )

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            f_first = pool.submit(_fetch_first)
            f_last  = pool.submit(_fetch_last)
            r_first = f_first.result()
            r_last  = f_last.result()

        data_first = r_first.json()
        if len(data_first) <= 1:
            return {"available": False, "snapshot_url": f"https://web.archive.org/web/*/{target}"}

        # Availability API: {"archived_snapshots": {"closest": {"timestamp": "..."}}}
        last_seen = None
        try:
            ts = r_last.json()["archived_snapshots"]["closest"]["timestamp"]
            last_seen = _parse_ts(ts)
        except Exception:
            pass

        return {
            "available": True,
            "first_seen": _parse_ts(data_first[1][0]),
            "last_seen": last_seen,
            "snapshot_url": f"https://web.archive.org/web/*/{target}",
        }
    except Exception as exc:
        return {"error": str(exc)}


# ─── WHOIS ────────────────────────────────────────────────────────────────────

def run_whois(target: str, dry_run: bool) -> dict:
    if dry_run:
        return {
            "registrar": "MarkMonitor Inc.",
            "creation_date": "1994-11-01",
            "expiration_date": "2026-10-31",
            "name_servers": ["ns1.example.com", "ns2.example.com"],
            "emails": ["abuse@example.com"],
            "org": "Amazon Technologies Inc.",
        }

    def _do_whois():
        import whois as python_whois
        return python_whois.whois(target)

    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=1) as ex:
            future = ex.submit(_do_whois)
            w = future.result(timeout=15)

        def _fmt_date(val):
            if not val:
                return None
            if isinstance(val, list):
                val = val[0]
            return str(val)[:10] if val else None

        emails = w.emails or []
        if isinstance(emails, str):
            emails = [emails]

        ns = w.name_servers or []
        if isinstance(ns, str):
            ns = [ns]

        return {
            "registrar": w.registrar,
            "creation_date": _fmt_date(w.creation_date),
            "expiration_date": _fmt_date(w.expiration_date),
            "name_servers": sorted({s.lower() for s in ns if s})[:6],
            "emails": list({e.lower() for e in emails if e})[:6],
            "org": w.org,
        }
    except concurrent.futures.TimeoutError:
        return {"error": "WHOIS timeout (>15s)"}
    except Exception as exc:
        return {"error": str(exc)}


# ─── URLScan.io ───────────────────────────────────────────────────────────────

def _parse_urlscan_result(data: dict, uuid: str, source: str, screenshot_override: str = "") -> dict:
    page     = data.get("page", {})
    task     = data.get("task", {})
    verdicts = data.get("verdicts", {}).get("overall", {})
    stats    = data.get("stats", {})

    tech = []
    for t in data.get("meta", {}).get("processors", {}).get("wappa", {}).get("data", [])[:30]:
        raw_cats = t.get("categories", [])
        cats = [c.get("name", "") for c in raw_cats if isinstance(c, dict)] if isinstance(raw_cats, list) else []
        tech.append({
            "name":       t.get("app", "") or t.get("name", ""),
            "website":    t.get("website", ""),
            "categories": cats,
            "category":   cats[0] if cats else "Other",
        })

    scan_time = task.get("time", "")
    try:
        page_status = int(page.get("status")) if page.get("status") is not None else None
    except (ValueError, TypeError):
        page_status = None

    screenshot = screenshot_override or data.get("screenshot", "") or (
        f"https://urlscan.io/screenshots/{uuid}.png" if uuid else ""
    )

    return {
        "scan_url":       f"https://urlscan.io/result/{uuid}/",
        "screenshot_url": screenshot or None,
        "scanned_url":    task.get("url", ""),
        "scan_date":      scan_time[:10] if scan_time else None,
        "page_title":     page.get("title", ""),
        "page_status":    page_status,
        "server":         page.get("server", ""),
        "ip":             page.get("ip", ""),
        "country":        page.get("country", ""),
        "asn":            page.get("asnname", "") or page.get("asn", ""),
        "language":       page.get("language", ""),
        "tls_issuer":     page.get("tlsIssuer", ""),
        "tls_valid_days": page.get("tlsValidDays"),
        "requests":       stats.get("requests"),
        "malicious":      verdicts.get("malicious", False),
        "score":          verdicts.get("score", 0),
        "tags":           verdicts.get("tags", []),
        "tech":           tech,
        "uniq_ips":       stats.get("uniqIPs"),
        "uniq_domains":   stats.get("uniqDomains"),
        "total_links":    stats.get("totalLinks"),
        "source":         source,
    }


def run_urlscan(api_key: str, target: str, dry_run: bool, original_url: str = "") -> dict:
    if dry_run:
        return {
            "scan_url":       "https://urlscan.io/result/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx/",
            "screenshot_url": "https://urlscan.io/screenshots/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx.png",
            "scanned_url":    f"https://{target}",
            "scan_date":      "2025-01-15",
            "page_title":     "Example Domain",
            "page_status":    200,
            "server":         "nginx/1.18.0",
            "ip":             "93.184.216.34",
            "country":        "US",
            "malicious":      False,
            "score":          0,
            "tags":           [],
            "tech": [
                {"name": "Nginx",       "website": "https://nginx.org",          "categories": ["Web servers"],           "category": "Web servers"},
                {"name": "WordPress",   "website": "https://wordpress.org",      "categories": ["CMS", "Blogs"],          "category": "CMS"},
                {"name": "PHP",         "website": "https://php.net",            "categories": ["Programming languages"], "category": "Programming languages"},
                {"name": "jQuery",      "website": "https://jquery.com",         "categories": ["JavaScript libraries"],  "category": "JavaScript libraries"},
                {"name": "Bootstrap",   "website": "https://getbootstrap.com",   "categories": ["UI frameworks"],         "category": "UI frameworks"},
                {"name": "Google Analytics", "website": "https://analytics.google.com", "categories": ["Analytics"],     "category": "Analytics"},
            ],
            "uniq_ips":     4,
            "uniq_domains": 6,
            "total_links":  18,
            "source":       "search",
        }

    headers = {"API-Key": api_key} if api_key else {}

    # Step 1: search for existing scans (no API key needed)
    query = f"ip:{target}" if _is_ip(target) else f"domain:{target}"
    try:
        search_resp = requests.get(
            f"https://urlscan.io/api/v1/search/?q={query}&size=1",
            headers=headers, timeout=15,
        )
        if search_resp.status_code == 429:
            return {"error": "URLScan rate limit reached"}
        search_resp.raise_for_status()
        search_results = search_resp.json().get("results", [])
    except Exception as exc:
        return {"error": f"URLScan search failed: {exc}"}

    if search_results:
        item = search_results[0]
        # API returns data directly; older responses wrapped it in "_source"
        src  = item.get("_source") or item
        uuid = src.get("_id") or src.get("task", {}).get("uuid", "")
        # Screenshot URL is provided directly in search results
        screenshot = src.get("screenshot", "")

        # Full result (tech stack) requires auth — only fetch if API key is present
        full_data = src
        if api_key and uuid:
            try:
                full_resp = requests.get(
                    f"https://urlscan.io/api/v1/result/{uuid}/",
                    headers=headers, timeout=10,
                )
                if full_resp.status_code == 200:
                    full_data = full_resp.json()
            except Exception:
                pass
        return _parse_urlscan_result(full_data, uuid, "search", screenshot_override=screenshot)

    # Step 2: no existing results — submit new scan (requires API key)
    if not api_key:
        return {"error": "No URLScan results found. Configure URLSCAN_API_KEY to submit new scans."}

    url_to_scan = original_url or (f"http://{target}" if _is_ip(target) else f"https://{target}")
    try:
        sub_resp = requests.post(
            "https://urlscan.io/api/v1/scan/",
            headers={**headers, "Content-Type": "application/json"},
            json={"url": url_to_scan, "visibility": "public"},
            timeout=15,
        )
        sub_resp.raise_for_status()
        uuid = sub_resp.json().get("uuid", "")
    except Exception as exc:
        return {"error": f"URLScan submission failed: {exc}"}

    if not uuid:
        return {"error": "URLScan did not return a scan UUID"}

    # Step 3: poll until result is ready (up to ~30s)
    time.sleep(5)
    for _ in range(5):
        time.sleep(5)
        try:
            result_resp = requests.get(
                f"https://urlscan.io/api/v1/result/{uuid}/",
                headers=headers, timeout=15,
            )
            if result_resp.status_code == 200:
                return _parse_urlscan_result(result_resp.json(), uuid, "submission")
        except Exception:
            pass

    return {
        "error": f"URLScan scan still processing — check urlscan.io/result/{uuid}/",
        "scan_url": f"https://urlscan.io/result/{uuid}/",
    }


# ─── VirusTotal hash lookup ───────────────────────────────────────────────────

def lookup_hash_virustotal(api_key: str, hash_value: str, dry_run: bool) -> dict:
    if dry_run:
        return {
            "name": "malware_sample.exe",
            "type": "Win32 EXE",
            "size": 245760,
            "malicious": 58,
            "suspicious": 3,
            "undetected": 14,
            "total_engines": 75,
            "last_seen": "2025-03-12",
            "reputation": -75,
            "votes_harmless": 0,
            "votes_malicious": 12,
        }

    if not api_key:
        return {"error": "VIRUSTOTAL_API_KEY not configured"}

    try:
        resp = requests.get(
            f"https://www.virustotal.com/api/v3/files/{hash_value}",
            headers={"x-apikey": api_key},
            timeout=15,
        )
        if resp.status_code == 404:
            return {"error": "Hash not found in VirusTotal database"}
        if resp.status_code == 429:
            return {"error": "VirusTotal rate limit (4 req/min on free plan)"}
        resp.raise_for_status()
        attr = resp.json().get("data", {}).get("attributes", {})
        stats = attr.get("last_analysis_stats", {})
        votes = attr.get("total_votes", {})
        last_seen = attr.get("last_submission_date")
        if last_seen:
            from datetime import datetime as _dt
            last_seen = _dt.utcfromtimestamp(last_seen).strftime("%Y-%m-%d")
        return {
            "name": attr.get("meaningful_name") or attr.get("name"),
            "type": attr.get("type_description"),
            "size": attr.get("size"),
            "malicious": stats.get("malicious", 0),
            "suspicious": stats.get("suspicious", 0),
            "undetected": stats.get("undetected", 0),
            "total_engines": sum(stats.values()),
            "last_seen": last_seen,
            "reputation": attr.get("reputation", 0),
            "votes_harmless": votes.get("harmless", 0),
            "votes_malicious": votes.get("malicious", 0),
        }
    except Exception as exc:
        return {"error": str(exc)}


# ─── Orchestrator ─────────────────────────────────────────────────────────────

def run_passive_osint(app, target: str, dry_run: bool, status: dict, scan_path, original_url: str = "") -> dict:
    from pathlib import Path

    cfg = app.config
    ip = _resolve_ip(target)
    is_domain = not _is_ip(target)

    results: dict = {"ip": ip}

    def _upd(module_name: str, progress: int):
        status["current_module"] = module_name
        status["progress"] = progress
        (Path(scan_path) / "status.json").write_text(
            json.dumps(status, ensure_ascii=False, indent=2)
        )

    _upd("Shodan", 12)
    results["shodan"] = run_shodan(cfg.get("SHODAN_API_KEY", ""), ip, dry_run)
    time.sleep(0.3)

    _upd("VirusTotal", 18)
    results["virustotal"] = run_virustotal(cfg.get("VIRUSTOTAL_API_KEY", ""), ip, dry_run)
    time.sleep(0.3)

    _upd("AbuseIPDB", 24)
    results["abuseipdb"] = run_abuseipdb(cfg.get("ABUSEIPDB_API_KEY", ""), ip, dry_run)
    time.sleep(0.2)

    _upd("WHOIS", 28)
    results["whois"] = run_whois(target, dry_run)
    time.sleep(0.2)

    _upd("URLScan.io", 33)
    results["urlscan"] = run_urlscan(cfg.get("URLSCAN_API_KEY", ""), target, dry_run, original_url)
    time.sleep(0.2)

    if is_domain:
        _upd("crt.sh subdomains", 37)
        results["crtsh"] = run_crtsh(target, dry_run)
    else:
        results["crtsh"] = None

    _upd("Wayback Machine", 40)
    results["wayback"] = run_wayback(target, dry_run)

    return results
