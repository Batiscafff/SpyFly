"""
CVE lookup module via NIST NVD API v2.0.

For each service+version found, queries NVD and returns CVE list with CVSS scores.
Primary strategy: CPE-based lookup (accurate, version-range aware).
Fallback: keyword search with cleaned/normalised version string.

Rate limits (without API key): 5 requests per 30 seconds.
Rate limits (with API key):    50 requests per 30 seconds.
"""

import re
import time
import urllib.parse

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DELAY_NO_KEY = 6.5   # ~5 req/30s with margin
DELAY_WITH_KEY = 0.7  # ~50 req/30s with margin

# Maps regex patterns against nmap version strings → (vendor, product) for CPE construction.
# Order matters: more specific patterns first.
_CPE_PATTERNS = [
    (r"^Apache httpd (\S+)",              "apache",       "http_server"),
    (r"^Apache Tomcat[/ ](\S+)",          "apache",       "tomcat"),
    (r"^nginx[/ ](\S+)",                  "f5",           "nginx"),
    (r"^OpenSSH[/ ](\S+)",               "openbsd",      "openssh"),
    (r"^MySQL[/ ](\S+)",                  "oracle",       "mysql"),
    (r"^MariaDB[/ ](\S+)",               "mariadb",      "mariadb"),
    (r"^PostgreSQL[/ ](\S+)",            "postgresql",   "postgresql"),
    (r"^Microsoft IIS httpd[/ ](\S+)",   "microsoft",    "internet_information_services"),
    (r"^ProFTPD[/ ](\S+)",               "proftpd",      "proftpd"),
    (r"^vsftpd[/ ](\S+)",               "vsftpd_project","vsftpd"),
    (r"^Dovecot[/ ](\S+)",              "dovecot",       "dovecot"),
    (r"^MongoDB[/ ](\S+)",              "mongodb",       "mongodb"),
    (r"^Redis[/ ](\S+)",                "redis",         "redis"),
    (r"^Postfix smtpd[/ ](\S+)",        "postfix",       "postfix"),
    (r"^Exim smtpd[/ ](\S+)",           "exim",          "exim"),
    (r"^OpenSSL[/ ](\S+)",              "openssl",       "openssl"),
    (r"^PHP[/ ](\S+)",                  "php",           "php"),
    (r"^Samba smbd[/ ](\S+)",           "samba",         "samba"),
    (r"^OpenVPN[/ ](\S+)",              "openvpn",       "openvpn"),
    (r"^Elasticsearch[/ ](\S+)",        "elastic",       "elasticsearch"),
]

# Keyword-mode only: map nmap product names to the names NVD uses in descriptions.
_KEYWORD_NORMALISE = {
    "Apache httpd": "Apache HTTP Server",
}

# Distro-specific suffixes nmap appends — strip before NVD lookup.
_DISTRO_RE = re.compile(
    r"\s+(Ubuntu|Debian|CentOS|RHEL|Red\s+Hat|Fedora|Raspbian|Alpine|Arch)\b.*$",
    re.IGNORECASE,
)


def _version_to_cpe(version: str) -> str | None:
    """Return a CPE 2.3 string for a known nmap version string, or None."""
    for pattern, vendor, product in _CPE_PATTERNS:
        m = re.match(pattern, version, re.IGNORECASE)
        if m:
            ver = m.group(1)
            # Strip trailing punctuation and distro/build suffixes after version digits
            ver = re.sub(r"[,;]$", "", ver)
            ver = re.sub(r"[-+~]([a-zA-Z].*)$", "", ver)  # e.g. "5.7.32-log" → "5.7.32"
            ver = ver.strip(".")
            if not ver:
                return None
            return f"cpe:2.3:a:{vendor}:{product}:{ver}:*:*:*:*:*:*:*"
    return None


def _clean_keyword(service: str, version: str) -> str:
    """Build a clean NVD keyword from service + nmap version string."""
    v = version

    # Strip parenthesised OS notes: "nginx 1.18.0 (Ubuntu)" / "httpd 2.4.25 ((Debian))"
    v = re.sub(r"\s*\(+[^)]*\)+\s*$", "", v).strip()

    # Strip distro suffixes: "OpenSSH 9.6p1 Ubuntu 3ubuntu13.16" → "OpenSSH 9.6p1"
    v = _DISTRO_RE.sub("", v).strip()

    # Normalise product names to match NVD description language
    for old, new in _KEYWORD_NORMALISE.items():
        if v.startswith(old):
            v = new + v[len(old):]
            break

    # If version already contains a product name (starts with a letter),
    # don't prepend the nmap service name — it adds noise to the search
    if v and not v[0].isdigit():
        return v

    return f"{service} {v}".strip()


def _severity(score: float) -> str:
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score > 0.0:
        return "LOW"
    return "INFO"


def _parse_cves(data: dict) -> list[dict]:
    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        desc_list = cve.get("descriptions", [])
        description = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")

        score = 0.0
        vector = ""
        metrics = cve.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if key in metrics and metrics[key]:
                m = metrics[key][0].get("cvssData", {})
                score = m.get("baseScore", 0.0)
                vector = m.get("vectorString", "")
                break

        published = cve.get("published", "")[:10]
        cves.append({
            "id": cve_id,
            "description": description[:300],
            "score": score,
            "severity": _severity(score),
            "vector": vector,
            "published": published,
            "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}",
        })
    return cves


def _query_nvd(keyword: str, api_key: str, cpe_name: str | None = None) -> list[dict]:
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    def _get(url_or_base, params_dict=None, hdrs=None):
        h = hdrs if hdrs is not None else headers
        if params_dict is None:
            resp = requests.get(url_or_base, headers=h, timeout=20)
        else:
            resp = requests.get(url_or_base, params=params_dict, headers=h, timeout=20)
        if resp.status_code == 429:
            time.sleep(30)
            resp = requests.get(url_or_base, params=params_dict, headers=h, timeout=20) \
                if params_dict else requests.get(url_or_base, headers=h, timeout=20)
        # Invalid/expired API key causes NVD to return 404 — retry without key
        if resp.status_code == 404 and h.get("apiKey"):
            return _get(url_or_base, params_dict, hdrs={})
        return resp

    try:
        if cpe_name:
            # CPE contains ':' and '*' which requests would percent-encode,
            # breaking NVD's CPE lookup. Build the URL manually, preserving them.
            safe_cpe = urllib.parse.quote(cpe_name, safe=":*")
            cpe_url = f"{NVD_URL}?cpeName={safe_cpe}&resultsPerPage=50"
            resp = _get(cpe_url)
            if resp.status_code in (404, 400):
                # CPE not found or malformed — fall back to keyword search
                resp = _get(NVD_URL, {"keywordSearch": keyword, "resultsPerPage": 10})
        else:
            resp = _get(NVD_URL, {"keywordSearch": keyword, "resultsPerPage": 10})

        resp.raise_for_status()
        data = resp.json()
        # CPE returned 0 results (valid CPE but no matching records) — fall back to keyword
        if cpe_name and data.get("totalResults", -1) == 0:
            resp = _get(NVD_URL, {"keywordSearch": keyword, "resultsPerPage": 10})
            resp.raise_for_status()
            data = resp.json()
    except Exception as exc:
        return [{"error": str(exc)}]

    cves = _parse_cves(data)
    cves.sort(key=lambda c: c["score"], reverse=True)
    return cves[:20]  # top 20 by CVSS score


DRY_RUN_CVES = [
    {
        "id": "CVE-2021-41773",
        "description": "A flaw was found in Apache HTTP Server 2.4.49. An attacker could use a path traversal attack to map URLs to files outside the expected document root.",
        "score": 7.5, "severity": "HIGH", "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "published": "2021-10-05",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2021-41773",
    },
    {
        "id": "CVE-2019-0211",
        "description": "Apache HTTP Server privilege escalation from least-privileged child process to parent.",
        "score": 7.8, "severity": "HIGH", "vector": "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
        "published": "2019-04-08",
        "url": "https://nvd.nist.gov/vuln/detail/CVE-2019-0211",
    },
]


def lookup_cves(app, services: list[dict], dry_run: bool) -> list[dict]:
    """
    For each {service, version, port} in services, query NVD and return
    a list of dicts: {service, version, port, keyword, cpe, cves: [...]}.
    """
    if dry_run:
        return [
            {
                "service": "http", "version": "Apache httpd 2.4.25", "port": 80,
                "cves": DRY_RUN_CVES,
                "keyword": "Apache HTTP Server 2.4.25",
                "cpe": "cpe:2.3:a:apache:http_server:2.4.25:*:*:*:*:*:*:*",
            },
            {
                "service": "ssh", "version": "OpenSSH 8.2p1", "port": 22,
                "cves": [],
                "keyword": "OpenSSH 8.2p1",
                "cpe": "cpe:2.3:a:openbsd:openssh:8.2p1:*:*:*:*:*:*:*",
            },
        ]

    api_key = app.config.get("NVD_API_KEY", "")
    delay = DELAY_WITH_KEY if api_key else DELAY_NO_KEY

    results = []
    seen: set = set()

    for svc in services:
        service = (svc.get("service") or "").strip()
        version = (svc.get("version") or "").strip()
        port = svc.get("port")

        if not service or not version or len(version) < 3:
            continue

        cpe_name = _version_to_cpe(version)
        keyword = _clean_keyword(service, version)

        dedup_key = cpe_name or keyword
        if dedup_key in seen:
            continue
        seen.add(dedup_key)

        raw = _query_nvd(keyword, api_key, cpe_name=cpe_name)
        nvd_error = next((c["error"] for c in raw if "error" in c), None)
        cves = [c for c in raw if "error" not in c]
        entry = {
            "service": service,
            "version": version,
            "port": port,
            "keyword": keyword,
            "cpe": cpe_name,
            "cves": cves,
        }
        if nvd_error:
            entry["error"] = nvd_error
        results.append(entry)

        time.sleep(delay)

    return results
