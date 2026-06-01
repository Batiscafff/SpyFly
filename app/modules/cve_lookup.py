"""
CVE lookup module via NIST NVD API v2.0.

For each service+version found, queries NVD and returns CVE list with CVSS scores.

Rate limits (without API key): 5 requests per 30 seconds.
Rate limits (with API key):    50 requests per 30 seconds.
"""

import time

import requests

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DELAY_NO_KEY = 6.5   # ~5 req/30s with margin
DELAY_WITH_KEY = 0.7  # ~50 req/30s with margin

SEVERITY_MAP = {
    "CRITICAL": (9.0, 10.0),
    "HIGH":     (7.0, 8.9),
    "MEDIUM":   (4.0, 6.9),
    "LOW":      (0.1, 3.9),
    "INFO":     (0.0, 0.0),
}


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


def _query_nvd(keyword: str, api_key: str) -> list[dict]:
    params = {"keywordSearch": keyword, "resultsPerPage": 10}
    headers = {}
    if api_key:
        headers["apiKey"] = api_key

    try:
        resp = requests.get(NVD_URL, params=params, headers=headers, timeout=20)
        if resp.status_code == 429:
            time.sleep(30)
            resp = requests.get(NVD_URL, params=params, headers=headers, timeout=20)
        resp.raise_for_status()
        data = resp.json()
    except Exception as exc:
        return [{"error": str(exc)}]

    cves = []
    for vuln in data.get("vulnerabilities", []):
        cve = vuln.get("cve", {})
        cve_id = cve.get("id", "")
        desc_list = cve.get("descriptions", [])
        description = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")

        # Extract CVSS score — try v3.1, v3.0, v2.0
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

    cves.sort(key=lambda c: c["score"], reverse=True)
    return cves


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
    a list of dicts: {service, version, port, cves: [...]}.
    """
    if dry_run:
        return [
            {
                "service": "nginx", "version": "1.18.0", "port": 80,
                "cves": DRY_RUN_CVES[:2],
                "keyword": "nginx 1.18.0",
            },
            {
                "service": "openssh", "version": "OpenSSH 8.2p1", "port": 22,
                "cves": [],
                "keyword": "OpenSSH 8.2p1",
            },
        ]

    api_key = app.config.get("NVD_API_KEY", "")
    delay = DELAY_WITH_KEY if api_key else DELAY_NO_KEY

    results = []
    seen_keywords: set = set()

    for svc in services:
        service = (svc.get("service") or "").strip()
        version = (svc.get("version") or "").strip()
        port = svc.get("port")

        if not service or not version or len(version) < 3:
            continue

        keyword = f"{service} {version}".strip()
        if keyword in seen_keywords:
            continue
        seen_keywords.add(keyword)

        cves = _query_nvd(keyword, api_key)
        results.append({
            "service": service,
            "version": version,
            "port": port,
            "keyword": keyword,
            "cves": [c for c in cves if "error" not in c],
        })

        time.sleep(delay)

    return results
