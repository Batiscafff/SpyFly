"""
MITRE ATT&CK rule-based mapper.

Takes aggregated scan results and maps findings to ATT&CK techniques.
No external libraries needed — pure rule engine.

map_to_attck(results) -> list[dict]
Each dict: {technique_id, technique_name, tactic, tactic_name, description, findings}
"""

TECHNIQUES = {
    "T1190": {
        "name": "Exploit Public-Facing Application",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1190/",
    },
    "T1133": {
        "name": "External Remote Services",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1133/",
    },
    "T1040": {
        "name": "Network Sniffing",
        "tactic": "TA0006",
        "tactic_name": "Credential Access / Discovery",
        "url": "https://attack.mitre.org/techniques/T1040/",
    },
    "T1203": {
        "name": "Exploitation for Client Execution",
        "tactic": "TA0002",
        "tactic_name": "Execution",
        "url": "https://attack.mitre.org/techniques/T1203/",
    },
    "T1596.001": {
        "name": "DNS / Passive DNS",
        "tactic": "TA0043",
        "tactic_name": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1596/001/",
    },
    "T1589.002": {
        "name": "Email Addresses",
        "tactic": "TA0043",
        "tactic_name": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1589/002/",
    },
    "T1592.002": {
        "name": "Software",
        "tactic": "TA0043",
        "tactic_name": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1592/002/",
    },
    "T1595.001": {
        "name": "Scanning IP Blocks",
        "tactic": "TA0043",
        "tactic_name": "Reconnaissance",
        "url": "https://attack.mitre.org/techniques/T1595/001/",
    },
    "T1583.001": {
        "name": "Domains",
        "tactic": "TA0042",
        "tactic_name": "Resource Development",
        "url": "https://attack.mitre.org/techniques/T1583/001/",
    },
    "T1078": {
        "name": "Valid Accounts",
        "tactic": "TA0001",
        "tactic_name": "Initial Access",
        "url": "https://attack.mitre.org/techniques/T1078/",
    },
}

# Remote admin ports → T1133
REMOTE_ADMIN_PORTS = {22, 3389, 5900, 5901, 23, 2222, 8022}
# Unencrypted service ports → T1040
UNENCRYPTED_PORTS = {21, 23, 80, 110, 143, 8080}
# Database ports → T1190 (exposed DB)
DB_PORTS = {3306, 5432, 6379, 27017, 1433, 5984}


def _open_ports(results: dict) -> set[int]:
    ports: set[int] = set()
    # From active scan
    active = results.get("active_scan") or {}
    for p in active.get("nmap", {}).get("ports", []):
        if p.get("state") == "open":
            ports.add(int(p["port"]))
    # From shodan (passive)
    shodan = (results.get("passive_osint") or {}).get("shodan", {})
    for p in shodan.get("ports", []):
        ports.add(int(p))
    return ports


def _get_cves(results: dict) -> list[dict]:
    all_cves = []
    for svc_result in results.get("cve_lookup") or []:
        all_cves.extend(svc_result.get("cves", []))
    return all_cves


def _get_subdomains(results: dict) -> list[str]:
    passive = results.get("passive_osint") or {}

    # crt.sh
    crtsh = passive.get("crtsh") or {}
    crt_domains = [d["name"] for d in crtsh.get("domains", [])]

    # DNS brute
    active = results.get("active_scan") or {}
    dns_found = [d["subdomain"] for d in (active.get("dns_brute") or {}).get("found", [])]

    return list(set(crt_domains + dns_found))


def _get_emails(results: dict) -> list[str]:
    passive = results.get("passive_osint") or {}
    return (passive.get("whois") or {}).get("emails", [])


def _has_high_cve(cves: list[dict]) -> bool:
    return any(c.get("score", 0) >= 7.0 for c in cves)


def _has_rce_cve(cves: list[dict]) -> bool:
    """Heuristic: CVE description mentions RCE-related keywords."""
    rce_keywords = {"remote code execution", "rce", "arbitrary code", "command injection",
                    "code injection", "shell", "privilege escalation"}
    for c in cves:
        desc = c.get("description", "").lower()
        if any(kw in desc for kw in rce_keywords):
            return True
    return False


def map_to_attck(results: dict) -> list[dict]:
    findings: dict[str, dict] = {}  # technique_id -> technique info + findings list

    def _add(tid: str, reason: str):
        if tid not in findings:
            t = TECHNIQUES[tid]
            findings[tid] = {
                "technique_id": tid,
                "technique_name": t["name"],
                "tactic": t["tactic"],
                "tactic_name": t["tactic_name"],
                "url": t["url"],
                "findings": [],
            }
        findings[tid]["findings"].append(reason)

    open_ports = _open_ports(results)
    cves = _get_cves(results)
    subdomains = _get_subdomains(results)
    emails = _get_emails(results)

    # T1595.001 — Shodan or nmap scan reveals open ports
    if open_ports:
        _add("T1595.001", f"Host has {len(open_ports)} open port(s): {sorted(open_ports)[:10]}")

    # T1190 — Public service with known CVE (score ≥ 7.0)
    if _has_high_cve(cves):
        high_ids = [c["id"] for c in cves if c.get("score", 0) >= 7.0][:5]
        _add("T1190", f"High/Critical CVEs on public service: {', '.join(high_ids)}")

    # T1190 — Exposed database ports
    exposed_dbs = open_ports & DB_PORTS
    if exposed_dbs:
        _add("T1190", f"Exposed database port(s): {sorted(exposed_dbs)}")

    # T1133 — Remote admin interface open
    exposed_admin = open_ports & REMOTE_ADMIN_PORTS
    if exposed_admin:
        _add("T1133", f"Remote admin port(s) open: {sorted(exposed_admin)}")

    # T1040 — Unencrypted service
    exposed_unencrypted = open_ports & UNENCRYPTED_PORTS
    if exposed_unencrypted:
        _add("T1040", f"Unencrypted service port(s) open: {sorted(exposed_unencrypted)}")

    # T1203 — CVE with RCE potential
    if _has_rce_cve(cves):
        rce_cves = [c["id"] for c in cves
                    if any(kw in c.get("description","").lower()
                           for kw in {"remote code execution","rce","arbitrary code","command injection"})][:3]
        _add("T1203", f"CVE(s) with RCE potential: {', '.join(rce_cves)}")

    # T1596.001 — Subdomains discovered
    if subdomains:
        _add("T1596.001", f"{len(subdomains)} subdomain(s) found via crt.sh / DNS brute")

    # T1589.002 — Email addresses exposed via WHOIS
    if emails:
        _add("T1589.002", f"Email(s) in WHOIS record: {', '.join(emails[:3])}")

    # T1592.002 — Service versions identified (attack surface intelligence)
    active = results.get("active_scan") or {}
    versioned = [
        f"{p['service']} {p['version']}"
        for p in active.get("nmap", {}).get("ports", [])
        if p.get("version")
    ]
    if versioned:
        _add("T1592.002", f"Software versions identified: {', '.join(versioned[:5])}")

    # T1583.001 — Domain registrar/WHOIS data
    passive = results.get("passive_osint") or {}
    whois = passive.get("whois") or {}
    if whois.get("registrar") and not whois.get("error"):
        _add("T1583.001", f"Domain registration data available via WHOIS (registrar: {whois['registrar']})")

    # T1078 — Shodan shows vulns in its database
    shodan = passive.get("shodan") or {}
    shodan_vulns = shodan.get("vulns", [])
    if shodan_vulns:
        _add("T1078", f"Shodan-listed vulnerabilities: {', '.join(shodan_vulns[:5])}")

    # T1190 — SSL expired
    ssl_data = active.get("ssl") or {}
    if ssl_data.get("expired"):
        _add("T1190", "SSL certificate is expired — service may be vulnerable or misconfigured")

    return list(findings.values())
