import json
import threading
import uuid
from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse


def _extract_host(raw: str) -> tuple[str, str]:
    """Return (hostname_or_ip, original_url).

    If raw is a URL (contains '://'), hostname is extracted and original_url is raw.
    Otherwise original_url is empty string.
    """
    s = raw.strip()
    if "://" in s:
        parsed = urlparse(s)
        return parsed.hostname or s, s
    return s, ""

def _scan_dir(app, scan_id: str) -> Path:
    d = Path(app.config["SCANS_DIR"]) / scan_id
    d.mkdir(parents=True, exist_ok=True)
    return d


def _atomic_write(dest: Path, data: dict):
    tmp = dest.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    tmp.replace(dest)


def _write_status(path: Path, data: dict):
    _atomic_write(path / "status.json", data)


def _write_results(path: Path, data: dict):
    _atomic_write(path / "results.json", data)


def read_status(app, scan_id: str) -> dict | None:
    f = Path(app.config["SCANS_DIR"]) / scan_id / "status.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def read_results(app, scan_id: str) -> dict | None:
    f = Path(app.config["SCANS_DIR"]) / scan_id / "results.json"
    if not f.exists():
        return None
    try:
        return json.loads(f.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError):
        return None


def list_scans(app) -> list[dict]:
    scans_dir = Path(app.config["SCANS_DIR"])
    scans = []
    for status_file in scans_dir.glob("*/status.json"):
        try:
            scans.append(json.loads(status_file.read_text()))
        except Exception:
            pass
    scans.sort(key=lambda s: s.get("started_at", ""), reverse=True)
    return scans


def create_hash_report(app, results: list[dict], dry_run: bool) -> str:
    """Save pre-computed VirusTotal hash results as a report. Returns scan_id."""
    scan_id = str(uuid.uuid4())
    scan_path = _scan_dir(app, scan_id)

    malicious_count  = sum(1 for r in results if not r.get("error") and (r.get("malicious") or 0) > 0)
    suspicious_count = sum(1 for r in results if not r.get("error") and (r.get("malicious") or 0) == 0 and (r.get("suspicious") or 0) > 0)
    now = datetime.utcnow().isoformat()

    status = {
        "id":               scan_id,
        "type":             "hash",
        "status":           "done",
        "hash_count":       len(results),
        "malicious_count":  malicious_count,
        "suspicious_count": suspicious_count,
        "dry_run":          dry_run,
        "started_at":       now,
        "finished_at":      now,
    }

    _write_status(scan_path, status)
    _write_results(scan_path, {"type": "hash", "results": results})
    return scan_id


def delete_scan(app, scan_id: str):
    import shutil
    scan_path = Path(app.config["SCANS_DIR"]) / scan_id
    if scan_path.exists():
        shutil.rmtree(scan_path)


# ─── Runner ───────────────────────────────────────────────────────────────────

def start_scan(app, target: str, scan_mode: str, dry_run: bool, ports: str = "") -> str:
    scan_id = str(uuid.uuid4())
    scan_path = _scan_dir(app, scan_id)

    host, original_url = _extract_host(target)

    status = {
        "id": scan_id,
        "target": host,
        "original_url": original_url,
        "scan_mode": scan_mode,
        "ports": ports,
        "dry_run": dry_run,
        "status": "queued",
        "progress": 0,
        "current_module": None,
        "modules": {
            "passive_osint": "pending" if scan_mode in ("passive", "full") else "skipped",
            "active_scan":   "pending" if scan_mode in ("active",  "full") else "skipped",
            "cve_lookup":    "pending",
            "mitre_mapper":  "pending",
        },
        "started_at": datetime.utcnow().isoformat(),
        "finished_at": None,
        "error": None,
        "cve_count": 0,
        "attck_count": 0,
    }
    _write_status(scan_path, status)

    t = threading.Thread(target=_run_scan, args=(app, scan_id, scan_path, status), daemon=True)
    t.start()
    return scan_id


def _update(scan_path: Path, state: dict, **kwargs):
    state.update(kwargs)
    _write_status(scan_path, state)


def _run_scan(app, scan_id: str, scan_path: Path, status: dict):
    import traceback as _tb

    def _fail(exc_text: str, tb_text: str):
        try:
            _update(scan_path, status,
                    status="error", error=exc_text,
                    finished_at=datetime.utcnow().isoformat())
        except Exception:
            pass
        try:
            (scan_path / "error.log").write_text(tb_text)
        except Exception:
            pass

    try:
        _update(scan_path, status, status="running", progress=5, current_module="Initializing")

        target = status["target"]
        original_url = status.get("original_url", "")
        dry_run = status["dry_run"]
        scan_mode = status["scan_mode"]
        ports = status.get("ports", "")
        results: dict = {"target": target, "scan_mode": scan_mode}

        # ── 1. Passive OSINT (passive / full) ────────────────────────────
        if scan_mode in ("passive", "full"):
            _update(scan_path, status,
                    modules={**status["modules"], "passive_osint": "running"},
                    progress=10, current_module="Passive OSINT")

            from app.modules.passive_osint import run_passive_osint
            results["passive_osint"] = run_passive_osint(app, target, dry_run, status, scan_path, original_url)

            _update(scan_path, status,
                    modules={**status["modules"], "passive_osint": "done"},
                    progress=40, current_module="Passive OSINT done")
        else:
            results["passive_osint"] = None

        # ── 2. Active scan (active / full) ────────────────────────────────
        if scan_mode in ("active", "full"):
            _update(scan_path, status,
                    modules={**status["modules"], "active_scan": "running"},
                    progress=45, current_module="Active Scan (nmap)")

            from app.modules.active_scan import run_active_scan
            results["active_scan"] = run_active_scan(app, target, dry_run, ports)

            _update(scan_path, status,
                    modules={**status["modules"], "active_scan": "done"},
                    progress=65, current_module="Active scan done")
        else:
            results["active_scan"] = None

        # ── 3. CVE lookup ─────────────────────────────────────────────────
        _update(scan_path, status,
                modules={**status["modules"], "cve_lookup": "running"},
                progress=70, current_module="CVE Lookup")

        from app.modules.cve_lookup import lookup_cves
        services = _extract_services(results)
        results["cve_lookup"] = lookup_cves(app, services, dry_run)

        cve_count = sum(len(r.get("cves", [])) for r in results["cve_lookup"])
        _update(scan_path, status,
                modules={**status["modules"], "cve_lookup": "done"},
                progress=85, current_module="CVE lookup done",
                cve_count=cve_count)

        # ── 4. MITRE ATT&CK mapping ───────────────────────────────────────
        _update(scan_path, status,
                modules={**status["modules"], "mitre_mapper": "running"},
                progress=90, current_module="MITRE ATT&CK Mapping")

        from app.modules.mitre_mapper import map_to_attck
        results["mitre"] = map_to_attck(results)

        attck_count = len(results["mitre"])
        _update(scan_path, status,
                modules={**status["modules"], "mitre_mapper": "done"},
                progress=95, current_module="Mapping done",
                attck_count=attck_count)

        _write_results(scan_path, results)
        _update(scan_path, status,
                status="done", progress=100, current_module=None,
                finished_at=datetime.utcnow().isoformat())

    except Exception as exc:
        _fail(str(exc), _tb.format_exc())


def _extract_services(results: dict) -> list[dict]:
    services = []
    # From active scan nmap results
    active = results.get("active_scan") or {}
    for port in active.get("nmap", {}).get("ports", []):
        svc = port.get("service", "")
        ver = port.get("version", "")
        if svc and ver:
            services.append({"service": svc, "version": ver, "port": port.get("port")})
    # From shodan banners
    shodan_data = (results.get("passive_osint") or {}).get("shodan", {})
    for banner in shodan_data.get("banners", []):
        text = banner.get("banner", "")
        if text:
            # crude extraction: first line often has product/version
            first_line = text.split("\n")[0][:80]
            if first_line:
                services.append({"service": "unknown", "version": first_line, "port": banner.get("port")})
    return services


