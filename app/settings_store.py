import json
from pathlib import Path

KEYS = ["SHODAN_API_KEY", "VIRUSTOTAL_API_KEY", "ABUSEIPDB_API_KEY", "NVD_API_KEY", "URLSCAN_API_KEY", "GOOGLE_API_KEY", "GOOGLE_CSE_ID"]

def _path(app) -> Path:
    return Path(app.root_path).parent / "settings.json"


def load(app):
    """Read settings.json and push values into app.config (overrides .env)."""
    p = _path(app)
    if not p.exists():
        return
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        for key in KEYS:
            if data.get(key):
                app.config[key] = data[key]
    except Exception:
        pass


def read(app) -> dict:
    """Return current key values (from app.config, which may come from .env or settings.json)."""
    return {key: app.config.get(key, "") for key in KEYS}


def save(app, data: dict):
    """Write only the recognised keys to settings.json and update app.config live."""
    filtered = {key: data.get(key, "").strip() for key in KEYS}
    _path(app).write_text(json.dumps(filtered, indent=2, ensure_ascii=False), encoding="utf-8")
    for key, val in filtered.items():
        app.config[key] = val
