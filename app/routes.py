import re
from flask import Blueprint, render_template, request, redirect, url_for, jsonify, abort, send_file, current_app, flash, Response
from pathlib import Path
from app import scanner

bp = Blueprint("main", __name__)


@bp.route("/")
def index():
    scans = scanner.list_scans(current_app._get_current_object())
    return render_template("index.html", scans=scans)


@bp.route("/scan", methods=["POST"])
def start_scan():
    target = request.form.get("target", "").strip()
    scan_mode = request.form.get("scan_mode", "passive")
    dry_run = bool(request.form.get("dry_run"))
    ports = request.form.get("ports", "").strip()

    if not target:
        flash("Target is required.", "danger")
        return redirect(url_for("main.index"))

    scan_id = scanner.start_scan(current_app._get_current_object(), target, scan_mode, dry_run, ports)
    return redirect(url_for("main.scan_page", scan_id=scan_id))


@bp.route("/scan/<scan_id>")
def scan_page(scan_id):
    app = current_app._get_current_object()
    status = scanner.read_status(app, scan_id)
    if status is None:
        abort(404)

    if status["status"] == "done":
        results = scanner.read_results(app, scan_id) or {}
        return render_template("scan_report.html", status=status, results=results,
                               generated_at=status.get("finished_at", "")[:16].replace("T", " ") + " UTC")

    return render_template("scan_progress.html", status=status)


@bp.route("/api/scan/<scan_id>/status")
def scan_status_api(scan_id):
    status = scanner.read_status(current_app._get_current_object(), scan_id)
    if status is None:
        abort(404)
    return jsonify(status)


def _make_standalone_html(app, scan_id: str) -> str:
    """Render the report and inline custom.css so the file is self-contained."""
    from datetime import datetime as _dt

    status = scanner.read_status(app, scan_id)
    results = scanner.read_results(app, scan_id)
    if not status or status.get("status") != "done":
        return ""

    html = render_template(
        "scan_report.html",
        status=status,
        results=results or {},
        generated_at=_dt.utcnow().strftime("%Y-%m-%d %H:%M UTC"),
    )

    css_path = Path(app.root_path).parent / "static" / "css" / "custom.css"
    if css_path.exists():
        css = css_path.read_text(encoding="utf-8")
        html = re.sub(
            r'<link[^>]+custom\.css[^>]*/?>',
            f'<style>\n{css}\n</style>',
            html,
        )

    return html


@bp.route("/report/<scan_id>")
def download_report(scan_id):
    app = current_app._get_current_object()
    html = _make_standalone_html(app, scan_id)
    if not html:
        abort(404)

    target = (scanner.read_status(app, scan_id) or {}).get("target", scan_id[:8])
    filename = f"spyfly-{target}.html"

    return Response(
        html,
        mimetype="text/html; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@bp.route("/scan/<scan_id>/delete", methods=["POST"])
def delete_scan(scan_id):
    scanner.delete_scan(current_app._get_current_object(), scan_id)
    flash("Scan deleted.", "info")
    return redirect(url_for("main.index"))


@bp.route("/scans/delete-bulk", methods=["POST"])
def delete_bulk():
    app = current_app._get_current_object()
    ids = request.get_json(silent=True) or {}
    for scan_id in ids.get("ids", []):
        scanner.delete_scan(app, scan_id)
    return jsonify({"ok": True})


@bp.route("/settings", methods=["GET", "POST"])
def settings():
    from app import settings_store
    app = current_app._get_current_object()
    if request.method == "POST":
        settings_store.save(app, request.form.to_dict())
        flash("Settings saved.", "success")
        return redirect(url_for("main.settings"))
    return render_template("settings.html", settings=settings_store.read(app))
