from flask import Blueprint, render_template, request, redirect, url_for, jsonify, abort, send_file, current_app, flash
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

    if not target:
        flash("Target is required.", "danger")
        return redirect(url_for("main.index"))

    scan_id = scanner.start_scan(current_app._get_current_object(), target, scan_mode, dry_run)
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


@bp.route("/report/<scan_id>")
def download_report(scan_id):
    report_path = Path(current_app.config["REPORTS_DIR"]) / f"{scan_id}.html"
    if not report_path.exists():
        abort(404)
    return send_file(report_path, mimetype="text/html", as_attachment=False)


@bp.route("/scan/<scan_id>/delete", methods=["POST"])
def delete_scan(scan_id):
    scanner.delete_scan(current_app._get_current_object(), scan_id)
    flash("Scan deleted.", "info")
    return redirect(url_for("main.index"))
