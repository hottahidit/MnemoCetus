# Flask web app for MnemoCetus (v0.4 - the browser front-end over the "MnemoIndex" store and "MnemoClean" cleanup).
#
# Six views:
#   /          -> statistics dashboard (totals, by-language / by-category, confidence spread, reclaimable space)
#   /projects  -> filterable database viewer with recategorisation, which POSTs into db_manager.set_override / approve / clear_override / delete_project.
#   /cleanup   -> reclaimable-space cleanup recommendations (advisory only; never deletes anything).
#   /overlap   -> cross-project dependency overlap + rough env savings, and the version-conflict / shareable-venv check.
#   /storage   -> storage analysis (largest projects / files / directories + workspace rollup).
#   /security  -> MnemoScan findings: hard-coded secrets (masked) and optional dependency vulnerabilities.
#
# NOTE: this is a local, single-user tool, so the mutating POST routes don't carry CSRF tokens.

import os
import sys

from flask import Flask, render_template, request, redirect, url_for, Response

# Make the sibling modules (db_manager) importable whether it's run as a script or imported.
UTILS_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if UTILS_DIR not in sys.path:
    sys.path.insert(0, UTILS_DIR)

import db_manager  # noqa: E402
import report  # noqa: E402

# The categories offered in the recategorise dropdown (mirrors the CLI review choices).
CATEGORIES = ["backend", "frontend", "full stack", "automation", "library", "cli", "desktop", "application", "data/ml", "other"]

def _human_size(num_bytes):
    """Bytes -> readable string (kept local so the web layer never imports the scanner)."""
    size = float(num_bytes or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024

def _load_projects(db_path):
    """All inflated projects (override-aware), or [] when there's no database yet."""
    if not os.path.exists(db_path):
        return []
    db = db_manager.Database(db_path)
    try:
        return db.all_projects()
    finally:
        db.close()

def _latest_scan(db_path):
    if not os.path.exists(db_path):
        return None
    db = db_manager.Database(db_path)
    try:
        return db.latest_scan()
    finally:
        db.close()

def _reclaimable(db_path):
    """Workspace-wide reclaimable-space rollup (marks), or None when there's no database yet."""
    if not os.path.exists(db_path):
        return None
    db = db_manager.Database(db_path)
    try:
        return db.reclaimable_summary()
    finally:
        db.close()

def _cleanup(db_path, min_bytes=0):
    """Advisory cleanup recommendations (never deletes), or None when there's no database yet."""
    if not os.path.exists(db_path):
        return None
    db = db_manager.Database(db_path)
    try:
        return db.cleanup_recommendations(min_bytes=min_bytes)
    finally:
        db.close()

def _overlap(db_path, min_projects=2):
    """Cross-project dependency overlap + rough env savings, or None when there's no database yet."""
    if not os.path.exists(db_path):
        return None
    db = db_manager.Database(db_path)
    try:
        return db.dependency_overlap(min_projects=min_projects)
    finally:
        db.close()

def _intel(db_path, min_projects=2):
    """Version-aware dependency conflict / shareable-venv analysis, or None when there's no database yet."""
    if not os.path.exists(db_path):
        return None
    db = db_manager.Database(db_path)
    try:
        return db.dependency_intel(min_projects=min_projects)
    finally:
        db.close()

def _storage(db_path, limit=10):
    """Workspace storage analysis (largest projects / files / dirs), or None when there's no database yet."""
    if not os.path.exists(db_path):
        return None
    db = db_manager.Database(db_path)
    try:
        return db.storage_report(limit=limit)
    finally:
        db.close()

def _security(db_path):
    """Workspace MnemoScan rollup (secrets / vulns), or None when there's no database yet."""
    if not os.path.exists(db_path):
        return None
    db = db_manager.Database(db_path)
    try:
        return db.security_summary()
    finally:
        db.close()

def _project_detail(db_path, path):
    """Everything about one project (deps + marks + security findings), or None if it isn't in the db."""
    if not os.path.exists(db_path):
        return None
    db = db_manager.Database(db_path)
    try:
        project = db.get_project(path)
        if project is None:
            return None
        return {
            "project": project,
            "dependencies": db.get_dependencies(project["id"]),
            "marks": db.get_marks(project["id"]),
            "findings": db.get_security_findings(project["id"]),
        }
    finally:
        db.close()

def _dashboard_stats(projects):
    """Roll the project list up into the numbers the dashboard shows."""
    by_language, by_category = {}, {}
    confidence = {"low (<0.6)": 0, "medium (0.6-0.85)": 0, "high (>0.85)": 0}
    confirmed = 0
    for p in projects:
        lang, cat = (p["language"] or "unknown"), (p["category"] or "uncategorised")
        bl = by_language.setdefault(lang, {"count": 0, "bytes": 0})
        bl["count"] += 1
        bl["bytes"] += p["size_bytes"] or 0
        bc = by_category.setdefault(cat, {"count": 0, "bytes": 0})
        bc["count"] += 1
        bc["bytes"] += p["size_bytes"] or 0
        if p["user_confirmed"]:
            confirmed += 1
        c = p["confidence"] or 0
        if c < 0.6:
            confidence["low (<0.6)"] += 1
        elif c <= 0.85:
            confidence["medium (0.6-0.85)"] += 1
        else:
            confidence["high (>0.85)"] += 1
    return {
        "project_count": len(projects),
        "total_bytes": sum(p["size_bytes"] or 0 for p in projects),
        "total_files": sum(p["file_count"] or 0 for p in projects),
        "confirmed": confirmed,
        "by_language": dict(sorted(by_language.items(), key=lambda kv: kv[1]["bytes"], reverse=True)),
        "by_category": dict(sorted(by_category.items(), key=lambda kv: kv[1]["bytes"], reverse=True)),
        "confidence": confidence,
    }

def _filter_projects(projects, language, category, framework, query, only_uncertain, threshold=0.6):
    """Override-aware filtering over the inflated project list (filters on effective values)."""
    out = []
    for p in projects:
        if language and (p["language"] or "") != language:
            continue
        if category and (p["category"] or "") != category:
            continue
        if framework and framework not in p["frameworks"]:
            continue
        if query and query.lower() not in p["path"].lower():
            continue
        if only_uncertain and not ((p["confidence"] or 0) < threshold and not p["user_confirmed"]):
            continue
        out.append(p)
    return out

def create_app(db_path=None):
    """Flask app factory -> keeps things testable and lets us point at any .db file."""
    app = Flask(__name__)
    app.config["DB_PATH"] = db_path or db_manager.DEFAULT_DB_PATH
    app.jinja_env.filters["humansize"] = _human_size

    def current_db():
        return app.config["DB_PATH"]

    @app.route("/")
    def index():
        projects = _load_projects(current_db())
        return render_template(
            "index.html",
            db_path=os.path.normpath(current_db()),
            stats=_dashboard_stats(projects) if projects else None,
            latest_scan=_latest_scan(current_db()),
            reclaimable=_reclaimable(current_db()) if projects else None,
        )

    @app.route("/projects")
    def projects_view():
        projects = _load_projects(current_db())
        f = {
            "language": request.args.get("language") or "",
            "category": request.args.get("category") or "",
            "framework": request.args.get("framework") or "",
            "q": request.args.get("q") or "",
            "uncertain": request.args.get("uncertain") == "1",
        }
        shown = _filter_projects(projects, f["language"], f["category"], f["framework"], f["q"], f["uncertain"])
        return render_template(
            "projects.html",
            db_path=os.path.normpath(current_db()),
            projects=shown, total=len(projects),
            languages=sorted({p["language"] for p in projects if p["language"]}),
            categories=sorted({p["category"] for p in projects if p["category"]}),
            frameworks=sorted({fw for p in projects for fw in p["frameworks"]}),
            all_categories=CATEGORIES,
            filters=f,
            query_string=request.query_string.decode(),
        )

    @app.route("/cleanup")
    def cleanup_view():
        # ?min= lets the user hide trivially small dirs (value is in MB for a friendly URL).
        try:
            min_mb = float(request.args.get("min") or 0)
        except ValueError:
            min_mb = 0
        recs = _cleanup(current_db(), min_bytes=int(min_mb * 1024 * 1024))
        return render_template(
            "cleanup.html",
            db_path=os.path.normpath(current_db()),
            recs=recs,
            min_mb=min_mb,
        )

    @app.route("/overlap")
    def overlap_view():
        # ?min= sets how many projects a dep must appear in to count as "shared" (default 2).
        try:
            min_projects = max(2, int(request.args.get("min") or 2))
        except ValueError:
            min_projects = 2
        return render_template(
            "overlap.html",
            db_path=os.path.normpath(current_db()),
            overlap=_overlap(current_db(), min_projects=min_projects),
            intel=_intel(current_db(), min_projects=min_projects),
            min_projects=min_projects,
        )

    @app.route("/storage")
    def storage_view():
        return render_template(
            "storage.html",
            db_path=os.path.normpath(current_db()),
            report=_storage(current_db()),
        )

    @app.route("/security")
    def security_view():
        return render_template(
            "security.html",
            db_path=os.path.normpath(current_db()),
            summary=_security(current_db()),
        )

    @app.route("/export")
    def export_view():
        # ?format=md (default) or json -> download the whole workspace report as one file.
        fmt = "json" if request.args.get("format", "md").lower() == "json" else "md"
        path = current_db()
        if not os.path.exists(path):
            # Nothing scanned yet -> send them back to the dashboard rather than an empty file.
            return redirect(url_for("index"))
        body = report.render(report.build_report(path), fmt)
        mimetype = "application/json" if fmt == "json" else "text/markdown"
        return Response(
            body,
            mimetype=mimetype,
            headers={"Content-Disposition": f"attachment; filename={report.suggested_filename(fmt)}"},
        )

    @app.route("/project")
    def project_view():
        # ?path= -> the full detail for a single project (linked from the Projects table).
        return render_template(
            "project.html",
            db_path=os.path.normpath(current_db()),
            detail=_project_detail(current_db(), request.args.get("path", "")),
        )

    # --- mutations: POST then redirect back (preserving the current filters) -------- #
    def back():
        return redirect(request.form.get("next") or url_for("projects_view"))

    def with_db(action):
        if os.path.exists(current_db()):
            db = db_manager.Database(current_db())
            try:
                action(db)
            finally:
                db.close()
        return back()

    @app.route("/projects/override", methods=["POST"])
    def override():
        path = request.form["path"]
        return with_db(lambda db: db.set_override(
            path,
            language=request.form.get("language") or None,
            category=request.form.get("category") or None,
            note=request.form.get("note") or None,
        ))

    @app.route("/projects/approve", methods=["POST"])
    def approve():
        return with_db(lambda db: db.approve(request.form["path"]))

    @app.route("/projects/clear", methods=["POST"])
    def clear():
        return with_db(lambda db: db.clear_override(request.form["path"]))

    @app.route("/projects/delete", methods=["POST"])
    def delete():
        return with_db(lambda db: db.delete_project(request.form["path"]))

    return app


if __name__ == "__main__":
    # Dev server: 'python utils/web/app.py' -> http://127.0.0.1:5000
    create_app().run(debug=True)
