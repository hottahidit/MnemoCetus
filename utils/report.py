# Report export for MnemoCetus (v0.6.1) -> render the whole workspace picture as one Markdown or JSON document.
#
# This is a read-only aggregator.
# It pulls the same findings the CLI and web already show (recognition, reclaimable / cleanup, dependency conflicts, security, storage) and serialises them into one portable report the user can keep, diff, or share.
# Both front-ends call build_report + render_markdown / render_json, so the CLI export and the web /export download are always the same document.

from datetime import datetime
import json

import db_manager


def _human_size(num_bytes):
    """Bytes -> readable string (kept local so the report layer never imports the scanner, matching the web layer)."""
    size = float(num_bytes or 0)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024


def _overview(projects):
    """Roll the project list up into the headline counts (kept in step with the web dashboard's _dashboard_stats)."""
    by_language, by_category = {}, {}
    confidence = {"low (<0.6)": 0, "medium (0.6-0.85)": 0, "high (>0.85)": 0}
    confirmed = 0
    for p in projects:
        by_language[p["language"] or "unknown"] = by_language.get(p["language"] or "unknown", 0) + 1
        by_category[p["category"] or "uncategorised"] = by_category.get(p["category"] or "uncategorised", 0) + 1
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
        "by_language": dict(sorted(by_language.items(), key=lambda kv: kv[1], reverse=True)),
        "by_category": dict(sorted(by_category.items(), key=lambda kv: kv[1], reverse=True)),
        "confidence": confidence,
    }


def build_report(db_path):
    """
    Assemble the full workspace report as a plain dict (JSON-serialisable throughout).

    Opens its own read-only connection so either front-end can call it with just a path.
    Every section mirrors a view the tool already shows on screen, so the export never drifts from the live UI.
    """
    db = db_manager.Database(db_path)
    try:
        projects = db.all_projects()
        return {
            "meta": {
                "tool": "MnemoCetus",
                "generated_at": datetime.now().isoformat(timespec="seconds"),
                "database": db_path,
                "latest_scan": db.latest_scan(),
            },
            "overview": _overview(projects),
            "projects": [
                {
                    "path": p["path"],
                    "language": p["language"],
                    "category": p["category"],
                    "frameworks": p["frameworks"],
                    "confidence": p["confidence"],
                    "user_confirmed": p["user_confirmed"],
                    "file_count": p["file_count"],
                    "size_bytes": p["size_bytes"],
                    "reclaimable_bytes": p["reclaimable_bytes"],
                    "dependency_count": len(p["dependencies"]),
                }
                for p in projects
            ],
            # The low-confidence review queue -> unconfirmed projects the recogniser wasn't sure about.
            "uncertain": [
                {"path": p["path"], "language": p["language"],
                 "category": p["category"], "confidence": p["confidence"]}
                for p in projects
                if not p["user_confirmed"] and (p["confidence"] or 0) < 0.6
            ],
            "reclaimable": db.reclaimable_summary(),
            "cleanup": db.cleanup_recommendations(),
            "dependency_intel": db.dependency_intel(),
            "security": db.security_summary(),
            "storage": db.storage_report(),
        }
    finally:
        db.close()


def render_json(report):
    """The report dict as pretty-printed JSON."""
    return json.dumps(report, indent=2, ensure_ascii=False)


def _md_escape(text):
    """Escape the pipe so a path or detail can't break out of a Markdown table row."""
    return str(text).replace("|", "\\|")


def _md_table(headers, rows):
    """A GitHub-flavoured Markdown table from a header list + row lists (returns '' when there are no rows)."""
    if not rows:
        return ""
    out = ["| " + " | ".join(headers) + " |",
           "| " + " | ".join("---" for _ in headers) + " |"]
    for row in rows:
        out.append("| " + " | ".join(_md_escape(c) for c in row) + " |")
    return "\n".join(out)


def render_markdown(report):
    """Render the report dict as one self-contained Markdown document."""
    meta, ov = report["meta"], report["overview"]
    lines = []
    w = lines.append

    w("# MnemoCetus workspace report")
    w("")
    w(f"Generated: {meta['generated_at']}")
    w(f"Database: {meta['database']}")
    scan = meta["latest_scan"]
    if scan:
        w(f"Latest scan: {scan['root_path']} -> {scan['project_count']} project(s), "
          f"{scan['file_count']} file(s), {_human_size(scan['total_bytes'] or 0)} "
          f"(finished {scan['finished_at']})")
    w("")

    # Overview.
    w("## Overview")
    w("")
    w(f"- Projects: {ov['project_count']} ({ov['confirmed']} user-confirmed)")
    w(f"- Total size: {_human_size(ov['total_bytes'])} across {ov['total_files']} file(s)")
    w("- Confidence: " + ", ".join(f"{k} {v}" for k, v in ov["confidence"].items()))
    w("")
    lang = _md_table(["language", "projects"], [[k, v] for k, v in ov["by_language"].items()])
    if lang:
        w("### By language")
        w("")
        w(lang)
        w("")
    cat = _md_table(["category", "projects"], [[k, v] for k, v in ov["by_category"].items()])
    if cat:
        w("### By category")
        w("")
        w(cat)
        w("")

    # Projects.
    w("## Projects")
    w("")
    proj_tbl = _md_table(
        ["path", "language", "category", "conf", "confirmed", "files", "size", "reclaimable", "deps"],
        [[p["path"], p["language"] or "?", p["category"] or "?", f"{p['confidence'] or 0:.2f}",
          "yes" if p["user_confirmed"] else "", p["file_count"] or 0, _human_size(p["size_bytes"] or 0),
          _human_size(p["reclaimable_bytes"] or 0), p["dependency_count"]]
         for p in report["projects"]])
    w(proj_tbl or "_No projects indexed yet._")
    w("")

    # Low-confidence review queue.
    if report["uncertain"]:
        w("## Low-confidence projects (need review)")
        w("")
        w(_md_table(["path", "language", "category", "conf"],
                    [[u["path"], u["language"] or "?", u["category"] or "?", f"{u['confidence'] or 0:.2f}"]
                     for u in report["uncertain"]]))
        w("")

    # Reclaimable + advisory cleanup.
    rec, cln = report["reclaimable"], report["cleanup"]
    w("## Reclaimable space")
    w("")
    if rec["total_bytes"]:
        w(f"Total regenerable bloat: {_human_size(rec['total_bytes'])}")
        w("")
        w(_md_table(["kind", "size", "dirs"],
                    [[k, _human_size(v["bytes"]), v["count"]] for k, v in rec["by_kind"].items()]))
        w("")
    else:
        w("_No reclaimable bloat recorded._")
        w("")
    if cln["item_count"]:
        w("### Cleanup recommendations (advisory -> nothing is ever deleted)")
        w("")
        w(f"Potential savings: {_human_size(cln['total_savings'])} across {cln['item_count']} director(y/ies).")
        w("")
        w(_md_table(["directory", "kind", "savings", "reason", "command"],
                    [[it["path"], it["kind"] or "?", _human_size(it["size_bytes"]), it["reason"] or "", it["command"]]
                     for it in cln["items"]]))
        w("")

    # Dependency conflicts.
    ecos = report["dependency_intel"]["ecosystems"]
    if ecos:
        w("## Dependency conflicts (shareable-environment check)")
        w("")
        for eco, d in ecos.items():
            if d["shareable"]:
                w(f"- **{eco}**: all {d['project_count']} project(s) could share one environment "
                  "(no conflicting exact pins).")
            else:
                w(f"- **{eco}**: {len(d['conflicting_projects'])} of {d['project_count']} project(s) conflict; "
                  f"{len(d['shareable_projects'])} could share one environment.")
        w("")
        for eco, d in ecos.items():
            if not d["conflicts"]:
                continue
            w(f"### {eco} version conflicts")
            w("")
            rows = []
            for cf in d["conflicts"]:
                for ver, paths in cf["pins"].items():
                    rows.append([cf["name"], ver, ", ".join(paths)])
            w(_md_table(["dependency", "version", "projects"], rows))
            w("")

    # Security (MnemoScan).
    sec = report["security"]
    w("## Security findings (MnemoScan)")
    w("")
    if sec["total"]:
        w(f"{sec['total']} finding(s): " + ", ".join(f"{k} {v}" for k, v in sec["by_severity"].items()) + ".")
        w("Secret values are masked -> the raw value is never stored.")
        w("")
        w(_md_table(["severity", "kind", "rule", "location", "detail"],
                    [[f["severity"], f["kind"], f["rule"],
                      f"{f['path']}:{f['line']}" if f["line"] else f["path"], f["detail"]]
                     for f in sec["findings"]]))
        w("")
    else:
        w("_No security findings recorded._")
        w("")

    # Storage.
    st = report["storage"]
    w("## Storage analysis")
    w("")
    if st["total_files"]:
        w(f"Workspace: {_human_size(st['total_bytes'])} across {st['total_files']} file(s) in "
          f"{st['project_count']} project(s). Reclaimable: {_human_size(st['reclaimable_bytes'])}.")
        w("")
        w("### Largest projects")
        w("")
        w(_md_table(["project", "size", "reclaimable"],
                    [[p["path"], _human_size(p["size_bytes"] or 0), _human_size(p["reclaimable_bytes"] or 0)]
                     for p in st["largest_projects"]]))
        w("")
        w("### Largest files")
        w("")
        w(_md_table(["file", "size"],
                    [[f["path"], _human_size(f["size_bytes"] or 0)] for f in st["largest_files"]]))
        w("")
        w("### Largest directories (bytes held directly)")
        w("")
        w(_md_table(["directory", "size", "files"],
                    [[d["path"], _human_size(d["size_bytes"] or 0), d["file_count"]] for d in st["largest_dirs"]]))
        w("")
    else:
        w("_No file inventory recorded._")
        w("")

    return "\n".join(lines).rstrip() + "\n"


def render(report, fmt):
    """Render to the requested format -> 'json', or Markdown for anything else ('md' / 'markdown')."""
    return render_json(report) if fmt == "json" else render_markdown(report)


def suggested_filename(fmt):
    """A default save / download name for the given format."""
    return "mnemocetus-report.json" if fmt == "json" else "mnemocetus-report.md"
