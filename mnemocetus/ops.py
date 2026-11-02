# Non-interactive operations for MnemoCetus -> the engine calls behind the `nemc` subcommands.
#
# Everything here is plain functions that take arguments and return dicts: no prompts, no printing
# (rendering lives in commands.py). That keeps them scriptable, testable, and reusable by the menu.
#
#   scan            -> scan a folder (incremental against the long-term DB), diff it, and save it
#   rescan          -> re-run scan over every folder that was saved before (or the one containing a path)
#   saved_roots     -> the folders the long-term DB has scans for
#   status          -> the state of the project at a path: clean / changed / security / unscanned
#   reclaim_plan    -> the cleanup candidates (optionally filtered), each paired with its scan root

import os
import shutil
import tempfile
import time

from mnemocetus.db import manager as db_manager


# --------------------------------------------------------------------------- #
# Paths
# --------------------------------------------------------------------------- #
def long_term_db(path=None):
    """The long-term database path: an explicit one, else the default ($MNEMOCETUS_DB / XDG / legacy)."""
    return os.path.abspath(os.path.expanduser(path)) if path else os.path.normpath(db_manager.DEFAULT_DB_PATH)


def _under(path, root):
    return path == root or path.startswith(root.rstrip(os.sep) + os.sep)


# --------------------------------------------------------------------------- #
# Scan / rescan
# --------------------------------------------------------------------------- #
def scan(directory, db_path=None, mode="CLASSIFY", filters=True, secrets=True, save=True, prune=True,
         workers=None, progress=None):
    """
    Scan 'directory' and (by default) save it into the long-term database.

    The scan runs into a private throwaway database first, incremental against the long-term one (unchanged
    projects reuse their stored results), then is diffed against it -> "what changed" -> and, with save,
    merged in. Saving also records the scan (root + totals) so `rescan` / `status` know what was scanned
    and when, and with prune drops saved projects under this folder whose directory no longer exists.

    Returns a dict: {root, project_count, file_count, total_bytes, changes (or None when there was no
    saved DB to compare against), saved (int or None), pruned [paths], db}.
    """
    from mnemocetus import insight
    from mnemocetus.scanner import persist_scan

    root = os.path.abspath(os.path.expanduser(directory))
    if not os.path.isdir(root):
        raise NotADirectoryError(f"not a directory: {root}")
    lt = long_term_db(db_path)
    baseline = lt if os.path.exists(lt) else None

    tmpdir = tempfile.mkdtemp(prefix="mnemocetus-scan-")  # private (0700) -> never a shared fixed path
    tmp_db = os.path.join(tmpdir, "scan.db")
    try:
        persist_scan(root, db_path=tmp_db, mode=mode, confirm_filters=filters, security=secrets,
                     progress=progress, workers=workers, baseline_db=baseline)
        with db_manager.Database(tmp_db) as cur:
            latest = cur.latest_scan() or {}
            changes = None
            if baseline:
                with db_manager.Database(baseline) as base:
                    changes = insight.diff_databases(cur, base, root=root)
        result = {"root": root, "db": lt, "project_count": latest.get("project_count") or 0,
                  "file_count": latest.get("file_count") or 0, "total_bytes": latest.get("total_bytes") or 0,
                  "changes": changes, "saved": None, "pruned": []}
        if save:
            with db_manager.Database(lt) as db:
                with db.batch():  # all-or-nothing: the save, the scan record and the prune land together
                    scan_id = db.start_scan(root)
                    result["saved"] = db.merge_from(tmp_db)
                    if prune:
                        for p in db.all_projects():
                            if _under(p["path"], root) and not os.path.isdir(p["path"]):
                                db.delete_project(p["path"])
                                result["pruned"].append(p["path"])
                    db.finish_scan(scan_id, project_count=result["project_count"],
                                   file_count=result["file_count"], total_bytes=result["total_bytes"])
        return result
    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def saved_roots(db_path=None):
    """
    The folders the long-term DB holds scans for, outermost only (rescanning /a covers /a/b), that still
    exist on disk. Most recently scanned first.
    """
    lt = long_term_db(db_path)
    if not os.path.exists(lt):
        return []
    with db_manager.Database(lt) as db:
        rows = db.con.execute(
            "SELECT root_path, MAX(id) AS last FROM scans GROUP BY root_path ORDER BY last DESC").fetchall()
    roots = [os.path.normpath(r["root_path"]) for r in rows if r["root_path"]]
    roots = [r for r in roots if os.path.isdir(r)]
    return [r for r in roots if not any(o != r and _under(r, o) for o in roots)]


def rescan(target=None, db_path=None, **scan_kwargs):
    """
    Re-scan saved folders: all of them, or (with 'target') the saved folder(s) containing that path. When
    'target' sits under no saved folder, it is scanned as a new root. Returns a list of scan() results.
    """
    roots = saved_roots(db_path)
    if target:
        t = os.path.abspath(os.path.expanduser(target))
        roots = [r for r in roots if _under(t, r)] or [t]
    return [scan(r, db_path=db_path, **scan_kwargs) for r in roots]


# --------------------------------------------------------------------------- #
# Status (the data behind the shell status light)
# --------------------------------------------------------------------------- #
CLEAN, CHANGED, SECURITY, UNSCANNED, UNKNOWN = "clean", "changed", "security", "unscanned", "unknown"


def _containing_project(db, path):
    """The deepest saved project that is 'path' or contains it, or None (one indexed-size query)."""
    return db.con.execute(
        "SELECT * FROM projects WHERE path = ? OR substr(?, 1, length(path) + 1) = path || ? "
        "ORDER BY length(path) DESC LIMIT 1", (path, path, os.sep)).fetchone()


def _content_changed(project, children, stored_mtime, deadline=None):
    """
    Has anything in the project changed since 'stored_mtime'? Mirrors what the scan's content_mtime covers
    (own files, hidden files, directories; excluded + hidden dirs pruned; child projects skipped) and stops
    at the first newer entry. Returns True / False, or None if the time budget ran out first.
    """
    from mnemocetus.scanner import Scanner, _is_excluded
    sc = Scanner(quiet=True)
    nr, pr = sc._name_rules, sc._path_rules
    threshold = stored_mtime + 1e-3
    skip = set(children)
    for root, dirs, files in os.walk(project):
        if deadline is not None and time.monotonic() > deadline:
            return None
        try:
            if os.stat(root).st_mtime > threshold:
                return True
        except OSError:
            pass
        dirs[:] = [d for d in dirs if not d.startswith('.')
                   and os.path.join(root, d) not in skip
                   and not _is_excluded(os.path.join(root, d), nr, pr)]
        for f in files:
            fp = os.path.join(root, f)
            if not f.startswith('.') and _is_excluded(fp, nr, pr):
                continue
            try:
                if os.stat(fp).st_mtime > threshold:
                    return True
            except OSError:
                continue
    return False


def status(path=".", db_path=None, budget=None):
    """
    The state of the project at 'path' (or containing it):
        security  -> stored security findings exist (red)            -- wins over changed
        changed   -> new commit or edited / added / removed files since the last saved scan (amber)
        clean     -> scanned and unchanged (green)
        unscanned -> no saved project here (no light)
        unknown   -> the change check ran out of its time 'budget' (seconds), e.g. inside a prompt
    Returns {state, path, project, language, category, findings, changed, reason, scanned_at}.
    Never prints, never runs a scan; only `git rev-parse HEAD` + a stat walk that stops at the first change.
    """
    from mnemocetus import gitinfo
    target = os.path.abspath(os.path.expanduser(path))
    out = {"state": UNSCANNED, "path": target, "project": None, "language": None, "category": None,
           "findings": 0, "changed": None, "reason": "no saved project here", "scanned_at": None}
    lt = long_term_db(db_path)
    if not os.path.exists(lt):
        out["reason"] = "nothing has been saved yet (run `nemc scan <dir>`)"
        return out
    deadline = time.monotonic() + budget if budget else None
    with db_manager.Database(lt) as db:
        row = _containing_project(db, target)
        if row is None:
            return out
        proj = row["path"]
        out.update(project=proj, language=row["override_language"] or row["language"],
                   category=row["override_category"] or row["category"], scanned_at=row["updated_at"])
        out["findings"] = db.con.execute(
            "SELECT COUNT(*) FROM security_findings WHERE project_id = ?", (row["id"],)).fetchone()[0]
        prefix = proj.rstrip(os.sep) + os.sep  # exact prefix match (LIKE would treat % / _ in paths as wildcards)
        children = [r["path"] for r in db.con.execute(
            "SELECT path FROM projects WHERE substr(path, 1, ?) = ?", (len(prefix), prefix))]
        stored_head, stored_mtime = row["git_head"], row["content_mtime"]

    changed, reason = None, None
    if stored_head:
        live_head = gitinfo._git(["rev-parse", "HEAD"], proj, timeout=2)
        if live_head and live_head != stored_head:
            changed, reason = True, "new commit(s) since the last scan"
    if changed is None:
        if not os.path.isdir(proj):
            changed, reason = True, "the project folder is gone"
        elif stored_mtime is None:
            changed, reason = True, "no change baseline stored (re-scan to record one)"
        else:
            c = _content_changed(proj, children, stored_mtime, deadline)
            if c is None:
                out.update(state=UNKNOWN, reason="change check timed out")
                if out["findings"]:
                    out["state"] = SECURITY
                return out
            changed, reason = c, ("files changed since the last scan" if c else None)
    out["changed"] = changed
    if out["findings"]:
        out["state"], out["reason"] = SECURITY, f"{out['findings']} stored security finding(s)"
        if changed:
            out["reason"] += f"; also {reason}"
    elif changed:
        out["state"], out["reason"] = CHANGED, reason
    else:
        out["state"], out["reason"] = CLEAN, "up to date with the last scan"
    return out


# --------------------------------------------------------------------------- #
# Reclaim
# --------------------------------------------------------------------------- #
def reclaim_plan(db_path=None, kinds=None, min_bytes=0, under=None):
    """
    The cleanup candidates from the long-term DB, filtered by kind / size / folder. Each item carries
    'root' = the saved scan folder it lives in (the reclaimer's safety guard refuses anything outside it).
    """
    lt = long_term_db(db_path)
    if not os.path.exists(lt):
        return {"items": [], "total_savings": 0}
    roots = saved_roots(db_path)
    with db_manager.Database(lt) as db:
        recs = db.cleanup_recommendations(min_bytes=min_bytes)
    scope = os.path.abspath(os.path.expanduser(under)) if under else None
    items = []
    for it in recs["items"]:
        if kinds and it["kind"] not in kinds:
            continue
        if scope and not _under(it["path"], scope):
            continue
        root = max((r for r in roots if _under(it["path"], r)), key=len, default=None)
        items.append({**it, "root": root})
    return {"items": items, "total_savings": sum(i["size_bytes"] or 0 for i in items)}
