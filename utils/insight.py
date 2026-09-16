# Workspace insight for MnemoCetus (v0.9) -> "what changed since last save" + "what's at risk".
#
# Read-only comparisons over the scan data the scanner already stores (git state, content mtime, sizes).
# Reused by the CLI, the web dashboard, and the export report so the three never drift.

import time

STALE_DAYS = 180  # "unused": no commit in this many days


def diff_databases(current, baseline):
    """
    Compare a current scan Database against a baseline Database (e.g. the long-term one).

    Returns {"new": [...], "removed": [...], "changed": [...], "grown": [...]} where each entry is a small
    dict keyed by project path. "changed" means the git commit / dirty-state / content mtime moved;
    "grown" carries the signed size delta.
    """
    cur = {p["path"]: p for p in current.all_projects()}
    base = {p["path"]: p for p in baseline.all_projects()}
    out = {"new": [], "removed": [], "changed": [], "grown": []}
    for path, p in cur.items():
        b = base.get(path)
        if b is None:
            out["new"].append({"path": path, "language": p.get("language"),
                               "size_bytes": p.get("size_bytes") or 0})
            continue
        if (p.get("git_head") != b.get("git_head")
                or bool(p.get("git_dirty")) != bool(b.get("git_dirty"))
                or p.get("content_mtime") != b.get("content_mtime")):
            out["changed"].append({"path": path, "now_dirty": bool(p.get("git_dirty")),
                                   "was_head": b.get("git_head"), "now_head": p.get("git_head")})
        delta = (p.get("size_bytes") or 0) - (b.get("size_bytes") or 0)
        if delta:
            out["grown"].append({"path": path, "delta_bytes": delta,
                                 "size_bytes": p.get("size_bytes") or 0})
    for path, b in base.items():
        if path not in cur:
            out["removed"].append({"path": path, "language": b.get("language"),
                                   "size_bytes": b.get("size_bytes") or 0})
    return out


def summarise_diff(d):
    """A one-line summary of a diff dict, e.g. '+3 new, -1 removed, 5 changed, 2 grew/shrank'."""
    parts = []
    if d["new"]:
        parts.append(f"+{len(d['new'])} new")
    if d["removed"]:
        parts.append(f"-{len(d['removed'])} removed")
    if d["changed"]:
        parts.append(f"{len(d['changed'])} changed")
    if d["grown"]:
        parts.append(f"{len(d['grown'])} grew/shrank")
    return ", ".join(parts) or "no changes since the baseline"


def git_gc_recommendations(db, min_bytes=50 * 1024 * 1024):
    """
    Git repos whose .git object store is worth compacting with `git gc`, measured live (count-objects per
    repo -> computed on demand, so scans stay fast). Returns {items, total_reclaimable}, where each item is
    {path, reclaimable, total}. Only repos with an estimate >= min_bytes are listed, biggest first.
    """
    import gitinfo
    items = []
    for p in db.all_projects():
        if not (p.get("git_head") or p.get("git_branch")):
            continue  # not a git repo
        size = gitinfo.git_dir_size(p["path"])
        if size and size["reclaimable_estimate"] >= min_bytes:
            items.append({"path": p["path"], "reclaimable": size["reclaimable_estimate"],
                          "total": size["total_bytes"]})
    items.sort(key=lambda it: it["reclaimable"], reverse=True)
    return {"items": items, "total_reclaimable": sum(it["reclaimable"] for it in items)}


def at_risk_projects(db, stale_days=STALE_DAYS, now=None):
    """
    Projects whose local git work could be lost, from the stored git state:
      uncommitted (dirty) / unpushed (ahead of upstream) / stale (no commit in a while).
    Returns [{path, language, risks: [...]}], only for projects that carry a git signal.
    """
    now = time.time() if now is None else now
    out = []
    for p in db.all_projects():
        if not (p.get("git_head") or p.get("git_branch")):
            continue  # not a git repo -> no git-shaped risk to report
        risks = []
        if p.get("git_dirty"):
            risks.append("uncommitted")
        if (p.get("git_ahead") or 0) > 0:
            risks.append("unpushed")
        last = p.get("git_last_commit")
        if last and (now - last) > stale_days * 86400:
            risks.append("stale")
        if risks:
            out.append({"path": p["path"], "language": p.get("language"), "risks": risks})
    return out
