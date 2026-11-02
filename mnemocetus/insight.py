# Workspace insight for MnemoCetus (v0.9) -> "what changed since last save" + "what's at risk".
#
# Read-only comparisons over the scan data the scanner already stores (git state, content mtime, sizes).
# Reused by the CLI, the web dashboard, and the export report so the three never drift.

import os
import time

STALE_DAYS = 180  # "unused": no commit in this many days


def _under(path, root):
    """True if 'path' is 'root' or lives inside it (both normalised)."""
    return root is None or path == root or path.startswith(root.rstrip(os.sep) + os.sep)


def _all_marks(db):
    """{project_path: [mark, ...]} for the whole database in ONE query (not one per project)."""
    out = {}
    for r in db.con.execute(
            "SELECT p.path AS project_path, m.kind, m.name, m.path, m.size_bytes, m.reason "
            "FROM marks m JOIN projects p ON p.id = m.project_id"):
        out.setdefault(r["project_path"], []).append(dict(r))
    return out


def _all_findings(db):
    """{project_path: [finding, ...]} for the whole database in ONE query."""
    out = {}
    for r in db.con.execute(
            "SELECT p.path AS project_path, s.kind, s.rule, s.severity, s.path, s.line, s.detail "
            "FROM security_findings s JOIN projects p ON p.id = s.project_id"):
        out.setdefault(r["project_path"], []).append(dict(r))
    return out


def _finding_key(f):
    """
    Identity of a finding across scans. The line number is deliberately left out: editing code above a
    secret shifts its line, and that must not read as "one resolved + one new".
    """
    return (f["kind"], f["rule"], os.path.normpath(f["path"] or ""), f["detail"])


_SEV_RANK = {"high": 0, "medium": 1, "low": 2}


def diff_databases(current, baseline, root=None):
    """
    Compare a current scan Database against a baseline Database (e.g. the long-term one) -> "what changed".

    'root' limits the comparison to one workspace folder (default: the current database's latest scan
    root). The baseline usually holds MANY scans' worth of projects; without the scope, scanning one
    sub-folder would report every other saved project as "removed".

    Returns a dict:
        root                 -> the folder compared
        new / removed        -> projects that appeared / disappeared ({path, language, size_bytes})
        changed              -> projects whose git commit / dirty state / content mtime moved
        grown                -> projects whose size changed ({path, delta_bytes, size_bytes})
        new_findings         -> security findings not present in the baseline (secrets, exposures, vulns),
                                most severe first. A brand-new project's findings count as new.
        resolved_findings    -> baseline findings that are gone now (only for projects both scans checked)
        unchecked            -> project paths where one side didn't run the secret scan, so their findings
                                can't be compared (reported instead of silently treated as "no change")
        new_bloat            -> reclaimable dirs (marks) that weren't there before ({project_path, path, ...})
        removed_bloat        -> marks that are gone (deleted / reclaimed)
        bloat_delta_bytes    -> net change in reclaimable bytes across the compared projects
    """
    if root is None:
        scan = current.latest_scan()
        root = scan["root_path"] if scan else None
    root = os.path.normpath(root) if root else None

    cur = {p["path"]: p for p in current.all_projects() if _under(p["path"], root)}
    base = {p["path"]: p for p in baseline.all_projects() if _under(p["path"], root)}
    cur_marks, base_marks = _all_marks(current), _all_marks(baseline)
    cur_finds, base_finds = _all_findings(current), _all_findings(baseline)

    out = {"root": root, "new": [], "removed": [], "changed": [], "grown": [],
           "new_findings": [], "resolved_findings": [], "unchecked": [],
           "new_bloat": [], "removed_bloat": [], "bloat_delta_bytes": 0}

    for path, p in cur.items():
        b = base.get(path)
        # --- bloat: by mark path (sizes inside a mark that merely grew are reflected in the delta)
        now_marks = {m["path"]: m for m in cur_marks.get(path, [])}
        was_marks = {m["path"]: m for m in base_marks.get(path, [])} if b else {}
        out["new_bloat"] += [m for mp, m in now_marks.items() if mp not in was_marks]
        out["removed_bloat"] += [m for mp, m in was_marks.items() if mp not in now_marks]
        out["bloat_delta_bytes"] += (p.get("reclaimable_bytes") or 0) - ((b or {}).get("reclaimable_bytes") or 0)

        # --- findings
        now_f = cur_finds.get(path, [])
        if b is None:
            out["new"].append({"path": path, "language": p.get("language"),
                               "size_bytes": p.get("size_bytes") or 0})
            out["new_findings"] += now_f
            continue
        if p.get("security_scanned") and b.get("security_scanned"):
            was_keys = {_finding_key(f) for f in base_finds.get(path, [])}
            now_keys = {_finding_key(f) for f in now_f}
            out["new_findings"] += [f for f in now_f if _finding_key(f) not in was_keys]
            out["resolved_findings"] += [f for f in base_finds.get(path, []) if _finding_key(f) not in now_keys]
        elif now_f or base_finds.get(path):
            out["unchecked"].append(path)

        # --- project state
        if (p.get("git_head") != b.get("git_head")
                or p.get("git_dirty") != b.get("git_dirty")
                or p.get("content_mtime") != b.get("content_mtime")):
            out["changed"].append({"path": path, "now_dirty": p.get("git_dirty"),
                                   "was_head": b.get("git_head"), "now_head": p.get("git_head")})
        delta = (p.get("size_bytes") or 0) - (b.get("size_bytes") or 0)
        if delta:
            out["grown"].append({"path": path, "delta_bytes": delta,
                                 "size_bytes": p.get("size_bytes") or 0})

    for path, b in base.items():
        if path not in cur:
            out["removed"].append({"path": path, "language": b.get("language"),
                                   "size_bytes": b.get("size_bytes") or 0})

    out["new_findings"].sort(key=lambda f: (_SEV_RANK.get(f["severity"], 3), f["path"] or "", f["line"] or 0))
    out["resolved_findings"].sort(key=lambda f: (_SEV_RANK.get(f["severity"], 3), f["path"] or ""))
    out["new_bloat"].sort(key=lambda m: -(m["size_bytes"] or 0))
    out["grown"].sort(key=lambda g: -abs(g["delta_bytes"]))
    return out


def has_changes(d):
    """True if the diff carries anything worth showing."""
    return any(d[k] for k in ("new", "removed", "changed", "grown", "new_findings",
                              "resolved_findings", "new_bloat", "removed_bloat"))


def summarise_diff(d):
    """A one-line summary, e.g. '+3 new, -1 removed, 5 changed, 2 grew/shrank, 2 NEW security finding(s)'."""
    from mnemocetus import utils
    parts = []
    if d["new"]:
        parts.append(f"+{len(d['new'])} new")
    if d["removed"]:
        parts.append(f"-{len(d['removed'])} removed")
    if d["changed"]:
        parts.append(f"{len(d['changed'])} changed")
    if d["grown"]:
        parts.append(f"{len(d['grown'])} grew/shrank")
    if d.get("new_findings"):
        parts.append(f"{len(d['new_findings'])} NEW security finding(s)")
    if d.get("resolved_findings"):
        parts.append(f"{len(d['resolved_findings'])} resolved")
    if d.get("new_bloat"):
        parts.append(f"+{len(d['new_bloat'])} new bloat dir(s) "
                     f"({utils.human_size(sum(m['size_bytes'] or 0 for m in d['new_bloat']))})")
    return ", ".join(parts) or "no changes since the baseline"


def git_gc_recommendations(db, min_bytes=50 * 1024 * 1024):
    """
    Git repos whose .git object store is worth compacting with `git gc`, measured live (count-objects per
    repo -> computed on demand, so scans stay fast). Returns {items, total_reclaimable}, where each item is
    {path, reclaimable, total}. Only repos with an estimate >= min_bytes are listed, biggest first.
    """
    from mnemocetus import gitinfo
    items = []
    for p in _one_per_repo(db.all_projects()):  # nested projects share ONE .git -> measure (and count) it once
        size = gitinfo.git_dir_size(p["path"])
        if size and size["reclaimable_estimate"] >= min_bytes:
            items.append({"path": p["path"], "reclaimable": size["reclaimable_estimate"],
                          "total": size["total_bytes"]})
    items.sort(key=lambda it: it["reclaimable"], reverse=True)
    return {"items": items, "total_reclaimable": sum(it["reclaimable"] for it in items)}


def _one_per_repo(projects):
    """
    Collapse projects to one representative per git repository. Several scanned projects can live in the
    same repo (a monorepo's backend/ + frontend/), and dirty / ahead / last-commit / .git size are all
    REPO-wide facts -> without this, one repo is listed (and its gc estimate summed) once per sub-project.
    The representative is the shallowest project path; it carries 'projects' = how many it stands for.
    Rows without a stored git_root (DBs from before schema v8) fall back to their own path.
    """
    groups = {}
    for p in projects:
        if not (p.get("git_head") or p.get("git_branch")):
            continue  # not a git repo
        groups.setdefault(p.get("git_root") or p["path"], []).append(p)
    out = []
    for members in groups.values():
        rep_ = min(members, key=lambda m: (len(m["path"]), m["path"]))
        out.append({**rep_, "projects": len(members)})
    out.sort(key=lambda m: m["path"])
    return out


def at_risk_projects(db, stale_days=STALE_DAYS, now=None):
    """
    Projects whose local git work could be lost, from the stored git state:
      uncommitted (dirty) / unpushed (ahead of upstream) / stale (no commit in a while).
    Returns [{path, language, risks: [...]}], only for projects that carry a git signal.
    """
    now = time.time() if now is None else now
    out = []
    for p in _one_per_repo(db.all_projects()):  # one row per repo, not per nested project
        risks = []
        if p.get("git_dirty") is None:
            risks.append("unverified")  # git status failed / timed out at scan time -> can't prove it's clean
        elif p.get("git_dirty"):
            risks.append("uncommitted")
        if (p.get("git_ahead") or 0) > 0:
            risks.append("unpushed")
        last = p.get("git_last_commit")
        if last and (now - last) > stale_days * 86400:
            risks.append("stale")
        if risks:
            out.append({"path": p["path"], "language": p.get("language"), "risks": risks,
                        "projects": p["projects"]})
    return out
