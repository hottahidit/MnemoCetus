# Git awareness for MnemoCetus (v0.9) -> read each project's git state by shelling out to the installed
# `git` (the same pattern security.py uses for pip-audit / npm-audit), so there is no new dependency.
#
# Everything degrades gracefully: no git on PATH, not a repo, or an empty repo all return a safe shape
# rather than raising. This module is the engine behind:
#   - change detection ("has this project changed since last scan?" -> (head, dirty) fingerprint)
#   - the "what changed" diff and the at-risk flags (uncommitted / unpushed / no-remote / stale)
#   - `.git` bloat measurement (git count-objects) feeding the reclaimer's git-gc recommendation
#   - the archive-candidate gate (stale AND fully backed up -> safe to push-and-remove)
# It only ever READS; nothing here mutates a repository.

import os
import time
import subprocess

_TIMEOUT = 10
STALE_DAYS = 180  # default "unused" threshold: no commit in this many days


def _git(args, cwd, timeout=_TIMEOUT):
    """Run `git <args>` in cwd -> stripped stdout, or None on any failure (git missing / not a repo / non-zero)."""
    try:
        proc = subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip()


def git_available():
    """True if a `git` binary is on PATH."""
    return _git(["--version"], cwd=None) is not None


def status(path):
    """
    Read a project directory's git state.

    Returns a dict:
        {is_repo, root, is_root, head, branch, detached, dirty, modified, untracked,
         has_remote, has_upstream, ahead, behind, last_commit_ts}
    or {"is_repo": False} when the path isn't inside a repo (or git is unavailable).
    """
    if not path or not os.path.isdir(path):
        return {"is_repo": False}
    toplevel = _git(["rev-parse", "--show-toplevel"], path)
    if not toplevel:
        return {"is_repo": False}
    root = os.path.normpath(toplevel)
    info = {"is_repo": True, "root": root,
            "is_root": root == os.path.normpath(os.path.abspath(path))}

    info["head"] = _git(["rev-parse", "HEAD"], path)  # None for a repo with no commits yet
    branch = _git(["rev-parse", "--abbrev-ref", "HEAD"], path)
    info["detached"] = branch == "HEAD"
    info["branch"] = None if branch in (None, "HEAD") else branch

    porcelain = _git(["status", "--porcelain"], path)
    lines = porcelain.splitlines() if porcelain else []
    info["untracked"] = sum(1 for ln in lines if ln.startswith("??"))
    info["modified"] = len(lines) - info["untracked"]
    info["dirty"] = bool(lines)

    info["has_remote"] = bool(_git(["remote"], path))

    # "<behind><TAB><ahead>" relative to the tracked upstream; absent when no upstream is configured.
    ab = _git(["rev-list", "--left-right", "--count", "@{upstream}...HEAD"], path)
    parts = ab.split() if ab else []
    if len(parts) == 2 and all(p.lstrip("-").isdigit() for p in parts):
        info["behind"], info["ahead"] = int(parts[0]), int(parts[1])
        info["has_upstream"] = True
    else:
        info["behind"] = info["ahead"] = 0
        info["has_upstream"] = False

    ts = _git(["log", "-1", "--format=%ct"], path)
    info["last_commit_ts"] = int(ts) if ts and ts.isdigit() else None
    return info


def change_key(info):
    """A cheap fingerprint of a repo's state for change detection -> (head, dirty), or None for a non-repo."""
    if not info.get("is_repo"):
        return None
    return (info.get("head"), bool(info.get("dirty")))


def change_signature(head, dirty, content_mtime):
    """
    A stable per-project signature for incremental scans. None means "always re-scan":
      - a CLEAN git repo -> pinned to its HEAD commit (rock-solid unchanged signal)
      - a non-repo folder -> its newest file mtime
      - a DIRTY repo or an unknown state -> None (never skip; we can't cheaply prove it's unchanged)
    Works identically on live gitinfo.status() and on a stored DB row, so the two can be compared.
    """
    if head and not dirty:
        return ("git", head)
    if not head and content_mtime:
        return ("mtime", round(content_mtime, 2))
    return None


def is_stale(info, days=STALE_DAYS, now=None):
    """True if the last commit is older than `days` (an unknown timestamp is treated as NOT stale)."""
    ts = info.get("last_commit_ts")
    if not ts:
        return False
    now = time.time() if now is None else now
    return (now - ts) > days * 86400


def at_risk(info):
    """Reasons a repo's work could be lost, as short tags (empty list when it's safe)."""
    if not info.get("is_repo"):
        return []
    risks = []
    if info.get("dirty"):
        risks.append("uncommitted")
    if not info.get("has_remote"):
        risks.append("no-remote")               # never backed up anywhere
    elif info.get("has_upstream") and info.get("ahead", 0) > 0:
        risks.append("unpushed")
    return risks


def is_archivable(info, days=STALE_DAYS, now=None):
    """
    Recommendation gate: a STALE repo that looks fully backed up (clean, tracked upstream, nothing ahead)
    -> a candidate to push-to-private-then-remove. The actual delete flow re-verifies ALL branches/tags
    and the absence of stashes at execution time; this is only the advisory flag.
    """
    return bool(
        info.get("is_repo") and info.get("has_remote") and info.get("has_upstream")
        and not info.get("dirty") and info.get("untracked", 0) == 0
        and info.get("ahead", 0) == 0 and is_stale(info, days=days, now=now)
    )


def is_ignored(repo_dir, relpath):
    """True if `relpath` is gitignored inside the repo at repo_dir (False if it isn't, or it's not a repo)."""
    return _git(["check-ignore", "-q", relpath], repo_dir) is not None


def git_dir_size(path):
    """
    Measure the repo's object store via `git count-objects -v` (sizes reported in KiB).

    Returns {total_bytes, reclaimable_estimate, loose_objects} or None (not a repo / git absent).
    reclaimable_estimate ~= loose objects + garbage that a `git gc` would pack away -> a rough hint only.
    """
    out = _git(["count-objects", "-v"], path)
    if out is None:
        return None
    vals = {}
    for ln in out.splitlines():
        key, sep, val = ln.partition(":")
        if sep:
            vals[key.strip()] = val.strip()

    def kib(key):
        try:
            return int(vals.get(key, "0")) * 1024
        except ValueError:
            return 0

    return {
        "total_bytes": kib("size") + kib("size-pack") + kib("size-garbage"),
        "reclaimable_estimate": kib("size") + kib("size-garbage"),
        "loose_objects": int(vals.get("count", "0") or 0),
    }


def badge_from_row(row):
    """Render the CLI git badge from a STORED project row (git_branch / git_head / git_dirty / git_ahead)."""
    if not (row.get("git_branch") or row.get("git_head")):
        return ""
    name = row.get("git_branch") or (row.get("git_head") or "")[:7]
    parts = [f"⎇ {name}", "●" if row.get("git_dirty") else "✓"]
    if row.get("git_ahead") or 0:
        parts.append(f"↑{row['git_ahead']}")
    return " ".join(parts)


def badge(info):
    """A short git badge for CLI listings, e.g. '⎇ main ✓', '⎇ feat ●2 ↑3', or '' for a non-repo."""
    if not info.get("is_repo"):
        return ""
    name = info.get("branch") or ((info.get("head") or "")[:7] or "?")
    parts = [f"⎇ {name}"]
    if info.get("dirty"):
        parts.append(f"●{info.get('modified', 0) + info.get('untracked', 0)}")
    else:
        parts.append("✓")
    if info.get("ahead", 0):
        parts.append(f"↑{info['ahead']}")
    if info.get("behind", 0):
        parts.append(f"↓{info['behind']}")
    if not info.get("has_remote"):
        parts.append("(no remote)")
    return " ".join(parts)
