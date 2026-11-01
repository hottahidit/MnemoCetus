# Workspace reclaimer for MnemoCetus (the EXECUTION half of "MnemoClean").
#
# Unlike the rest of MnemoCetus, this module actually changes the disk: it deletes reclaimable directories (venv / cache / build / node_modules) and can build one shared "uni-venv".
# It is only ever reached from an explicit, confirmed CLI flow -> nothing here runs on its own, and every delete is guarded so it can only touch curated bloat dirs inside the scanned workspace.

import os
import sys
import shutil
import re
import subprocess

from cleaner import RECLAIMABLE_MARKERS  # the curated set of dir names we are ever willing to delete

# Marker names that are ALSO common names for real, hand-written content (a committed dist/ for a GitHub
# Action, electron-builder's build/ icons, a Maven-less target/ folder ...). These are only treated as
# regenerable when a sibling file proves which tool produces them.
_AMBIGUOUS_MARKERS = {
    "target": ("Cargo.toml", "pom.xml", "build.sbt", "build.gradle", "build.gradle.kts", "project.clj"),
    "vendor": ("go.mod", "composer.json", "Gemfile"),
    "dist":   ("package.json", "pyproject.toml", "setup.py", "setup.cfg", "Cargo.toml", "vite.config.js",
               "vite.config.ts", "webpack.config.js", "rollup.config.js", "tsconfig.json"),
    "build":  ("package.json", "pyproject.toml", "setup.py", "setup.cfg", "CMakeLists.txt", "Makefile",
               "meson.build", "build.gradle", "build.gradle.kts", "pubspec.yaml"),
}


_PEP508_NAME = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9._-]*[A-Za-z0-9])?$")


def _contains_git_repo(path):
    """True if a .git (dir or worktree file) lives anywhere under 'path' -> e.g. an edited clone in vendor/."""
    for root, dirs, files in os.walk(path):  # os.walk does not follow symlinked dirs by default
        if ".git" in dirs or ".git" in files:
            return True
    return False


def _safe_to_delete(path, workspace_root):
    """
    Guard a single delete before it happens.

    The path must be a real directory, one of the curated reclaimable markers, NOT a symlink, and physically inside the scanned workspace -> anything else is refused, so a stray symlink or a bad path can never lead a delete out of the tree.

    Args:
        path (str): the directory we're about to remove.
        workspace_root (str): the scanned root; nothing outside it may be touched.

    Returns:
        (ok, reason): ok is False (with a human reason) when the path fails any check.
    """
    if not path or not os.path.isdir(path):
        return False, "not a directory"
    if os.path.islink(path):
        return False, "is a symlink (refusing to follow it)"
    if os.path.basename(os.path.normpath(path)) not in RECLAIMABLE_MARKERS:
        return False, "not a recognised reclaimable directory"
    real = os.path.realpath(path)
    root = os.path.realpath(workspace_root)
    if real == root:
        # Refuse the scanned root itself -> e.g. a workspace literally named 'node_modules' would otherwise pass the marker check and delete the whole tree.
        return False, "is the workspace root itself (refusing to delete it)"
    if not real.startswith(root + os.sep):
        return False, "resolves outside the scanned workspace"
    # The NAME says "bloat"; now check the CONTENTS agree before an irreversible rmtree.
    name = os.path.basename(real)
    needs = _AMBIGUOUS_MARKERS.get(name)
    if needs and not any(os.path.exists(os.path.join(os.path.dirname(real), f)) for f in needs):
        return False, f"'{name}/' has no build manifest beside it (may be hand-written content)"
    import gitinfo  # local import -> the git layer stays optional
    if gitinfo.git_available():
        tracked = gitinfo.tracked_files_under(real)
        if tracked:
            return False, f"git tracks {tracked} file(s) in it (committed content, not regenerable bloat)"
        if tracked is None and gitinfo._git(["rev-parse", "--is-inside-work-tree"], os.path.dirname(real)) == "true":
            return False, "inside a git repo but its tracked files couldn't be checked (git failed / timed out)"
    if _contains_git_repo(real):
        return False, "contains a nested git repository (local commits could be lost)"
    return True, ""


def execute_reclaim(items, workspace_root):
    """
    Delete the given reclaimable directories, each guarded by _safe_to_delete first.

    Args:
        items (iterable): dicts carrying at least 'path' and 'size_bytes'.
        workspace_root (str): the scanned root; nothing outside it is touched.

    Returns:
        dict: {deleted: [path,...], freed_bytes: int, skipped: [(path, reason),...], errors: [(path, msg),...]}
    """
    deleted, skipped, errors, freed = [], [], [], 0
    for it in items:
        path = it.get("path")
        ok, reason = _safe_to_delete(path, workspace_root)
        if not ok:
            skipped.append((path, reason))
            continue
        try:
            shutil.rmtree(path)
            deleted.append(path)
            freed += it.get("size_bytes", 0)
        except OSError as e:
            errors.append((path, str(e)))
    return {"deleted": deleted, "freed_bytes": freed, "skipped": skipped, "errors": errors}


def create_uni_venv(venv_path, dependencies=()):
    """
    Create one shared virtualenv at 'venv_path' and pip-install the given dependency names into it.

    Deps are installed by bare name (latest resolvable version) -> a fresh shared env, not a reproduction of any single project's pins. The caller is expected to have already warned about hard version conflicts.

    Args:
        venv_path (str): where the shared venv should live.
        dependencies (iterable): package names to install ('python' is ignored).

    Returns:
        dict: {created: bool, path: str, installed: int, failed: [name,...], error: str|None}
    """
    if os.path.isdir(venv_path) and os.listdir(venv_path):
        # Never build over an existing non-empty directory -> refuse rather than risk clobbering a real venv or project.
        return {"created": False, "path": venv_path, "installed": 0, "failed": [],
                "error": "target already exists and is not empty"}
    try:
        subprocess.run([sys.executable, "-m", "venv", venv_path],
                       check=True, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.SubprocessError) as e:
        return {"created": False, "path": venv_path, "installed": 0, "failed": [], "error": str(e)}

    # Dep names come from scanned (untrusted) manifests -> only pass valid PEP 508 project names to pip, so a
    # line like '-i https://evil/simple' or 'git+https://...' can never become a pip option or source.
    names = {d.strip() for d in dependencies if d and d.strip().lower() != "python"}
    deps = sorted(d for d in names if _PEP508_NAME.match(d))
    rejected = sorted(names - set(deps))
    if not deps:
        return {"created": True, "path": venv_path, "installed": 0, "failed": rejected,
                "error": "skipped invalid package names" if rejected else None}

    pip = os.path.join(venv_path, "bin", "pip")
    if not os.path.exists(pip):  # Windows layout
        pip = os.path.join(venv_path, "Scripts", "pip.exe")
    try:
        proc = subprocess.run([pip, "install", "--", *deps], capture_output=True, text=True, timeout=1800)
    except (OSError, subprocess.SubprocessError) as e:
        return {"created": True, "path": venv_path, "installed": 0, "failed": deps, "error": str(e)}
    if proc.returncode == 0:
        return {"created": True, "path": venv_path, "installed": len(deps), "failed": rejected,
                "error": f"skipped invalid package names: {', '.join(rejected)}" if rejected else None}
    # pip resolves the whole set at once, so a conflict fails the batch -> report it, the venv still exists.
    return {"created": True, "path": venv_path, "installed": 0, "failed": deps + rejected, "error": (proc.stderr or "").strip()[-500:]}


def run_git_gc(repo_paths, aggressive=False):
    """
    Run `git gc` on each repo to compact + prune its .git object store, reclaiming disk WITHOUT touching
    reachable history (branches/tags/commits are safe). aggressive=True adds --prune=now, which also drops
    the reflog grace window -> maximum reclaim, but genuinely-dangling commits become unrecoverable.

    Returns {ran: [path,...], freed_bytes: int, failed: [(path, msg),...]}.
    """
    from gitinfo import git_dir_size, git_command, git_env  # local import -> git layer stays optional
    cmd = git_command(["gc"] + (["--prune=now"] if aggressive else []))
    ran, failed, freed = [], [], 0
    for path in repo_paths:
        before = git_dir_size(path)
        try:
            proc = subprocess.run(cmd, cwd=path, capture_output=True, text=True, timeout=600,
                                  stdin=subprocess.DEVNULL, env=git_env())
        except (OSError, subprocess.SubprocessError) as e:
            failed.append((path, str(e)))
            continue
        if proc.returncode != 0:
            failed.append((path, (proc.stderr or "").strip()[-300:]))
            continue
        after = git_dir_size(path)
        if before and after:
            freed += max(0, before["total_bytes"] - after["total_bytes"])
        ran.append(path)
    return {"ran": ran, "freed_bytes": freed, "failed": failed}
