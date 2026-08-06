# Workspace reclaimer for MnemoCetus (the EXECUTION half of "MnemoClean").
#
# Unlike the rest of MnemoCetus, this module actually changes the disk: it deletes reclaimable directories (venv / cache / build / node_modules) and can build one shared "uni-venv".
# It is only ever reached from an explicit, confirmed CLI flow -> nothing here runs on its own, and every delete is guarded so it can only touch curated bloat dirs inside the scanned workspace.

import os
import sys
import shutil
import subprocess

from cleaner import RECLAIMABLE_MARKERS  # the curated set of dir names we are ever willing to delete


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
    if real != root and not real.startswith(root + os.sep):
        return False, "resolves outside the scanned workspace"
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
    try:
        subprocess.run([sys.executable, "-m", "venv", venv_path],
                       check=True, capture_output=True, text=True, timeout=300)
    except (OSError, subprocess.SubprocessError) as e:
        return {"created": False, "path": venv_path, "installed": 0, "failed": [], "error": str(e)}

    deps = sorted({d for d in dependencies if d and d.lower() != "python"})
    if not deps:
        return {"created": True, "path": venv_path, "installed": 0, "failed": [], "error": None}

    pip = os.path.join(venv_path, "bin", "pip")
    if not os.path.exists(pip):  # Windows layout
        pip = os.path.join(venv_path, "Scripts", "pip.exe")
    try:
        proc = subprocess.run([pip, "install", *deps], capture_output=True, text=True, timeout=1800)
    except (OSError, subprocess.SubprocessError) as e:
        return {"created": True, "path": venv_path, "installed": 0, "failed": deps, "error": str(e)}
    if proc.returncode == 0:
        return {"created": True, "path": venv_path, "installed": len(deps), "failed": [], "error": None}
    # pip resolves the whole set at once, so a conflict fails the batch -> report it, the venv still exists.
    return {"created": True, "path": venv_path, "installed": 0, "failed": deps, "error": (proc.stderr or "").strip()[-500:]}
