# Security scanning for MnemoCetus (v0.5 - the "MnemoScan" detection half).
#
# Two layers, both non-destructive: a self-contained regex SECRET scanner (no external tools), and an OPTIONAL dependency-vulnerability audit that shells out to pip-audit / npm audit only when they're installed.
# The audit degrades gracefully -> if a tool isn't on PATH it simply contributes nothing, so a plain install still works.

import os
import re
import json
import stat
import shutil
import subprocess

from mnemocetus.scanner import _is_excluded  # reuse the scan's exclusion test so we skip the same junk (and never descend into .git)

# Well-known secret shapes, kept deliberately specific to keep false positives down.
# Each entry: rule name -> (compiled pattern, severity).
# The generic assignment rule is the loosest, so it is only "low".
SECRET_RULES = [
    ("AWS access key id",        re.compile(r"AKIA[0-9A-Z]{16}"), "high"),
    ("GitHub token",             re.compile(r"gh[pousr]_[0-9A-Za-z]{36,}"), "high"),
    ("Slack token",              re.compile(r"xox[baprs]-[0-9A-Za-z-]{10,}"), "high"),
    ("Google API key",           re.compile(r"AIza[0-9A-Za-z_\-]{35}"), "high"),
    ("Stripe secret key",        re.compile(r"sk_live_[0-9A-Za-z]{16,}"), "high"),
    ("Private key block",        re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----"), "high"),
    ("JSON web token",           re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{6,}"), "medium"),
    ("Generic secret assignment", re.compile(r"(?i)(?:api[_-]?key|secret|passwd|password|token)\s*[:=]\s*['\"][0-9A-Za-z\-_./+=]{12,}['\"]"), "low"),
]

# Binary / opaque files we never bother reading (no text secrets to find, and we don't want the noise).
BINARY_EXTS = {
    ".png", ".jpg", ".jpeg", ".gif", ".ico", ".pdf", ".zip", ".gz", ".tar", ".tgz", ".bz2",
    ".exe", ".dll", ".so", ".dylib", ".o", ".a", ".class", ".jar", ".pyc", ".pyo",
    ".woff", ".woff2", ".ttf", ".otf", ".eot", ".mp3", ".mp4", ".wav", ".mov", ".avi",
    ".db", ".sqlite", ".sqlite3", ".bin", ".dat", ".wasm",
}

MAX_FILE_BYTES = 1_000_000   # skip anything bigger -> a real secret sits in small config/source files
MAX_LINE_CHARS = 4_000       # truncate very long (e.g. minified) lines before matching, to stay fast

# Config files whose EXPOSURE (present in a repo but not gitignored, so committable) is a leak risk.
ENV_FILENAMES = (".env", ".env.local", ".env.development", ".env.production", ".env.staging", ".env.prod")


def check_env_exposure(directory, is_repo):
    """
    Flag root-level .env files a git repo is NOT ignoring -> they risk being committed with their secrets.

    Returns MnemoScan findings (same shape as scan_secrets); empty for non-repos (the risk is git-specific).
    """
    if not is_repo:
        return []
    from mnemocetus import gitinfo  # lazy -> keep the git layer off security.py's import path
    findings = []
    for name in ENV_FILENAMES:
        path = os.path.join(directory, name)
        if os.path.isfile(path) and not gitinfo.is_ignored(directory, name):
            findings.append({
                "kind": "config", "rule": "exposed dotenv", "severity": "high",
                "path": path, "line": 0,
                "detail": f"{name} is not gitignored -> at risk of being committed with its secrets",
            })
    return findings


def check_ignore_hygiene(directory, is_repo, marks):
    """
    Flag regenerable bloat a git repo ISN'T ignoring -> node_modules / venv / build output at risk of
    being committed (and, when there's bloat but no .gitignore at all, the missing file itself).

    'marks' are the reclaimable directories the scan already sized (see cleaner._collect_marks), so this
    reuses that work instead of walking again. Returns MnemoScan findings; empty for non-repos.
    """
    if not is_repo or not marks:
        return []
    from mnemocetus import gitinfo  # lazy -> keep the git layer off security.py's import path
    findings = []
    unignored = []
    for m in marks:
        mp = m.get("path")
        if not mp:
            continue
        rel = os.path.relpath(mp, directory)
        if rel.startswith(".."):  # bloat resolved outside this project dir -> not ours to judge
            continue
        if not gitinfo.is_ignored(directory, rel):
            unignored.append(m)
            findings.append({
                "kind": "config", "rule": "un-ignored bloat", "severity": "medium",
                "path": mp, "line": 0,
                "detail": f"{m.get('name') or rel} is regenerable but not gitignored -> risks being committed",
            })
    # If there's un-ignored bloat AND no .gitignore exists at all, name the root cause too.
    if unignored and not os.path.isfile(os.path.join(directory, ".gitignore")):
        findings.append({
            "kind": "config", "rule": "missing gitignore", "severity": "low",
            "path": os.path.join(directory, ".gitignore"), "line": 0,
            "detail": "no .gitignore -> regenerable bloat (and secrets) can slip into commits",
        })
    return findings


def _mask(secret):
    """Redact a matched secret for storage/display -> keep the first 4 chars, star the rest (capped)."""
    secret = secret.strip()
    if len(secret) <= 4:
        return "*" * len(secret)
    return secret[:4] + "*" * min(len(secret) - 4, 20)

def _scan_file(path):
    """Scan one text file line by line, returning a finding dict per secret match (the value masked)."""
    out = []
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as fh:
            for lineno, line in enumerate(fh, 1):
                if len(line) > MAX_LINE_CHARS:
                    line = line[:MAX_LINE_CHARS]
                for rule, pattern, severity in SECRET_RULES:
                    m = pattern.search(line)
                    if m:
                        out.append({
                            "kind": "secret", "rule": rule, "severity": severity,
                            "path": path, "line": lineno, "detail": _mask(m.group(0)),
                        })
    except OSError:
        pass
    return out

def scan_secrets(directory, name_rules, path_rules, skip=()):
    """
    Walk 'directory' and flag likely hard-coded secrets (API keys, tokens, private keys) in its text files.

    We prune the same excluded/hidden DIRS the scan skips (so we never read .git), but we DO read hidden FILES like .env, since that is exactly where secrets tend to hide.
    Binary and oversized files are skipped.

    Args:
        directory (str): the project dir to inspect.
        name_rules (set): compiled basename exclude rules.
        path_rules (set): compiled path exclude rules.
        skip (iterable): directories NOT to descend into -> nested child projects, scanned (and reported)
            on their own, so a parent doesn't duplicate every child's findings.

    Returns:
        list[dict]: one {kind, rule, severity, path, line, detail} per match (detail is the masked secret).
    """
    skip = {os.path.normpath(p) for p in skip}
    findings = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs
                   if not d.startswith('.') and not _is_excluded(os.path.join(root, d), name_rules, path_rules)
                   and not (skip and os.path.normpath(os.path.join(root, d)) in skip)]
        for f in files:
            path = os.path.normpath(os.path.join(root, f))
            if _is_excluded(path, name_rules, path_rules):
                continue
            if os.path.splitext(f)[1].lower() in BINARY_EXTS:
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            # Only ever open regular files -> reading a socket/FIFO (e.g. a Chrome profile's
            # SingletonSocket) could block a worker thread forever; skip them and oversized files.
            if not stat.S_ISREG(st.st_mode) or st.st_size > MAX_FILE_BYTES:
                continue
            findings.extend(_scan_file(path))
    return findings


class HistoryScanError(RuntimeError):
    """The history scan could not finish (git failed or timed out) -> the result is UNKNOWN, not clean."""


def scan_git_history(directory, timeout=300):
    """
    Scan a repo's FULL git history for hard-coded secrets -> secrets that were committed and later
    "removed" still live in the history and are the real leak. On-demand (heavier than the working-tree
    scan), read-only, and shells out to git.

    Returns [] when git is absent or 'directory' isn't a repo (nothing to scan). Raises HistoryScanError
    when git fails or the walk exceeds 'timeout' seconds -> the caller must NOT show that as "no secrets".

    Walks every blob reachable from all refs (`git rev-list --objects --all`) and streams their contents
    through one `git cat-file --batch`, one object at a time -> memory stays bounded by MAX_FILE_BYTES no
    matter how big the repo is (oversized blobs are read past in chunks, never held). Binary/oversized
    blobs are skipped and findings are deduped by (rule, masked value, path), so a secret living across
    many commits is one finding. Findings use kind 'secret-history'; detail carries the masked value +
    the in-history path.
    """
    import time
    import tempfile
    from mnemocetus import gitinfo  # lazy -> keep the git layer off security.py's import path
    if not gitinfo.git_available():
        return []
    if gitinfo._git(["rev-parse", "--git-dir"], directory) is None:
        return []  # not a repository
    deadline = time.monotonic() + timeout
    listing = gitinfo._git(["rev-list", "--objects", "--all"], directory, timeout=timeout)
    if listing is None:
        raise HistoryScanError("`git rev-list --objects --all` failed or timed out")
    # rev-list --objects lines are "<sha>" (commits) or "<sha> <path>" (blobs + subtrees). Keep the ones
    # that carry a path (candidate files); cat-file --batch tells us which are actually blobs.
    sha_path, order = {}, []
    for ln in listing.splitlines():
        sha, sep, path = ln.partition(" ")
        if sep and path and sha not in sha_path:
            sha_path[sha] = path
            order.append(sha)
    if not order:
        return []

    findings, seen = [], set()

    def _check(path, content):
        for lineno, line in enumerate(content.decode("utf-8", "ignore").splitlines(), 1):
            if len(line) > MAX_LINE_CHARS:
                line = line[:MAX_LINE_CHARS]
            for rule, pattern, severity in SECRET_RULES:
                m = pattern.search(line)
                if m:
                    masked = _mask(m.group(0))
                    key = (rule, masked, path)
                    if key in seen:
                        continue
                    seen.add(key)
                    findings.append({
                        "kind": "secret-history", "rule": rule, "severity": severity,
                        "path": os.path.join(directory, path), "line": lineno,
                        "detail": f"{masked} (in git history: {path})",
                    })

    # Feed the sha list from a temp FILE (not a pipe we also write to) -> no stdin/stdout deadlock while
    # we stream the output.
    with tempfile.TemporaryFile() as shas:
        shas.write(("\n".join(order) + "\n").encode())
        shas.seek(0)
        try:
            proc = subprocess.Popen(gitinfo.git_command(["cat-file", "--batch"]), cwd=directory,
                                    stdin=shas, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                    env=gitinfo.git_env())
        except OSError as e:
            raise HistoryScanError(f"could not run git cat-file: {e}") from e
        out = proc.stdout
        try:
            for _ in order:
                if time.monotonic() > deadline:
                    raise HistoryScanError(f"timed out after {timeout}s")
                header = out.readline()
                if not header:
                    raise HistoryScanError("git cat-file ended early")
                parts = header.decode("utf-8", "ignore").split()
                if len(parts) == 2 and parts[1] == "missing":
                    continue  # object gone -> no content follows
                if len(parts) != 3 or not parts[2].isdigit():
                    raise HistoryScanError("malformed git cat-file output")
                sha, otype, size = parts[0], parts[1], int(parts[2])
                path = sha_path.get(sha, "")
                wanted = (otype == "blob" and size <= MAX_FILE_BYTES
                          and os.path.splitext(path)[1].lower() not in BINARY_EXTS)
                if wanted:
                    content = out.read(size)
                else:
                    remaining = size  # stream past it in chunks -> never hold a huge blob in memory
                    while remaining:
                        chunk = out.read(min(remaining, 1 << 20))
                        if not chunk:
                            break
                        remaining -= len(chunk)
                    content = None
                out.read(1)  # the newline after each object's content
                if content is not None:
                    _check(path, content)
        finally:
            if proc.poll() is None:
                proc.kill()
            proc.wait()
            out.close()
    return findings


def _run(cmd, cwd):
    """Run an external audit tool, returning its stdout, or None if the tool is missing or it errors out."""
    if not shutil.which(cmd[0]):
        return None
    try:
        proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=120)
        return proc.stdout or ""
    except (OSError, subprocess.SubprocessError):
        return None

def _pip_audit(directory):
    """Parse a pip-audit JSON run into vuln findings (best-effort; tolerant of its output shapes)."""
    out = _run(["pip-audit", "-f", "json"], directory)
    if not out:
        return []
    try:
        data = json.loads(out)
    except ValueError:
        return []
    deps = data.get("dependencies", []) if isinstance(data, dict) else data
    findings = []
    for dep in deps or []:
        name = dep.get("name", "?")
        for v in dep.get("vulns", []) or []:
            findings.append({
                "kind": "vuln", "rule": f"{name} {v.get('id', '')}".strip(), "severity": "high",
                "path": os.path.join(directory, "requirements.txt"), "line": 0,
                "detail": (v.get("description") or "")[:200],
            })
    return findings

def _npm_audit(directory):
    """Parse an 'npm audit --json' run into vuln findings (best-effort; tolerant of its output shapes)."""
    out = _run(["npm", "audit", "--json"], directory)
    if not out:
        return []
    try:
        data = json.loads(out)
    except ValueError:
        return []
    findings = []
    for name, info in (data.get("vulnerabilities") or {}).items():
        findings.append({
            "kind": "vuln", "rule": name, "severity": info.get("severity", "unknown"),
            "path": os.path.join(directory, "package.json"), "line": 0,
            "detail": f"{name}: {info.get('severity', 'unknown')} severity (npm audit)",
        })
    return findings

def audit_dependencies(directory):
    """
    OPTIONAL dependency-vulnerability audit -> shells out to pip-audit / npm audit when they're installed.

    Never raises and never requires the tools: if neither is on PATH (or a run fails), it just returns [].

    Returns:
        list[dict]: {kind:'vuln', rule, severity, path, line, detail} findings, possibly empty.
    """
    findings = []
    if os.path.exists(os.path.join(directory, "requirements.txt")) or \
       os.path.exists(os.path.join(directory, "pyproject.toml")):
        findings.extend(_pip_audit(directory))
    if os.path.exists(os.path.join(directory, "package.json")):
        findings.extend(_npm_audit(directory))
    return findings
