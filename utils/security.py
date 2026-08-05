# Security scanning for MnemoCetus (v0.5 - the "MnemoScan" detection half).
#
# Two layers, both non-destructive: a self-contained regex SECRET scanner (no external tools), and an OPTIONAL dependency-vulnerability audit that shells out to pip-audit / npm audit only when they're installed.
# The audit degrades gracefully -> if a tool isn't on PATH it simply contributes nothing, so a plain install still works.

import os
import re
import json
import shutil
import subprocess

from scanner import _is_excluded  # reuse the scan's exclusion test so we skip the same junk (and never descend into .git)

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

def scan_secrets(directory, name_rules, path_rules):
    """
    Walk 'directory' and flag likely hard-coded secrets (API keys, tokens, private keys) in its text files.

    We prune the same excluded/hidden DIRS the scan skips (so we never read .git), but we DO read hidden FILES like .env, since that is exactly where secrets tend to hide.
    Binary and oversized files are skipped.

    Args:
        directory (str): the project dir to inspect.
        name_rules (set): compiled basename exclude rules.
        path_rules (set): compiled path exclude rules.

    Returns:
        list[dict]: one {kind, rule, severity, path, line, detail} per match (detail is the masked secret).
    """
    findings = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs
                   if not d.startswith('.') and not _is_excluded(os.path.join(root, d), name_rules, path_rules)]
        for f in files:
            path = os.path.normpath(os.path.join(root, f))
            if _is_excluded(path, name_rules, path_rules):
                continue
            if os.path.splitext(f)[1].lower() in BINARY_EXTS:
                continue
            try:
                if os.path.getsize(path) > MAX_FILE_BYTES:
                    continue
            except OSError:
                continue
            findings.extend(_scan_file(path))
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
