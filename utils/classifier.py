# Project classifier for MnemoCetus (v0.3 classification + v0.5 recognition - the classification half of "MnemoSort").
#
# Given a project directory, work out what it is: language, frameworks, category, a 0.0-1.0 confidence, and a composition breakdown.
# This is the recognition engine scanner.py's Scanner.detect() drives.
# Pure and import-safe (no file I/O at import), and it never reaches back into the scanner.

# IMPORTS
import os
import re
import json
try:
    import tomllib  # Python 3.11+; parses pyproject.toml (and could also parse Cargo.toml)
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None

# SETUP
PYTHON_SIGNALS = {
    "django": ("django", "backend"),
    "flask": ("flask", "backend", "templates"),
    "fastapi": ("fastapi", "backend"),
    "torch": ("pytorch", None),
    "tensorflow": ("tensorflow", None),
    "scikit-learn": ("scikit-learn", None),
    "click": ("click", "cli"),
    "typer": ("typer", "cli"),
    "ansible": ("ansible", "automation"),
    "fabric": ("fabric", "automation"),
    "invoke": ("invoke", "automation"),
    "celery": ("celery", "automation")
}
JS_SIGNALS = {
    "next": ("next.js", "frontend"),
    "nuxt": ("nuxt.js", "frontend"),
    "react": ("react", "frontend"),
    "vue": ("vue", "frontend"),
    "svelte": ("svelte", "frontend"),
    "@angular/core": ("angular", "frontend"),
    "express": ("express", "backend"),
    "koa": ("koa", "backend"),
    "@nestjs/core": ("nestjs", "backend"),
    "electron": ("electron", "desktop"),
    "gulp": ("gulp", "automation"),
    "grunt": ("grunt", "automation")
}
CODE_EXTENSIONS = {
    ".py": "python", ".js": "javascript", ".jsx": "javascript",
    ".ts": "javascript", ".tsx": "javascript", ".rs": "rust", ".go": "go",
    ".java": "java", ".rb": "ruby", ".php": "php", ".cs": "c#"
}

## -- CLASSIFICATION RESULT --------------------------------------------------------------- ##
def _result(language, frameworks, category, markers, confidence, metrics=None, dependencies=None, breakdown=None):
    """Build the canonical classification dict. Always returns a dict (never None)."""
    # dependencies may arrive as a {name: version spec} dict or a plain name iterable.
    if isinstance(dependencies, dict):
        specs = {k: (v or "") for k, v in dependencies.items()}
        names = sorted(dependencies)
    else:
        specs = {}
        names = sorted(dependencies) if dependencies else []
    return {
        "language": language,
        "frameworks": frameworks,
        "category": category,
        "markers": markers,
        "confidence": round(confidence, 2),
        "metrics": metrics or _empty_metrics(),     # size / file count / dep count
        "dependencies": names,                       # declared package names
        "dependency_specs": specs,                   # {name: version spec} (v0.5 dependency intelligence)
        "breakdown": breakdown or {"languages": {}, "categories": {}}  # composition shares
    }

def _unknown():
    return _result(None, [], None, [], 0.0)

def _empty_metrics():
    return {"file_count": 0, "size_bytes": 0, "dependency_count": 0}
## ---------------------------------------------------------------------------------------- ##

## -- MANIFEST READERS -------------------------------------------------------------------- ##
def _safe_read(path, limit=1_000_000):
    """Read a text file defensively (size-capped)."""
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            return f.read(limit)
    except OSError:
        return ""

def _load_json(path):
    try:
        data = json.loads(_safe_read(path))
        return data if isinstance(data, dict) else {}
    except ValueError:  # malformed JSON -> behave as "no data", so we don't crash the scan
        return {}

def _load_toml(path):
    if tomllib is None:
        return {}
    try:
        with open(path, "rb") as f:
            return tomllib.load(f)
    except (OSError, ValueError):  # tomllib.TOMLDecodeError subclasses ValueError
        return {}

def _dep_name(spec):
    """Reduce a requirement string (e.g. 'Django>=4.0; extra') to its bare package name."""
    return re.split(r"[<>=!~;[]", spec, maxsplit=1)[0].strip().lower()

def _dep_name_spec(spec):
    """Split a requirement string ('Django>=4.0,<5 ; python_version>3') into (bare name, version spec)."""
    spec = spec.split(";", 1)[0].strip()  # drop environment markers
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*(.*)$", spec)
    if not m:
        return _dep_name(spec), ""
    return m.group(1).lower(), m.group(2).strip()
## ---------------------------------------------------------------------------------------- ##

## -- DEPENDENCIES ------------------------------------------------------------------------ ##
def _python_dependencies(directory):
    """Collect declared dependency names + version specs from requirements.txt and pyproject.toml -> {name: spec}."""
    deps = {}
    req = os.path.join(directory, "requirements.txt")
    if os.path.exists(req):
        for line in _safe_read(req).splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                name, spec = _dep_name_spec(line)
                if name:
                    deps.setdefault(name, spec)
    data = _load_toml(os.path.join(directory, "pyproject.toml"))
    for entry in data.get("project", {}).get("dependencies", []) or []:
        name, spec = _dep_name_spec(entry)
        if name:
            deps.setdefault(name, spec)
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name, constraint in (poetry or {}).items():
        if name.lower() != "python":
            deps.setdefault(name.lower(), constraint if isinstance(constraint, str) else "")
    return deps

def _js_dependencies(directory):
    """Return the package.json dict and {name: version spec} for its (dev)dependencies."""
    data = _load_json(os.path.join(directory, "package.json"))
    names = {}
    for key in ("dependencies", "devDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            for k, v in section.items():
                names.setdefault(k.lower(), v if isinstance(v, str) else "")
    return data, names

def _go_dependencies(directory):
    """Return {module path: version} from go.mod (both single 'require x v' lines and require (...) blocks)."""
    deps = {}
    in_block = False
    for line in _safe_read(os.path.join(directory, "go.mod")).splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        if in_block:
            if line == ")":
                in_block = False
            else:
                parts = line.split()  # "example.com/m v1.2.3"
                deps.setdefault(parts[0], parts[1] if len(parts) > 1 else "")
        elif line.startswith("require ("):
            in_block = True
        elif line.startswith("require "):
            parts = line[len("require "):].split()  # "require example.com/m v1.2.3"
            if parts:
                deps.setdefault(parts[0], parts[1] if len(parts) > 1 else "")
    return deps

def _go_dependency_count(directory):
    """Count required modules in go.mod (kept for back-compat; delegates to _go_dependencies)."""
    return len(_go_dependencies(directory))
## ---------------------------------------------------------------------------------------- ##


## -- RECOGNITION (weighted confidence) --------------------------------------------------- ##
# How much each kind of evidence is worth when scoring a project's category.
W_MARKER = 5.0   # a definitive marker file/folder (manage.py, next.config, src/main.rs, ...)
W_DEP    = 3.0   # a parsed dependency that implies a category (react -> frontend, ...)
W_LAYOUT = 2.0   # a telltale directory (app.py beside templates/ or static/, ...)
W_CENSUS = 3.0   # the file-type census, scaled by the markup/style share of the tree

# Extensions we count for the language census + breakdown (code + markup/style).
LANG_EXTENSIONS = {
    **CODE_EXTENSIONS,
    ".html": "html", ".htm": "html",
    ".css": "css", ".scss": "css", ".sass": "css", ".less": "css",
    ".vue": "vue", ".svelte": "svelte",
}
FRONTEND_LANGS = {"html", "css", "vue", "svelte"}  # markup/style => frontend evidence
FRONTEND_CENSUS_FLOOR = 0.30  # markup must be >=30% of files before it gets a frontend vote
FULL_STACK_FLOOR = 0.25       # each side needs >=25% of the category weight to call "full stack"

def _census(paths):
    """Count the meaningful code/markup files by language -> {language: count}."""
    counts = {}
    for p in paths:
        lang = LANG_EXTENSIONS.get(os.path.splitext(p)[1].lower())
        if lang:
            counts[lang] = counts.get(lang, 0) + 1
    return counts

def _normalise(scores):
    """Turn a {key: weight} dict into a sorted {key: share} that sums to ~1.0 (or {} if empty)."""
    total = sum(scores.values())
    if total <= 0:
        return {}
    return {k: round(v / total, 3) for k, v in sorted(scores.items(), key=lambda kv: kv[1], reverse=True)}

def _resolve_scored_category(cat_scores):
    """
    Pick ONE category out of the weighted votes.

    'full stack' when frontend AND backend are both present and each carries a real share of the weight; otherwise the highest-scoring category, or None if nothing voted.
    """
    if not cat_scores:
        return None
    total = sum(cat_scores.values())
    fe, be = cat_scores.get("frontend", 0.0), cat_scores.get("backend", 0.0)
    if fe > 0 and be > 0 and min(fe, be) >= FULL_STACK_FLOOR * total:
        return "full stack"
    return max(cat_scores, key=cat_scores.get)

def _recognise(language, cat_votes, has_strong_marker, census):
    """
    Blend marker/dependency/layout votes with the file-type census into a category, a 0.0-1.0 confidence, and a composition breakdown.

    Args:
        language (str | None): the primary language already chosen from markers (None -> unknown).
        cat_votes (list): (category, weight) pairs cast by markers / deps / layout.
        has_strong_marker (bool): whether a real manifest/marker backed the language.
        census (dict): {language: count} for the tree (drives the breakdown + frontend share).

    Returns:
        (category, confidence, breakdown): the label, how sure we are, and the shares.
    """
    total_files = sum(census.values())

    cat_scores = {}
    for cat, weight in cat_votes:
        if cat:
            cat_scores[cat] = cat_scores.get(cat, 0.0) + weight

    # The census votes frontend only when markup/style genuinely dominates the tree -> this is what stops a pile of HTML/CSS from being mislabelled by one tiny backend file.
    if total_files:
        frontend_share = sum(c for lang, c in census.items() if lang in FRONTEND_LANGS) / total_files
        if frontend_share >= FRONTEND_CENSUS_FLOOR:
            cat_scores["frontend"] = cat_scores.get("frontend", 0.0) + frontend_share * W_CENSUS

    category = _resolve_scored_category(cat_scores)

    if language is None:
        confidence = 0.0
    elif not cat_scores:
        confidence = 0.7 if has_strong_marker else 0.5  # known language, but nothing voted a category
    else:
        share = max(cat_scores.values()) / sum(cat_scores.values())
        confidence = 0.45 + 0.45 * share + (0.08 if has_strong_marker else 0.0)
    confidence = max(0.0, min(confidence, 0.98))

    breakdown = {"languages": _normalise(census), "categories": _normalise(cat_scores)}
    return category, round(confidence, 2), breakdown
## ---------------------------------------------------------------------------------------- ##
