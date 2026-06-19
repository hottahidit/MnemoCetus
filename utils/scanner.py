# File scanner for MnemoCetus (v0.2 scanning + v0.3 classification - the "MnemoSort" engine).
#
# This is the discovery half of the project;
# it walks a workspace, filters out the junk (node_modules, venv, build artifacts...), and works out what kind of project each dir is.
# v0.4 folds the stateful bits (exclude config + classification cache) into a Scanner class; the original module-level functions stay on as thin shims.

# IMPORTS
from rich import print
from rich.columns import Columns
from rich.panel import Panel
import os
import re
import json
try:
    import tomllib  # Python 3.11+; parses pyproject.toml (and could also parse Cargo.toml)
except ModuleNotFoundError:  # pragma: no cover
    tomllib = None

# SETUP
# The exclude list is loaded lazily by Scanner (see _load_exclude_list) so importing this module does no file I/O.
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

# FUNCTIONS
def _load_exclude_list():
    """
    Read the exclude list off disk -> prefer the user's custom_exclude_list.txt, else fall back to the shipped default_exclude_list.txt.

    Returns:
        list: the raw lines (Scanner compiles them into rules). This is the only file I/O, and it runs when a Scanner is built, not at import.
    """
    try:
        with open('utils/exclude_list/custom_exclude_list.txt', 'r') as f:
            return f.read().splitlines()
    except FileNotFoundError:
        print("Custom exclude list not found, proceeding without it. (If it exists, name your custom list 'custom_exclude_list.txt' and place it in the 'exclude_list' folder to use it.)")
        with open('utils/exclude_list/default_exclude_list.txt', 'r') as f:
            return f.read().splitlines()

def compile_exclude_rules(exclude_list):
    """
    Takes the raw exclude list and splits it into two buckets, like gitignore does.

    Args:
        exclude_list (list): the folders to ignore, from default_ or custom_exclude_list.

    Returns:
        (name_rules, path_rules): bare names (like 'node_modules') match that name anywhere in the tree; anything with a slash matches that exact path or whatever lives under it.
    """
    name_rules = set()
    path_rules = set()
    for entry in exclude_list:
        entry = entry.strip()
        if not entry or entry.startswith('#'): # ignore empty or commented-out lines
            continue
        entry = entry.rstrip('/\\')  # trailing slashes are cosmetic; remove them
        if os.sep in entry or (os.altsep and os.altsep in entry):
            path_rules.add(os.path.normpath(entry))  # if it has a separator -> treat it as a path
        else:
            name_rules.add(entry)  # bare name -> match this basename anywhere
    return name_rules, path_rules

def _is_excluded(path, name_rules, path_rules):
    """
    Quick check -> does this path pass the filters?

    Args:
        path (str): the path we're testing.
        name_rules (set): basenames to kill anywhere in the tree.
        path_rules (set): exact paths (or parent paths) to kill.

    Returns:
        bool: True if it's excluded, False if it survives.
    """
    norm = os.path.normpath(path)
    if os.path.basename(norm) in name_rules:  # e.g. any '../node_modules'
        return True
    if norm in path_rules:  # exact path match
        return True
    return any(norm.startswith(p + os.sep) for p in path_rules)  # anything under an excluded path

## -- DIRECTORY MGMT ---------------------------------------------------------------------- ##
def _result(language, frameworks, category, markers, confidence, metrics=None, dependencies=None):
    """Build the canonical classification dict. Always returns a dict (never None)."""
    return {
        "language": language,
        "frameworks": frameworks,
        "category": category,
        "markers": markers,
        "confidence": round(confidence, 2),
        "metrics": metrics or _empty_metrics(),     # size / file count / dep count
        "dependencies": sorted(dependencies) if dependencies else []  # declared package names
    }

def _unknown():
    return _result(None, [], None, [], 0.0)

def _empty_metrics():
    return {"file_count": 0, "size_bytes": 0, "dependency_count": 0}

def _directory_metrics(directory, name_rules, path_rules, dependency_count=0, file_paths=None):
    """
    Tallies the project's size -> how many files, how many bytes, how many declared deps.

    Args:
        directory (str): the project dir we're measuring.
        name_rules (set): basename exclude rules (already compiled by the caller).
        path_rules (set): path exclude rules (already compiled by the caller).
        dependency_count (int): deps the caller already parsed (so we don't re-read manifests).
        file_paths (list): optional pre-scanned paths -> if given we just total the ones under `directory` instead of walking the tree again.

    Returns:
        dict: {"file_count", "size_bytes", "dependency_count"} (excludes/hidden stuff skipped).
    """
    file_count = 0
    size_bytes = 0

    if file_paths is not None:
        # Reuse an existing scan -> keep only the paths that sit under this directory.
        base = os.path.normpath(directory)
        for p in file_paths:
            norm = os.path.normpath(p)
            if norm == base or norm.startswith(base + os.sep):
                try:
                    size_bytes += os.path.getsize(norm)
                    file_count += 1
                except OSError:
                    continue
    else:
        # No scan handy -> walk it ourselves, honouring the same excludes scan uses.
        for root, dirs, files in os.walk(directory):
            dirs[:] = [d for d in dirs if not d.startswith('.') and not _is_excluded(os.path.join(root, d), name_rules, path_rules)]
            for f in files:
                if f.startswith('.'):
                    continue
                fp = os.path.normpath(os.path.join(root, f))
                if _is_excluded(fp, name_rules, path_rules):
                    continue
                try:
                    size_bytes += os.path.getsize(fp)
                    file_count += 1
                except OSError:
                    continue

    return {"file_count": file_count, "size_bytes": size_bytes, "dependency_count": dependency_count}


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
## ---------------------------------------------------------------------------------------- ##

## -- DEPENDENCIES ------------------------------------------------------------------------ ##
def _python_dependencies(directory):
    """Collect declared dependency names from requirements.txt and pyproject.toml."""
    deps = set()
    req = os.path.join(directory, "requirements.txt")
    if os.path.exists(req):
        for line in _safe_read(req).splitlines():
            line = line.strip()
            if line and not line.startswith("#"):
                name = _dep_name(line)
                if name:
                    deps.add(name)
    data = _load_toml(os.path.join(directory, "pyproject.toml"))
    for spec in data.get("project", {}).get("dependencies", []) or []:
        deps.add(_dep_name(spec))
    poetry = data.get("tool", {}).get("poetry", {}).get("dependencies", {})
    for name in (poetry or {}):
        if name.lower() != "python":
            deps.add(name.lower())
    return deps

def _js_dependencies(directory):
    """Return package.json dict and a set of lowercase dependency names."""

    data = _load_json(os.path.join(directory, "package.json"))
    names = set()
    for key in ("dependencies", "devDependencies"):
        section = data.get(key)
        if isinstance(section, dict):
            names.update(k.lower() for k in section)
    return data, names

def _go_dependencies(directory):
    """Return required module paths from go.mod (both single 'require x' lines and require (...) blocks)."""
    deps = []
    in_block = False
    for line in _safe_read(os.path.join(directory, "go.mod")).splitlines():
        line = line.strip()
        if not line or line.startswith("//"):
            continue
        if in_block:
            if line == ")":
                in_block = False
            else:
                deps.append(line.split()[0])  # "example.com/m v1.2.3" -> "example.com/m"
        elif line.startswith("require ("):
            in_block = True
        elif line.startswith("require "):
            parts = line[len("require "):].split()  # "require example.com/m v1.2.3"
            if parts:
                deps.append(parts[0])
    return deps

def _go_dependency_count(directory):
    """Count required modules in go.mod (kept for back-compat; delegates to _go_dependencies)."""
    return len(_go_dependencies(directory))
## ---------------------------------------------------------------------------------------- ##


def _resolve_category(cats):
    """
    Picks ONE category out of all the votes the matched frameworks cast.

    Args:
        cats (list): the category each matched framework voted for (Nones allowed).

    Returns:
        str | None: 'full stack' if we saw both frontend AND backend, otherwise the highest-priority category present, or None if nothing voted.
    """
    seen = {c for c in cats if c}
    if "frontend" in seen and "backend" in seen:  # front + back together -> full stack
        return "full stack"
    for pref in ("backend", "frontend", "desktop", "cli", "automation"):
        if pref in seen:
            return pref
    return None

def _human_size(num_bytes):
    """Turn a byte count into something readable (e.g. 1536 -> '1.5 KB')."""
    size = float(num_bytes)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if size < 1024 or unit == "TB":
            return f"{size:.0f} {unit}" if unit == "B" else f"{size:.1f} {unit}"
        size /= 1024

def describe(info):
    """Human-readable one-liner for a classification dict (back-compat string form)."""
    if info["language"] is None:
        return "Unknown Directory Type -> No recognisable project markers found"
    text = f"{info['language'].capitalize()} project"
    if info["frameworks"]:
        text += ", " + ", ".join(info["frameworks"])
    if info["category"]:
        text += f" [{info['category']}]"
    m = info.get("metrics")
    if m and m["file_count"]:
        text += f" -> {m['file_count']} files, {_human_size(m['size_bytes'])}, {m['dependency_count']} deps"
    return text

def _is_recognised(info):
    """True if the classifier identified a language for this directory."""
    return info["language"] is not None

# --- debug / CLI helpers ------------------------------------------------- #
def _is_child(child, parent):
    """
    Checks whether `child` lives inside `parent` (i.e. parent is an ancestor of child).

    Args:
        child (str): the path we think is nested.
        parent (str): the path we think is the ancestor.

    Returns:
        bool: True if child sits under parent (and isn't parent itself), else False.
    """
    child_abs = os.path.abspath(child)
    parent_abs = os.path.abspath(parent)
    if child_abs == parent_abs:
        return False
    try:
        return os.path.commonpath([child_abs, parent_abs]) == parent_abs
    except ValueError:  # e.g. different drives on Windows -> not related
        return False

def _nearest_project_ancestor(directory):
    """Walk up from `directory` and hand back the closest parent that looks like a project (or None)."""
    path = os.path.abspath(directory)
    parent = os.path.dirname(path)
    while parent and parent != path:
        if _is_recognised(classify_directory(parent)):
            return parent
        path, parent = parent, os.path.dirname(parent)
    return None

def _directory_facts(directory):
    """Dumps a bunch of low-level facts about a path, handy when something looks off."""
    facts = {
        "input": directory,
        "abspath": os.path.abspath(directory),
        "exists": os.path.exists(directory),
        "is_dir": os.path.isdir(directory),
        "is_file": os.path.isfile(directory),
        "readable": os.access(directory, os.R_OK) if os.path.exists(directory) else False,
        "is_symlink": os.path.islink(directory),
        "realpath": os.path.realpath(directory),
    }
    try:
        facts["size_bytes"] = os.path.getsize(directory)
        facts["mtime"] = os.path.getmtime(directory)
    except OSError:
        facts["size_bytes"] = facts["mtime"] = None
    return facts

## -- SCANNER ----------------------------------------------------------------------------- ##
class Scanner:
    """
    Owns the stateful half of scanning -> the exclude config and the classification cache.

    Build one (optionally with your own exclude_list); it compiles the exclude rules ONCE and reuses them across every scan. The old module-level functions (scan_directory, classify_directory, ...) still work -> they just delegate to a shared default Scanner.
    """

    def __init__(self, exclude_list=None):
        """
        Args:
            exclude_list (list): folders to ignore. If None we load it from the custom/default exclude_list files -> that's the only file I/O, and it happens here, not at import time.
        """
        if exclude_list is None:
            exclude_list = _load_exclude_list()
        self.exclude_list = exclude_list
        # Compile the exclude list once up front rather than re-parsing it on every path.
        self._name_rules, self._path_rules = compile_exclude_rules(exclude_list)
        # Memoisation store for classify() -> abs path -> (mtime, result).
        self._cache = {}

    def scan(self, directory, confirm_filters=True):
        """
        Walks the directory (and everything under it) and hands back a list of file paths.

        Args:
            directory (str): where to start digging.
            confirm_filters (bool): if true it WILL apply filters; if false it WON'T

        Returns:
            list: the file paths we found (empty list if the dir is missing or unreadable).
        """

        files_scanned = 0
        bytes_scanned = 0
        file_paths = []

        # Check if the directory exists and is accessible (error handling)
        if directory is None or not os.path.exists(directory):
            print(f"Directory '{directory}' does not exist.")
            return []
        if not os.path.isdir(directory):
            print(f"'{directory}' is not a directory.")
            return []
        if not os.access(directory, os.R_OK):
            print(f"Directory '{directory}' is not readable. (Permission denied)")
            return []

        # Recursively scan the directory and its subdirectories, while counting the number of files and bytes scanned
        if confirm_filters:
            # Exclude rules were compiled once in __init__; just reuse them here.
            name_rules, path_rules = self._name_rules, self._path_rules
            for root, dirs, files in os.walk(directory):
                # Prune excluded/hidden dirs in place so os.walk never even descends into them.
                dirs[:] = [d for d in dirs if not d.startswith('.') and not _is_excluded(os.path.join(root, d), name_rules, path_rules)]
                for file in files:

                    if file.startswith('.'):  # Skip hidden files
                        continue

                    file_path = os.path.normpath(os.path.join(root, file))
                    if _is_excluded(file_path, name_rules, path_rules):  # Exclude files by name or under an excluded path
                        continue

                    try:
                        file_paths.append(file_path)
                        files_scanned += 1
                        bytes_scanned += os.path.getsize(file_path)
                    except (OSError, PermissionError):
                        print(f"Error accessing file: {file_path}, skipping... (Permission denied or file not found)")
        else:
            for root, dirs, files in os.walk(directory):
                for file in files:
                    file_path = os.path.normpath(os.path.join(root, file))
                    try:
                        file_paths.append(file_path)
                        files_scanned += 1
                        bytes_scanned += os.path.getsize(file_path)
                    except (OSError, PermissionError):
                        print(f"Error accessing file: {file_path}, skipping... (Permission denied or file not found)")

        return file_paths

    def detect(self, directory, file_paths=None):
        """
        Pokes at a directory and works out what kind of project it is. Always hands back a dict (never None) -> {"language", "frameworks", "category", "markers", "confidence", "metrics"}.

        Args:
            directory (str): the dir to inspect.
            file_paths (list): optional last-resort fallback -> if no manifest turns up we do a file-extension census over this list to guess the language.

        Returns:
            dict: the classification. For repeated calls prefer the cached classify().
        """
        if not directory or not os.path.isdir(directory):
            return _unknown()

        def has(*parts):
            return os.path.exists(os.path.join(directory, *parts))

        # Python
        py_markers = [m for m in ("pyproject.toml", "requirements.txt", "setup.py", "Pipfile") if has(m)]
        if py_markers:
            deps = _python_dependencies(directory)
            frameworks, cats = [], []
            if has("manage.py"):  # near-definitive Django signal, better than reading deps
                frameworks.append("django")
                cats.append("backend")
            for dep, sig in PYTHON_SIGNALS.items():
                fw, cat = sig[0], sig[1]  # tolerate extra tuple elements (e.g. flask's 'templates')
                if dep in deps and fw not in frameworks:
                    frameworks.append(fw)
                    cats.append(cat)
            if not frameworks and has("app.py") and (has("templates") or has("static")):
                frameworks.append("flask")
                cats.append("backend")
            category = _resolve_category(cats)
            if category is None and (has("setup.py") or has("pyproject.toml")):
                category = "library"  # if its packaged, with no web framework -> treat it as a library
            metrics = _directory_metrics(directory, self._name_rules, self._path_rules, len(deps), file_paths)
            return _result("python", frameworks, category, py_markers, 0.9 if frameworks else 0.7, metrics, dependencies=deps)

        # JavaScript / TypeScript
        js_markers = [m for m in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml") if has(m)]
        if js_markers:
            pkg, deps = _js_dependencies(directory)
            frameworks, cats = [], []
            if has("next.config.js") or has("next.config.mjs") or "next" in deps:
                frameworks.append("next.js")
                cats.append("frontend")
            if has("nuxt.config.js") or has("nuxt.config.mjs") or "nuxt" in deps:
                frameworks.append("nuxt.js")
                cats.append("frontend")
            for dep, sig in JS_SIGNALS.items():
                fw, cat = sig[0], sig[1]
                if dep in deps and fw not in frameworks:
                    frameworks.append(fw)
                    cats.append(cat)
            category = _resolve_category(cats)
            if category is None and isinstance(pkg.get("bin"), (str, dict)):
                category = "cli"
            language = "typescript" if has("tsconfig.json") else "javascript"
            metrics = _directory_metrics(directory, self._name_rules, self._path_rules, len(deps), file_paths)
            return _result(language, frameworks, category, js_markers, 0.9 if frameworks else 0.7, metrics, dependencies=deps)

        # Rust
        rs_markers = [m for m in ("Cargo.toml", "Cargo.lock") if has(m)]
        if rs_markers:
            if has("src", "lib.rs") and not has("src", "main.rs"):
                category = "library"
            elif has("src", "main.rs"):
                category = "application"
            else:
                category = None
            rs_deps = list(_load_toml(os.path.join(directory, "Cargo.toml")).get("dependencies", {}) or {})
            metrics = _directory_metrics(directory, self._name_rules, self._path_rules, len(rs_deps), file_paths)
            return _result("rust", [], category, rs_markers, 0.9 if category else 0.7, metrics, dependencies=rs_deps)

        # Go
        go_markers = [m for m in ("go.mod", "go.sum") if has(m)]
        if go_markers:
            if has("main.go") or (has("cmd") and os.path.isdir(os.path.join(directory, "cmd"))):
                category = "application"
            elif has("lib.go"):
                category = "library"
            else:
                category = None
            go_deps = _go_dependencies(directory)
            metrics = _directory_metrics(directory, self._name_rules, self._path_rules, len(go_deps), file_paths)
            return _result("go", [], category, go_markers, 0.9 if category else 0.7, metrics, dependencies=go_deps)

        # Fallback: file-extension census
        if file_paths:
            counts = {}
            for p in file_paths:
                lang = CODE_EXTENSIONS.get(os.path.splitext(p)[1].lower())
                if lang:
                    counts[lang] = counts.get(lang, 0) + 1
            if counts:
                language = max(counts, key=counts.get)
                metrics = _directory_metrics(directory, self._name_rules, self._path_rules, 0, file_paths)
                return _result(language, [], None, ["file-extension census"], 0.4, metrics)

        return _unknown()

    def classify(self, directory):
        """
        Cached wrapper around detect() -> results get stashed in self._cache (keyed by absolute path) and guarded with the dir's mtime, so if a marker file is added/removed the mtime shifts and we just recompute.

        Args:
            directory (str): the dir to classify.

        Returns:
            dict: same shape as detect(), just cached.
        """
        cache = self._cache
        if directory is None:
            return self.detect(directory)
        abs_dir = os.path.abspath(directory)
        try:
            mtime = os.path.getmtime(directory)
        except OSError:
            return self.detect(directory)
        cached = cache.get(abs_dir)
        if cached is not None and cached[0] == mtime:  # unchanged since last time
            return cached[1]
        result = self.detect(directory)
        cache[abs_dir] = (mtime, result)
        return result

    def resolve_relationships(self, file_paths, mode):
        """
        Takes a finished list of scanned files and figures out how their directories relate to each other -> parent-child, symlinks, etc...

        Args:
            file_paths (list): the list you got back from scan.
            mode (str): how to handle nested projects, you have to pick one:
                SKIP     -> ignore the nested dirs, only keep the top-level project
                MERGE    -> show the relationships but treat the whole thing as one project (scans
                            the top dir, shows the links, but doesn't go scanning the children)
                CLASSIFY -> map out AND investigate every relationship (this is the default)
                SPLIT    -> treat every nested dir as its own separate project

        Returns:
            dict: maps each project dir to its info (type, parent, children, role, symlink).
        """

        relationships = {}

        # Validate the mode, defaulting to CLASSIFY
        if mode is None or mode not in ["SKIP", "MERGE", "CLASSIFY", "SPLIT"]:
            print(f"Invalid mode: '{mode}', defaulting to 'CLASSIFY'.")
            mode = "CLASSIFY"

        # Validate the incoming list
        if file_paths is None or not isinstance(file_paths, list):
            print(f"The list of file paths were invalid. Expected: A list of file paths. Recieved: {file_paths}")
            return {}

        # Collapse the FILE list into a DIR list, then filter it out
        directories = set()
        for path in file_paths:
            if path is None or not isinstance(path, str):  # in case a file/folder was deleted mid-scan
                print(f"Skipping invalid file path: '{path}'. Expected a string representing a file path.")
                continue
            directories.add(os.path.dirname(os.path.normpath(path)))

        # Keep only the directories that actually look like projects (reuse the classifier)
        project_dirs = sorted(d for d in directories if _is_recognised(self.classify(d)))
        if not project_dirs:
            print("No recognisable project directories were found in the scanned files.")
            return {}
        project_set = set(project_dirs)

        # Helper: walk up the tree to find the closest progenitor that is also a project.
        def nearest_project_ancestor(path):
            parent = os.path.dirname(path)
            while parent and parent != path:
                if parent in project_set:
                    return parent
                path, parent = parent, os.path.dirname(parent)
            return None

        # Build the base relationship map. This is the full, classified tree used by CLASSIFY.
        for project in project_dirs:
            parent = nearest_project_ancestor(project)
            is_symlink = os.path.islink(project)
            classification = self.classify(project)
            relationships[project] = {
                "type": describe(classification),       # human string (back-compat)
                "classification": classification,       # structured dict
                "parent": parent,
                "children": [],
                "is_symlink": is_symlink,
                "symlink_target": os.path.realpath(project) if is_symlink else None,
                "role": "root" if parent is None else "child"
            }

        # Now that every node exists, fill in each parent's children list.
        for project, info in relationships.items():
            if info["parent"] is not None:
                relationships[info["parent"]]["children"].append(project)

        # Re-shape the map according to the chosen mode.
        if mode == "SKIP":
            # Only the primogenitor
            relationships = {p: info for p, info in relationships.items() if info["parent"] is None}
            for info in relationships.values():
                info["children"] = []  # children were skipped, so don't advertise them

        elif mode == "MERGE":
            # Keep the relationships visible, but fold children into their root project; the root stays the scannable unit while children remain listed, just flagged as merged.
            for info in relationships.values():
                if info["parent"] is not None:
                    info["role"] = "merged"

        # CLASSIFY mode is the default, so we don't need to do anything special

        elif mode == "SPLIT":
            # Every project directory becomes its own independent project; cut the links.
            for info in relationships.values():
                info["parent"] = None
                info["children"] = []
                info["role"] = "independent"

        return relationships
## ---------------------------------------------------------------------------------------- ##

## -- BACK-COMPAT SHIMS ------------------------------------------------------------------- ##
# The original functional API. Each one delegates to a shared default Scanner so existing callers (and the test suite) keep working unchanged.
_DEFAULT_SCANNER = None

def _default():
    """Lazily build (and then reuse) a module-wide Scanner, so importing this module does no file I/O."""
    global _DEFAULT_SCANNER
    if _DEFAULT_SCANNER is None:
        _DEFAULT_SCANNER = Scanner()
    return _DEFAULT_SCANNER

def scan_directory(directory, exclude_list=None, confirm_filters=True):
    """Shim for Scanner.scan() -> uses the default Scanner, or a one-off built from exclude_list when given."""
    sc = _default() if exclude_list is None else Scanner(exclude_list)
    return sc.scan(directory, confirm_filters=confirm_filters)

def detect_directory_type(directory, file_paths=None):
    """Shim for Scanner.detect()."""
    return _default().detect(directory, file_paths)

def classify_directory(directory):
    """Shim for Scanner.classify()."""
    return _default().classify(directory)

def resolve_directory_relationships(file_paths, mode):
    """Shim for Scanner.resolve_relationships()."""
    return _default().resolve_relationships(file_paths, mode)

def identify_directory_type(directory):
    """Back-compat string form of classify_directory(); used for display & relationships."""
    return describe(classify_directory(directory))
## ---------------------------------------------------------------------------------------- ##

## -- PERSISTENCE BRIDGE ------------------------------------------------------------------ ##
# Glue between the scanner and the SQLite store (db_manager). db_manager is imported lazily so plain scanning never drags in the database layer.
def _project_record(path, info):
    """Flatten a resolve_relationships entry into the record shape db_manager.upsert_project wants."""
    c = info["classification"]
    return {
        "path": path,
        "language": c["language"],
        "category": c["category"],
        "confidence": c["confidence"],
        "frameworks": c["frameworks"],
        "markers": c["markers"],
        "metrics": c["metrics"],
        "dependencies": c.get("dependencies", []),
        "parent_path": info["parent"],
        "role": info["role"],
        "is_symlink": info["is_symlink"],
        "symlink_target": info["symlink_target"],
    }

def persist_scan(directory, db_path=None, mode="CLASSIFY", confirm_filters=True):
    """
    Scan `directory`, classify every project under it, and store the lot in SQLite.

    Args:
        directory (str): the workspace root to scan.
        db_path (str): where the .db file lives (None -> db_manager's default path).
        mode (str): relationship mode for resolve_relationships (CLASSIFY/SKIP/MERGE/SPLIT).
        confirm_filters (bool): apply the exclude filters while scanning (default True).

    Returns:
        (scan_id, project_count): the stored scan's id and how many projects landed.
    """
    import db_manager  # local import -> the DB layer is optional for plain scanning

    files = scan_directory(directory, confirm_filters=confirm_filters)
    rels = resolve_directory_relationships(files, mode)

    db = db_manager.Database(db_path) if db_path else db_manager.Database()
    try:
        scan_id = db.start_scan(os.path.abspath(directory))
        total_files = total_bytes = 0
        for project, info in rels.items():
            record = _project_record(project, info)
            pid = db.upsert_project(record, scan_id=scan_id)
            db.save_dependencies(pid, record["dependencies"])  # populate the dependencies table
            total_files += record["metrics"]["file_count"]
            total_bytes += record["metrics"]["size_bytes"]
        db.finish_scan(scan_id, project_count=len(rels), file_count=total_files, total_bytes=total_bytes)
        return scan_id, len(rels)
    finally:
        db.close()
## ---------------------------------------------------------------------------------------- ##

def _cli():
    """The interactive questionary menu shown when this file is run directly."""
    import sys
    import questionary

    if not sys.stdin.isatty():
        print("The interactive CLI needs a real terminal. Run: python utils/scanner.py")
        return

    def ask_dir(msg="Enter a directory:"):
        return questionary.path(msg).ask()

    # --- main actions ---------------------------------------------------- #
    def do_scan():
        directory = ask_dir("Directory to scan:")
        if not directory:
            return
        apply_filters = questionary.confirm("Apply exclude filters?", default=True).ask()
        files = scan_directory(directory, confirm_filters=apply_filters)
        total_gb = sum(os.path.getsize(f) for f in files) / 1073741824
        print(Panel(
            f"Scanned [bold]{len(files)}[/] files, ~{total_gb:.2f} GB\n"
            f"Type: {identify_directory_type(directory)}\n"
            f"Filters: {'applied' if apply_filters else 'skipped'}",
            title=f"Scan -> {directory}", style="green"))
        if files and questionary.confirm("Show the file list?", default=False).ask():
            print(Columns(files))

    def do_classify():
        directory = ask_dir("Directory to classify:")
        if not directory:
            return
        info = classify_directory(directory)
        print(Panel(describe(info), title="Best guess", style="cyan"))
        print(info)  # rich pretty-prints the structured dict

    def do_relationships():
        directory = ask_dir("Directory to scan + map:")
        if not directory:
            return
        mode = questionary.select("Relationship mode:",
                                  choices=["CLASSIFY", "SKIP", "MERGE", "SPLIT"]).ask()
        if not mode:
            return
        rels = resolve_directory_relationships(scan_directory(directory), mode=mode)
        if not rels:
            print("No recognised project directories in there.")
            return
        for proj, info in rels.items():
            print(Panel(
                f"type:     {info['type']}\n"
                f"role:     {info['role']}\n"
                f"parent:   {info['parent']}\n"
                f"children: {len(info['children'])}\n"
                f"symlink:  {info['is_symlink']}",
                title=proj, style="cyan"))

    def do_persist():
        import db_manager  # lazy: only needed once you actually save to the DB
        directory = ask_dir("Directory to scan + store:")
        if not directory:
            return
        mode = questionary.select("Relationship mode:",
                                  choices=["CLASSIFY", "SKIP", "MERGE", "SPLIT"]).ask()
        if not mode:
            return
        scan_id, count = persist_scan(directory, mode=mode)
        print(Panel(
            f"Stored [bold]{count}[/] projects\n"
            f"scan id:  {scan_id}\n"
            f"database: {os.path.normpath(db_manager.DEFAULT_DB_PATH)}",
            title="Saved to database", style="green"))

    def do_browse():
        import db_manager  # lazy: the DB layer is only needed for browsing
        from rich.table import Table

        db_path = questionary.path(
            "Database file:", default=os.path.normpath(db_manager.DEFAULT_DB_PATH)
        ).ask()
        if not db_path:
            return
        if not os.path.exists(db_path):
            print(f"No database at '{db_path}' yet. Run 'Scan + save to database' first.")
            return

        def show_projects(projects):
            if not projects:
                print("No matching projects.")
                return
            table = Table(title=f"{len(projects)} project(s)")
            for col in ("path", "language", "category", "conf", "files", "deps"):
                table.add_column(col, overflow="fold")
            for p in projects:
                table.add_row(
                    p["path"], str(p["language"]), str(p["category"]),
                    f"{p['confidence']:.2f}", str(p["file_count"]), str(len(p["dependencies"])),
                )
            print(table)

        db = db_manager.Database(db_path)
        try:
            while True:
                action = questionary.select(
                    "Browse the database:",
                    choices=[
                        "List all projects",
                        "Search (language / category / framework)",
                        "View a project (details + deps)",
                        "Latest scan",
                        "Delete a project",
                        "Back",
                    ],
                ).ask()
                if action in (None, "Back"):
                    return

                if action == "List all projects":
                    show_projects(db.all_projects())

                elif action == "Search (language / category / framework)":
                    language = questionary.text("language (blank to skip):").ask() or None
                    category = questionary.text("category (blank to skip):").ask() or None
                    framework = questionary.text("framework (blank to skip):").ask() or None
                    show_projects(db.find_projects(language=language, category=category, framework=framework))

                elif action == "View a project (details + deps)":
                    directory = ask_dir("Project path:")
                    if directory:
                        p = db.get_project(directory)
                        if p is None:
                            print("That path isn't in the database.")
                        else:
                            frameworks = ", ".join(p["frameworks"]) or "(none)"
                            deps = ", ".join(p["dependencies"]) or "(none)"
                            print(Panel(
                                f"language:   {p['language']}\n"
                                f"category:   {p['category']}\n"
                                f"confidence: {p['confidence']:.2f}\n"
                                f"frameworks: {frameworks}\n"
                                f"role:       {p['role']}\n"
                                f"parent:     {p['parent_path']}\n"
                                f"files:      {p['file_count']}  ({_human_size(p['size_bytes'])})\n"
                                f"deps ({p['dependency_count']}): {deps}\n"
                                f"first seen: {p['first_seen']}\n"
                                f"updated:    {p['updated_at']}",
                                title=p["path"], style="cyan"))

                elif action == "Latest scan":
                    scan = db.latest_scan()
                    if scan is None:
                        print("No scans recorded yet.")
                    else:
                        print(Panel(
                            f"root:     {scan['root_path']}\n"
                            f"started:  {scan['started_at']}\n"
                            f"finished: {scan['finished_at']}\n"
                            f"projects: {scan['project_count']}\n"
                            f"files:    {scan['file_count']}\n"
                            f"bytes:    {_human_size(scan['total_bytes'] or 0)}",
                            title=f"Scan #{scan['id']}", style="cyan"))

                elif action == "Delete a project":
                    directory = ask_dir("Project path to delete:")
                    if directory and questionary.confirm(f"Delete '{directory}' from the DB?", default=False).ask():
                        ok = db.delete_project(directory)
                        print("Deleted." if ok else "Nothing matched that path.")
        finally:
            db.close()

    # --- Debug Submenu --------------------------------------------------- #
    def do_debug():
        while True:
            check = questionary.select(
                "Debug / checks:",
                choices=[
                    "Is X a child of Y?",
                    "Is a path excluded by the filters?",
                    "Show the compiled exclude rules",
                    "Is it a recognised project?",
                    "Nearest project ancestor",
                    "Symlink info",
                    "Directory facts (low-level dump)",
                    "Back",
                ],
            ).ask()
            if check in (None, "Back"):
                return

            if check == "Is X a child of Y?":
                child = ask_dir("Child path:")
                parent = ask_dir("Parent path:")
                if child and parent:
                    yes = _is_child(child, parent)
                    print(f"{'✅' if yes else '❌'} '{child}' is "
                          f"{'' if yes else 'NOT '}a child of '{parent}'")

            elif check == "Is a path excluded by the filters?":
                path = questionary.path("Path to test:").ask()
                if path:
                    sc = _default()
                    blocked = _is_excluded(path, sc._name_rules, sc._path_rules)
                    print(f"{'🚫 excluded' if blocked else '✅ kept'} -> {os.path.normpath(path)}")

            elif check == "Show the compiled exclude rules":
                sc = _default()
                name_rules, path_rules = sc._name_rules, sc._path_rules
                print(Panel(
                    f"name rules ({len(name_rules)}):\n{sorted(name_rules)}\n\n"
                    f"path rules ({len(path_rules)}):\n{sorted(path_rules)}",
                    title="Compiled exclude rules", style="yellow"))

            elif check == "Is it a recognised project?":
                directory = ask_dir()
                if directory:
                    info = classify_directory(directory)
                    print(f"{'✅ yes' if _is_recognised(info) else '❌ no'} -> {describe(info)}")

            elif check == "Nearest project ancestor":
                directory = ask_dir()
                if directory:
                    anc = _nearest_project_ancestor(directory)
                    print(f"Nearest project ancestor -> {anc or '(none found)'}")

            elif check == "Symlink info":
                directory = ask_dir()
                if directory:
                    if os.path.islink(directory):
                        print(f"🔗 symlink -> {os.path.realpath(directory)}")
                    else:
                        print("Not a symlink.")

            elif check == "Directory facts (low-level dump)":
                directory = ask_dir()
                if directory:
                    print(_directory_facts(directory))

    actions = {
        "Scan a directory": do_scan,
        "Classify a directory": do_classify,
        "Resolve relationships (scan + map)": do_relationships,
        "Scan + save to database": do_persist,
        "Browse the database": do_browse,
        "Debug / checks": do_debug,
    }
    while True:
        action = questionary.select("MnemoCetus -> pick an action:",
                                    choices=list(actions) + ["Quit"]).ask()
        if action in (None, "Quit"):
            print("Bye! 🐳")
            return
        actions[action]()

# MAIN
# (if the file is run directly, usually for testing)
if __name__ == "__main__":
              #👇  Show this in raw format so "\" will print.                          Do you like the ASCII?
    print(Panel(r"""
                                                                            __________...----..____..-'``-..___
                                                                          ,'.                                  ```--.._
                                                                         :                                             ``._
                                                                        |                           --                    ``.
                                                                        |                <o>   -.-      -.     -   -.        `.
                                                                        : .                   __           --            .     \
                                                                        `._____________     (  `.   -.-      --  -   .   `      \
                                                                          `-----------------\   \_.--------..__..--.._ `. `.    :
ooo        ooooo                                                     .oooooo.                \. /                     `-._ .    |
`88.       .888'                                                    d8P'  `Y8b              .o8                           `.`   |
 888b     d'888  ooo. .oo.    .ooooo.  ooo. .oo.  .oo.    .ooooo.  888           .ooooo.  .o888oo oooo  oooo   .oooo.o      \`  |
 8 Y88. .P  888  `888P"Y88b  d88' `88b `888P"Y88bP"Y88b  d88' `88b 888          d88' `88b   888   `888  `888  d88(  "8       \  |
 8  `888'   888   888   888  888ooo888  888   888   888  888   888 888          888ooo888   888    888   888  `"Y88b.        /  \`
 8    Y     888   888   888  888    .o  888   888   888  888   888 `88b    ooo  888    .o   888 .  888   888  o.  )88b      /   .\
o8o        o888o o888o o888o `Y8bod8P' o888o o888o o888o `Y8bod8P'  `Y8bood8P'  `Y8bod8P'   "888"  `V88V"V8P' 8""888P'     /  __ .\
                                                                                                                          /_,'  \__\
""", title="v0.4", subtitle="MnemoCetus", style="cyan"))
    _cli()
