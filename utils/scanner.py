# File scanner for MnemoCetus (v0.2 scanning + v0.4 refactor - the discovery half of "MnemoSort").
#
# Walks a workspace and filters out the junk (node_modules, venv, build artifacts...), then hands each candidate dir to the classifier to work out what it is.
# v0.4 folds the stateful bits (exclude config + classification cache) into a Scanner class; the original module-level functions stay on as thin shims.
# The recognition engine now lives in classifier.py and the cleanup detection in cleaner.py -> this file is the scanning core plus the Scanner orchestrator.

# IMPORTS
from rich import print
import os

# The classification engine (Scanner.detect delegates the "what kind of project" work to these).
from classifier import (
    PYTHON_SIGNALS, JS_SIGNALS, W_MARKER, W_DEP, W_LAYOUT,
    _result, _unknown, _census, _recognise, _load_toml,
    _python_dependencies, _js_dependencies, _go_dependencies,
)

# FUNCTIONS
def _load_exclude_list():
    """
    Read the exclude list off disk -> prefer the user's custom_exclude_list.txt, else fall back to the shipped default_exclude_list.txt.

    Returns:
        list: the raw lines (Scanner compiles them into rules). This is the only file I/O, and it runs when a Scanner is built, not at import.
    """
    # Resolve the exclude_list dir relative to THIS file (utils/), not the current working directory,
    # so the CLI works no matter where it's launched from (e.g. from inside utils/, not just the repo root).
    here = os.path.dirname(os.path.abspath(__file__))
    custom = os.path.join(here, "exclude_list", "custom_exclude_list.txt")
    default = os.path.join(here, "exclude_list", "default_exclude_list.txt")
    try:
        with open(custom, 'r') as f:
            return f.read().splitlines()
    except FileNotFoundError:
        print("Custom exclude list not found, proceeding without it. (If it exists, name your custom list 'custom_exclude_list.txt' and place it in the 'exclude_list' folder to use it.)")
        with open(default, 'r') as f:
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

## -- FILE COLLECTION --------------------------------------------------------------------- ##
def _collect_files(directory, name_rules, path_rules, file_paths=None):
    """
    One pass over a project's files -> a list of (path, size_bytes), honouring excludes + hidden.

    Args:
        directory (str): the project dir we're measuring.
        name_rules (set): basename exclude rules (already compiled by the caller).
        path_rules (set): path exclude rules (already compiled by the caller).
        file_paths (list): optional pre-scanned paths -> if given we just keep the ones under 'directory' instead of walking the tree again.

    Returns:
        list: (path, size_bytes) tuples. Both metrics and the census are derived from this.
    """
    collected = []

    if file_paths is not None:
        # Reuse an existing scan -> keep only the paths that sit under this directory.
        base = os.path.normpath(directory)
        for p in file_paths:
            norm = os.path.normpath(p)
            if norm == base or norm.startswith(base + os.sep):
                try:
                    collected.append((norm, os.path.getsize(norm)))
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
                    collected.append((fp, os.path.getsize(fp)))
                except OSError:
                    continue

    return collected

def _metrics(collected, dependency_count=0):
    """Roll a _collect_files() result up into the metrics dict {file_count, size_bytes, dependency_count}."""
    return {
        "file_count": len(collected),
        "size_bytes": sum(size for _, size in collected),
        "dependency_count": dependency_count,
    }

def _directory_metrics(directory, name_rules, path_rules, dependency_count=0, file_paths=None):
    """Back-compat helper: collect the files and roll them up in one go (see _collect_files / _metrics)."""
    return _metrics(_collect_files(directory, name_rules, path_rules, file_paths), dependency_count)
## ---------------------------------------------------------------------------------------- ##

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
        Pokes at a directory and works out what kind of project it is. Always hands back a dict (never None) -> {"language", "frameworks", "category", "markers", "confidence", "metrics", "dependencies", "breakdown"}.

        Markers pick the candidate language + frameworks; the file-type census then sets the confidence and a composition breakdown, and can promote a backend-with-lots-of-markup project to "full stack" (see classifier._recognise).

        Args:
            directory (str): the dir to inspect.
            file_paths (list): optional pre-scanned paths -> reused for metrics/census, and the last-resort file-extension census when no manifest turns up.

        Returns:
            dict: the classification. For repeated calls prefer the cached classify().
        """
        if not directory or not os.path.isdir(directory):
            return _unknown()

        def has(*parts):
            return os.path.exists(os.path.join(directory, *parts))

        def collect():
            return _collect_files(directory, self._name_rules, self._path_rules, file_paths)

        # Python
        py_markers = [m for m in ("pyproject.toml", "requirements.txt", "setup.py", "Pipfile") if has(m)]
        if py_markers:
            deps = _python_dependencies(directory)
            frameworks, cat_votes = [], []
            if has("manage.py"):  # near-definitive Django signal, better than reading deps
                frameworks.append("django")
                cat_votes.append(("backend", W_MARKER))
            for dep, sig in PYTHON_SIGNALS.items():
                fw, cat = sig[0], sig[1]  # tolerate extra tuple elements (e.g. flask's 'templates')
                if dep in deps and fw not in frameworks:
                    frameworks.append(fw)
                    if cat:
                        cat_votes.append((cat, W_DEP))
            if not frameworks and has("app.py") and (has("templates") or has("static")):
                frameworks.append("flask")
                cat_votes.append(("backend", W_LAYOUT))
            collected = collect()
            category, confidence, breakdown = _recognise(
                "python", cat_votes, True, _census([p for p, _ in collected]))
            if category is None and (has("setup.py") or has("pyproject.toml")):
                category = "library"  # if its packaged, with no web framework -> treat it as a library
            metrics = _metrics(collected, len(deps))
            return _result("python", frameworks, category, py_markers, confidence, metrics,
                           dependencies=deps, breakdown=breakdown)

        # JavaScript / TypeScript
        js_markers = [m for m in ("package.json", "package-lock.json", "yarn.lock", "pnpm-lock.yaml") if has(m)]
        if js_markers:
            pkg, deps = _js_dependencies(directory)
            frameworks, cat_votes = [], []
            if has("next.config.js") or has("next.config.mjs") or "next" in deps:
                frameworks.append("next.js")
                cat_votes.append(("frontend", W_MARKER))
            if has("nuxt.config.js") or has("nuxt.config.mjs") or "nuxt" in deps:
                frameworks.append("nuxt.js")
                cat_votes.append(("frontend", W_MARKER))
            for dep, sig in JS_SIGNALS.items():
                fw, cat = sig[0], sig[1]
                if dep in deps and fw not in frameworks:
                    frameworks.append(fw)
                    if cat:
                        cat_votes.append((cat, W_DEP))
            language = "typescript" if has("tsconfig.json") else "javascript"
            collected = collect()
            category, confidence, breakdown = _recognise(
                language, cat_votes, True, _census([p for p, _ in collected]))
            if category is None and isinstance(pkg.get("bin"), (str, dict)):
                category = "cli"
            metrics = _metrics(collected, len(deps))
            return _result(language, frameworks, category, js_markers, confidence, metrics,
                           dependencies=deps, breakdown=breakdown)

        # Rust
        rs_markers = [m for m in ("Cargo.toml", "Cargo.lock") if has(m)]
        if rs_markers:
            cat_votes = []
            if has("src", "lib.rs") and not has("src", "main.rs"):
                cat_votes.append(("library", W_MARKER))
            elif has("src", "main.rs"):
                cat_votes.append(("application", W_MARKER))
            rs_table = _load_toml(os.path.join(directory, "Cargo.toml")).get("dependencies", {}) or {}
            # Cargo dep values are either a version string or a table ({version = "1.3", ...}).
            rs_deps = {name: (v if isinstance(v, str) else (v.get("version", "") if isinstance(v, dict) else ""))
                       for name, v in rs_table.items()}
            collected = collect()
            category, confidence, breakdown = _recognise(
                "rust", cat_votes, True, _census([p for p, _ in collected]))
            metrics = _metrics(collected, len(rs_deps))
            return _result("rust", [], category, rs_markers, confidence, metrics,
                           dependencies=rs_deps, breakdown=breakdown)

        # Go
        go_markers = [m for m in ("go.mod", "go.sum") if has(m)]
        if go_markers:
            cat_votes = []
            if has("main.go") or (has("cmd") and os.path.isdir(os.path.join(directory, "cmd"))):
                cat_votes.append(("application", W_MARKER))
            elif has("lib.go"):
                cat_votes.append(("library", W_MARKER))
            go_deps = _go_dependencies(directory)
            collected = collect()
            category, confidence, breakdown = _recognise(
                "go", cat_votes, True, _census([p for p, _ in collected]))
            metrics = _metrics(collected, len(go_deps))
            return _result("go", [], category, go_markers, confidence, metrics,
                           dependencies=go_deps, breakdown=breakdown)

        # Fallback: no manifest -> lean entirely on the file-extension census.
        if file_paths:
            census = _census(file_paths)
            if census:
                language = max(census, key=census.get)
                category, confidence, breakdown = _recognise(language, [], False, census)
                metrics = _metrics(collect(), 0)
                return _result(language, [], category, ["file-extension census"], confidence, metrics,
                               breakdown=breakdown)

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

        # Build the base relationship map.
        # This is the full, classified tree used by CLASSIFY.
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
# Glue between the scanner and the SQLite store (db_manager). db_manager + cleaner are imported lazily so plain scanning never drags in the database or cleanup layers.
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
        "breakdown": c.get("breakdown"),
        "dependencies": c.get("dependencies", []),
        "dependency_specs": c.get("dependency_specs", {}),
        "parent_path": info["parent"],
        "role": info["role"],
        "is_symlink": info["is_symlink"],
        "symlink_target": info["symlink_target"],
    }

def persist_scan(directory, db_path=None, mode="CLASSIFY", confirm_filters=True, security=True):
    """
    Scan 'directory', classify every project under it, and store the lot in SQLite.

    Args:
        directory (str): the workspace root to scan.
        db_path (str): where the .db file lives (None -> db_manager's default path).
        mode (str): relationship mode for resolve_relationships (CLASSIFY/SKIP/MERGE/SPLIT).
        confirm_filters (bool): apply the exclude filters while scanning (default True).
        security (bool): run the MnemoScan secret scan per project and store findings (default True).

    Returns:
        (scan_id, project_count): the stored scan's id and how many projects landed.
    """
    import db_manager  # local import -> the DB layer is optional for plain scanning
    from cleaner import _collect_marks  # local import -> keep the cleanup layer out of plain scanning
    from security import scan_secrets  # local import -> keep the security layer out of plain scanning

    sc = _default()
    files = sc.scan(directory, confirm_filters=confirm_filters)
    rels = sc.resolve_relationships(files, mode)

    db = db_manager.Database(db_path) if db_path else db_manager.Database()
    try:
        scan_id = db.start_scan(os.path.abspath(directory))
        total_files = total_bytes = 0
        for project, info in rels.items():
            # Size up the regenerable bloat (node_modules, venv, ...) the scan filtered out.
            marks = _collect_marks(project, sc._name_rules, sc._path_rules)
            record = _project_record(project, info)
            record["reclaimable_bytes"] = sum(m["size_bytes"] for m in marks)
            pid = db.upsert_project(record, scan_id=scan_id)
            # Populate the dependencies table, tagging each with its ecosystem (the project language) and declared version spec -> feeds the dependency-intelligence conflict check.
            db.save_dependencies(pid, record["dependencies"], ecosystem=record["language"],
                                 specs=record["dependency_specs"])
            db.save_marks(pid, marks)                          # populate the reclaimable marks
            # Persist the per-project file inventory too (reuses the scan's file list) -> feeds the storage analyser's "largest files / directories".
            db.save_files(pid, _collect_files(project, sc._name_rules, sc._path_rules, files))
            if security:
                # MnemoScan: flag hard-coded secrets in the project's files (values are masked before storage).
                db.save_security_findings(pid, scan_secrets(project, sc._name_rules, sc._path_rules))
            total_files += record["metrics"]["file_count"]
            total_bytes += record["metrics"]["size_bytes"]
        db.finish_scan(scan_id, project_count=len(rels), file_count=total_files, total_bytes=total_bytes)
        return scan_id, len(rels)
    finally:
        db.close()
## ---------------------------------------------------------------------------------------- ##

# MAIN
# (run directly -> hand off to the interactive CLI, which lives in cli.py now)
if __name__ == "__main__":
    from cli import main
    main()
