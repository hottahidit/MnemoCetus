"""
Test suite for utils/scanner.py.

The tests themselves are stdlib 'unittest' (no dependencies), so CI works with:

    python -m unittest discover -s utils/tests        # from the repo root

Running the file directly launches an INTERACTIVE runner (needs 'questionary'):

    python utils/tests/test_suite.py

It asks which parts to run (toggle each group) and an output mode:
    compact  — dots + summary (the classic unittest look)
    verbose  — prints OK / FAIL per test
    detailed — verbose + each test's docstring and timing
    quiet    — final summary only

If questionary is missing or stdin isn't a terminal (CI / piped), it falls back to
running every part in verbose mode and exits non-zero on failure.

NOTE: scanner.py loads 'utils/exclude_list/...' relative to the current working
directory the FIRST time a Scanner is built (lazily, no longer at import time), so
we chdir to the repo root and put utils/ on the path *before* importing it. After
that, every scan in these tests uses absolute temp paths, so the working directory
no longer matters.
"""

import os, sys, time, shutil, tempfile, traceback, unittest
from unittest import mock
import questionary  # optional dependency for interactive mode; not required for CI

# --- make scanner importable regardless of where the tests are launched from --- #
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
os.chdir(REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, "utils"))

import scanner  # noqa: E402  (import must follow the path setup above)
import classifier  # noqa: E402  the recognition engine scanner.detect delegates to
import cleaner     # noqa: E402  MnemoClean's marks detection
import security    # noqa: E402  MnemoScan's secret detection


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def touch(path):
    """Create an (empty-ish) file, making parent directories as needed."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write("x")


def write(path, content):
    """Create a file with specific content (e.g. a manifest)."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


def mkdir(path):
    os.makedirs(path, exist_ok=True)


class ScannerTestCase(unittest.TestCase):
    """Base class: gives every test an isolated temp dir and a clean cache."""

    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mnemo_test_")
        # The classification cache lives on the shared default Scanner; clear it so tests don't leak.
        scanner._default()._cache.clear()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def path(self, *parts):
        return os.path.join(self.tmp, *parts)


# --------------------------------------------------------------------------- #
# compile_exclude_rules
# --------------------------------------------------------------------------- #
class TestCompileExcludeRules(ScannerTestCase):
    def test_bare_names_become_name_rules(self):
        names, paths = scanner.compile_exclude_rules(["node_modules", "venv"])
        self.assertEqual(names, {"node_modules", "venv"})
        self.assertEqual(paths, set())

    def test_trailing_slash_is_stripped(self):
        names, _ = scanner.compile_exclude_rules(["node_modules/", "__pycache__/"])
        self.assertEqual(names, {"node_modules", "__pycache__"})

    def test_entries_with_separator_become_path_rules(self):
        sep_entry = os.path.join("home", "me", "build")
        names, paths = scanner.compile_exclude_rules([sep_entry])
        self.assertEqual(names, set())
        self.assertIn(os.path.normpath(sep_entry), paths)

    def test_blank_lines_and_comments_skipped(self):
        names, paths = scanner.compile_exclude_rules(["", "  ", "# a comment", "dist"])
        self.assertEqual(names, {"dist"})
        self.assertEqual(paths, set())


# --------------------------------------------------------------------------- #
# is_excluded
# --------------------------------------------------------------------------- #
class TestIsExcluded(ScannerTestCase):
    def test_basename_match_anywhere(self):
        names, paths = {"node_modules"}, set()
        self.assertTrue(
            scanner._is_excluded("/a/b/node_modules", names, paths)
        )
        self.assertTrue(
            scanner._is_excluded("/deep/nested/node_modules", names, paths)
        )

    def test_non_matching_name(self):
        self.assertFalse(scanner._is_excluded("/a/b/src", {"node_modules"}, set()))

    def test_exact_path_match(self):
        target = os.path.normpath("/a/b/build")
        self.assertTrue(scanner._is_excluded(target, set(), {target}))

    def test_under_excluded_path(self):
        target = os.path.normpath("/a/b/build")
        self.assertTrue(
            scanner._is_excluded("/a/b/build/sub/file.o", set(), {target})
        )


# --------------------------------------------------------------------------- #
# scan_directory
# --------------------------------------------------------------------------- #
class TestScanDirectory(ScannerTestCase):
    def _build_tree(self):
        touch(self.path("src", "main.py"))
        touch(self.path("README.md"))
        touch(self.path("node_modules", "pkg", "index.js"))
        touch(self.path("__pycache__", "x.pyc"))
        touch(self.path(".hidden_dir", "secret.txt"))
        touch(self.path(".env"))

    def test_excludes_node_modules_and_pycache(self):
        self._build_tree()
        files = scanner.scan_directory(
            self.tmp, exclude_list=["node_modules", "__pycache__"]
        )
        self.assertFalse(any("node_modules" in f for f in files))
        self.assertFalse(any("__pycache__" in f for f in files))

    def test_skips_hidden_files_and_dirs(self):
        self._build_tree()
        files = scanner.scan_directory(
            self.tmp, exclude_list=["node_modules", "__pycache__"]
        )
        self.assertFalse(any(".env" in f for f in files))
        self.assertFalse(any(".hidden_dir" in f for f in files))
        # Only the two real source files should survive.
        self.assertEqual(
            sorted(os.path.basename(f) for f in files), ["README.md", "main.py"]
        )

    def test_per_call_isolation(self):
        """The v0.3 prerequisite: repeated scans must NOT accumulate."""
        self._build_tree()
        first = scanner.scan_directory(self.tmp, exclude_list=["node_modules", "__pycache__"])
        second = scanner.scan_directory(self.tmp, exclude_list=["node_modules", "__pycache__"])
        self.assertEqual(len(first), len(second))
        self.assertEqual(len(first), 2)

    def test_confirm_filters_false_bypasses_everything(self):
        self._build_tree()
        files = scanner.scan_directory(self.tmp, confirm_filters=False)
        # No filtering at all -> all 6 files, including hidden and node_modules.
        self.assertEqual(len(files), 6)

    def test_default_exclude_list_excludes_node_modules(self):
        """Sanity check that the shipped default list actually works end-to-end."""
        self._build_tree()
        files = scanner.scan_directory(self.tmp)  # uses module default exclude_list
        self.assertFalse(any("node_modules" in f for f in files))

    def test_nonexistent_directory_returns_empty(self):
        self.assertEqual(scanner.scan_directory(self.path("does_not_exist")), [])

    def test_none_directory_returns_empty(self):
        self.assertEqual(scanner.scan_directory(None), [])

    def test_file_instead_of_directory_returns_empty(self):
        touch(self.path("a_file.txt"))
        self.assertEqual(scanner.scan_directory(self.path("a_file.txt")), [])


# --------------------------------------------------------------------------- #
# classify_directory / detect_directory_type / identify_directory_type
# --------------------------------------------------------------------------- #
class TestClassifyDirectory(ScannerTestCase):
    # --- Python --------------------------------------------------------- #
    def test_plain_python_never_returns_none(self):
        # requirements.txt with no known framework must NOT crash or return None.
        write(self.path("requirements.txt"), "requests==2.31.0\n")
        info = scanner.classify_directory(self.tmp)
        self.assertEqual(info["language"], "python")
        self.assertEqual(info["frameworks"], [])

    def test_python_django_via_manage_py(self):
        write(self.path("requirements.txt"), "Django>=4\n")
        touch(self.path("manage.py"))
        info = scanner.classify_directory(self.tmp)
        self.assertIn("django", info["frameworks"])
        self.assertEqual(info["category"], "backend")

    def test_python_framework_match_is_case_insensitive(self):
        # 'Flask' is commonly capitalised in requirements.txt -> must still match.
        write(self.path("requirements.txt"), "Flask==2.3.0\n")
        info = scanner.classify_directory(self.tmp)
        self.assertIn("flask", info["frameworks"])
        self.assertEqual(info["category"], "backend")

    def test_python_fastapi_from_requirements(self):
        write(self.path("requirements.txt"), "fastapi\nuvicorn\n")
        info = scanner.classify_directory(self.tmp)
        self.assertIn("fastapi", info["frameworks"])
        self.assertEqual(info["category"], "backend")

    def test_python_pyproject_setup_detected_without_requirements(self):
        # Regression guard: pyproject-only projects must be recognised as Python.
        write(self.path("pyproject.toml"), "[project]\nname = 'x'\n")
        self.assertEqual(scanner.classify_directory(self.tmp)["language"], "python")

    @unittest.skipIf(classifier.tomllib is None, "tomllib unavailable (<py3.11)")
    def test_python_pyproject_poetry_dependency_parsed(self):
        write(
            self.path("pyproject.toml"),
            '[tool.poetry.dependencies]\npython = "^3.11"\ndjango = "^4.0"\n',
        )
        info = scanner.classify_directory(self.tmp)
        self.assertEqual(info["language"], "python")
        self.assertIn("django", info["frameworks"])

    # --- JavaScript / TypeScript --------------------------------------- #
    def test_javascript_react_frontend(self):
        write(self.path("package.json"), '{"dependencies": {"react": "^18"}}')
        info = scanner.classify_directory(self.tmp)
        self.assertEqual(info["language"], "javascript")
        self.assertIn("react", info["frameworks"])
        self.assertEqual(info["category"], "frontend")

    def test_typescript_detected_via_tsconfig(self):
        write(self.path("package.json"), '{"dependencies": {"react": "^18"}}')
        touch(self.path("tsconfig.json"))
        self.assertEqual(scanner.classify_directory(self.tmp)["language"], "typescript")

    def test_javascript_next_via_config_file(self):
        touch(self.path("package.json"))
        touch(self.path("next.config.js"))
        self.assertIn("next.js", scanner.classify_directory(self.tmp)["frameworks"])

    def test_javascript_express_backend(self):
        write(self.path("package.json"), '{"dependencies": {"express": "^4"}}')
        info = scanner.classify_directory(self.tmp)
        self.assertIn("express", info["frameworks"])
        self.assertEqual(info["category"], "backend")

    def test_javascript_full_stack(self):
        # frontend (react) + backend (express) in the same package -> full stack
        write(self.path("package.json"),
              '{"dependencies": {"react": "^18", "express": "^4"}}')
        info = scanner.classify_directory(self.tmp)
        self.assertIn("react", info["frameworks"])
        self.assertIn("express", info["frameworks"])
        self.assertEqual(info["category"], "full stack")

    def test_javascript_automation_gulp(self):
        write(self.path("package.json"), '{"devDependencies": {"gulp": "^4"}}')
        info = scanner.classify_directory(self.tmp)
        self.assertIn("gulp", info["frameworks"])
        self.assertEqual(info["category"], "automation")

    def test_python_automation_ansible(self):
        write(self.path("requirements.txt"), "ansible\n")
        info = scanner.classify_directory(self.tmp)
        self.assertIn("ansible", info["frameworks"])
        self.assertEqual(info["category"], "automation")

    def test_malformed_package_json_does_not_crash(self):
        write(self.path("package.json"), "{ not valid json ")
        info = scanner.classify_directory(self.tmp)
        self.assertEqual(info["language"], "javascript")  # marker still recognised

    # --- Rust / Go ------------------------------------------------------ #
    def test_rust_binary_application(self):
        touch(self.path("Cargo.toml"))
        touch(self.path("src", "main.rs"))
        info = scanner.classify_directory(self.tmp)
        self.assertEqual(info["language"], "rust")
        self.assertEqual(info["category"], "application")

    def test_rust_library(self):
        touch(self.path("Cargo.toml"))
        touch(self.path("src", "lib.rs"))
        self.assertEqual(scanner.classify_directory(self.tmp)["category"], "library")

    def test_go_application(self):
        touch(self.path("go.mod"))
        touch(self.path("main.go"))
        info = scanner.classify_directory(self.tmp)
        self.assertEqual(info["language"], "go")
        self.assertEqual(info["category"], "application")

    # --- Metrics (file count / size / dep count) ------------------------ #
    def test_metrics_count_files_and_bytes(self):
        write(self.path("requirements.txt"), "requests\nflask\n")  # 2 deps
        write(self.path("app.py"), "print('hello')\n")             # 14 bytes
        info = scanner.classify_directory(self.tmp)
        m = info["metrics"]
        # requirements.txt + app.py = 2 files
        self.assertEqual(m["file_count"], 2)
        self.assertEqual(m["dependency_count"], 2)
        self.assertGreater(m["size_bytes"], 0)

    def test_metrics_exclude_node_modules(self):
        write(self.path("package.json"), '{"dependencies": {"react": "^18"}}')
        touch(self.path("index.js"))
        touch(self.path("node_modules", "react", "index.js"))  # must NOT be counted
        info = scanner.classify_directory(self.tmp)
        # package.json + index.js only; node_modules is excluded.
        self.assertEqual(info["metrics"]["file_count"], 2)
        self.assertEqual(info["metrics"]["dependency_count"], 1)

    def test_metrics_default_zero_for_unknown(self):
        touch(self.path("notes.txt"))
        m = scanner.classify_directory(self.tmp)["metrics"]
        self.assertEqual(m, {"file_count": 0, "size_bytes": 0, "dependency_count": 0})

    def test_metrics_reuse_prescanned_paths(self):
        # When file_paths is supplied, metrics total those instead of re-walking.
        write(self.path("requirements.txt"), "requests\n")
        write(self.path("app.py"), "x = 1\n")
        files = [self.path("requirements.txt"), self.path("app.py")]
        info = scanner.detect_directory_type(self.tmp, file_paths=files)
        self.assertEqual(info["metrics"]["file_count"], 2)

    # --- Dependency names ----------------------------------------------- #
    def test_dependencies_listed_python(self):
        write(self.path("requirements.txt"), "requests==2.31.0\nFlask>=2\n")
        info = scanner.classify_directory(self.tmp)
        self.assertEqual(info["dependencies"], ["flask", "requests"])  # sorted, lowercased

    def test_dependency_version_specs_captured(self):
        # v0.5: the declared version constraint is kept alongside the bare name.
        write(self.path("requirements.txt"), "requests==2.31.0\nFlask>=2,<3\nplain\n")
        specs = scanner.classify_directory(self.tmp)["dependency_specs"]
        self.assertEqual(specs["requests"], "==2.31.0")
        self.assertEqual(specs["flask"], ">=2,<3")
        self.assertEqual(specs["plain"], "")   # unconstrained -> empty spec

    def test_dependencies_listed_javascript(self):
        write(self.path("package.json"),
              '{"dependencies": {"react": "^18", "express": "^4"}}')
        info = scanner.classify_directory(self.tmp)
        self.assertEqual(info["dependencies"], ["express", "react"])

    def test_dependencies_empty_for_unknown(self):
        touch(self.path("notes.txt"))
        self.assertEqual(scanner.classify_directory(self.tmp)["dependencies"], [])

    # --- Weighted recognition: confidence + breakdown ------------------- #
    def test_breakdown_present_and_shaped(self):
        write(self.path("requirements.txt"), "flask\n")
        write(self.path("app.py"), "x = 1\n")
        b = scanner.classify_directory(self.tmp)["breakdown"]
        self.assertIn("languages", b)
        self.assertIn("categories", b)
        self.assertIn("python", b["languages"])

    def test_confidence_high_for_clear_django(self):
        write(self.path("requirements.txt"), "Django\n")
        touch(self.path("manage.py"))
        self.assertGreaterEqual(scanner.classify_directory(self.tmp)["confidence"], 0.9)

    def test_markup_heavy_flask_becomes_full_stack(self):
        # A tiny Flask backend file, but the tree is mostly HTML/CSS -> the census should
        # pull it to 'full stack' and the breakdown should show frontend dominating.
        write(self.path("requirements.txt"), "flask\n")
        write(self.path("app.py"), "x = 1\n")
        for i in range(6):
            write(self.path(f"page{i}.html"), "<html></html>\n")
        write(self.path("style.css"), "body{}\n")
        info = scanner.classify_directory(self.tmp)
        self.assertIn("flask", info["frameworks"])
        self.assertEqual(info["category"], "full stack")
        langs = info["breakdown"]["languages"]
        self.assertGreater(langs.get("html", 0), langs.get("python", 0))
        self.assertIn("frontend", info["breakdown"]["categories"])
        self.assertIn("backend", info["breakdown"]["categories"])

    def test_low_confidence_for_census_only(self):
        write(self.path("a.py"), "x = 1\n")
        write(self.path("b.py"), "y = 2\n")
        files = [self.path("a.py"), self.path("b.py")]
        info = scanner.detect_directory_type(self.tmp, file_paths=files)
        self.assertEqual(info["language"], "python")
        self.assertLess(info["confidence"], 0.6)  # no manifest -> low confidence

    # --- Unknown / fallback / back-compat ------------------------------ #
    def test_unknown_directory_is_structured_blank(self):
        touch(self.path("notes.txt"))
        info = scanner.classify_directory(self.tmp)
        self.assertIsNone(info["language"])
        self.assertFalse(scanner._is_recognised(info))

    def test_extension_census_fallback(self):
        # No manifest; classification leans on the scanned file list.
        files = [self.path("a.py"), self.path("b.py"), self.path("c.js")]
        info = scanner.detect_directory_type(self.tmp, file_paths=files)
        self.assertEqual(info["language"], "python")
        self.assertLess(info["confidence"], 0.6)  # no manifest -> uncertain (flagged for review)

    def test_identify_directory_type_returns_string(self):
        write(self.path("requirements.txt"), "Django\n")
        touch(self.path("manage.py"))
        text = scanner.identify_directory_type(self.tmp)
        self.assertIsInstance(text, str)
        self.assertIn("django", text.lower())

    def test_identify_unknown_startswith_unknown(self):
        touch(self.path("notes.txt"))
        self.assertTrue(scanner.identify_directory_type(self.tmp).startswith("Unknown"))

    # --- Caching -------------------------------------------------------- #
    def test_cache_hit_avoids_recompute(self):
        write(self.path("package.json"), '{"dependencies": {"react": "^18"}}')
        sc = scanner._default()
        with mock.patch.object(sc, "detect", wraps=sc.detect) as spy:
            scanner.classify_directory(self.tmp)
            scanner.classify_directory(self.tmp)
            self.assertEqual(spy.call_count, 1)  # second call served from cache
        self.assertIn(os.path.abspath(self.tmp), sc._cache)

    def test_cache_invalidates_on_mtime_change(self):
        write(self.path("package.json"), '{"dependencies": {"react": "^18"}}')
        sc = scanner._default()
        with mock.patch.object(sc, "detect", wraps=sc.detect) as spy:
            scanner.classify_directory(self.tmp)
            future = os.path.getmtime(self.tmp) + 1000  # make the cached entry stale
            os.utime(self.tmp, (future, future))
            scanner.classify_directory(self.tmp)
            self.assertEqual(spy.call_count, 2)  # recomputed after mtime moved


# --------------------------------------------------------------------------- #
# resolve_directory_relationships
# --------------------------------------------------------------------------- #
class TestResolveRelationships(ScannerTestCase):
    def _build_projects(self):
        """website (JS) -> frontend (JS), backend (Python)."""
        touch(self.path("website", "package.json"))
        touch(self.path("website", "frontend", "package.json"))
        touch(self.path("website", "backend", "requirements.txt"))
        self.website = os.path.normpath(self.path("website"))
        self.frontend = os.path.normpath(self.path("website", "frontend"))
        self.backend = os.path.normpath(self.path("website", "backend"))
        return [
            self.path("website", "package.json"),
            self.path("website", "frontend", "package.json"),
            self.path("website", "backend", "requirements.txt"),
        ]

    def test_classify_builds_parent_child_tree(self):
        files = self._build_projects()
        rels = scanner.resolve_directory_relationships(files, "CLASSIFY")
        self.assertEqual(rels[self.website]["role"], "root")
        self.assertIsNone(rels[self.website]["parent"])
        self.assertEqual(
            set(rels[self.website]["children"]), {self.frontend, self.backend}
        )
        self.assertEqual(rels[self.frontend]["parent"], self.website)
        self.assertEqual(rels[self.backend]["parent"], self.website)
        self.assertEqual(rels[self.frontend]["role"], "child")

    def test_skip_keeps_only_roots(self):
        files = self._build_projects()
        rels = scanner.resolve_directory_relationships(files, "SKIP")
        self.assertEqual(set(rels.keys()), {self.website})
        self.assertEqual(rels[self.website]["children"], [])

    def test_split_flattens_everything(self):
        files = self._build_projects()
        rels = scanner.resolve_directory_relationships(files, "SPLIT")
        self.assertEqual(set(rels.keys()), {self.website, self.frontend, self.backend})
        for info in rels.values():
            self.assertIsNone(info["parent"])
            self.assertEqual(info["children"], [])
            self.assertEqual(info["role"], "independent")

    def test_merge_flags_children_as_merged(self):
        files = self._build_projects()
        rels = scanner.resolve_directory_relationships(files, "MERGE")
        self.assertEqual(rels[self.website]["role"], "root")
        self.assertEqual(rels[self.frontend]["role"], "merged")
        self.assertEqual(rels[self.backend]["role"], "merged")

    def test_invalid_mode_defaults_to_classify(self):
        files = self._build_projects()
        rels = scanner.resolve_directory_relationships(files, "BOGUS")
        # CLASSIFY behaviour: tree intact with website as root.
        self.assertEqual(rels[self.website]["role"], "root")
        self.assertEqual(
            set(rels[self.website]["children"]), {self.frontend, self.backend}
        )

    def test_invalid_input_returns_empty(self):
        self.assertEqual(scanner.resolve_directory_relationships(None, "CLASSIFY"), {})
        self.assertEqual(
            scanner.resolve_directory_relationships("not a list", "CLASSIFY"), {}
        )

    def test_no_projects_returns_empty(self):
        touch(self.path("plain", "notes.txt"))
        rels = scanner.resolve_directory_relationships(
            [self.path("plain", "notes.txt")], "CLASSIFY"
        )
        self.assertEqual(rels, {})

    def test_symlinked_project_is_flagged(self):
        touch(self.path("realproj", "package.json"))
        link = self.path("linkproj")
        try:
            os.symlink(self.path("realproj"), link, target_is_directory=True)
        except (OSError, NotImplementedError):
            self.skipTest("symlinks not supported on this platform/permissions")
        rels = scanner.resolve_directory_relationships(
            [os.path.join(link, "package.json")], "CLASSIFY"
        )
        node = rels[os.path.normpath(link)]
        self.assertTrue(node["is_symlink"])
        self.assertEqual(node["symlink_target"], os.path.realpath(link))


# --------------------------------------------------------------------------- #
# persist_scan  (scanner -> db_manager bridge)
# --------------------------------------------------------------------------- #
class TestMarks(ScannerTestCase):
    """_collect_marks / _dir_size -> reclaimable regenerable bloat (v0.5 Stage B)."""

    def _rules(self):
        sc = scanner._default()
        return sc._name_rules, sc._path_rules

    def test_dir_size_totals_subtree(self):
        write(self.path("proj", "a.txt"), "abc")       # 3 bytes
        write(self.path("proj", "sub", "b.txt"), "de")  # 2 bytes
        size, count = cleaner._dir_size(self.path("proj"))
        self.assertEqual(size, 5)
        self.assertEqual(count, 2)

    def test_marks_flag_node_modules(self):
        write(self.path("proj", "app.py"), "x = 1\n")
        write(self.path("proj", "node_modules", "left-pad", "index.js"), "module.exports = 1")
        marks = cleaner._collect_marks(self.path("proj"), *self._rules())
        self.assertEqual(len(marks), 1)
        m = marks[0]
        self.assertEqual(m["name"], "node_modules")
        self.assertEqual(m["kind"], "dependencies")
        self.assertGreater(m["size_bytes"], 0)
        self.assertEqual(m["file_count"], 1)

    def test_marks_flag_multiple_kinds(self):
        write(self.path("proj", "main.py"), "x")
        touch(self.path("proj", "venv", "pyvenv.cfg"))
        touch(self.path("proj", "dist", "bundle.js"))
        touch(self.path("proj", "__pycache__", "main.cpython-312.pyc"))
        marks = cleaner._collect_marks(self.path("proj"), *self._rules())
        kinds = {m["name"]: m["kind"] for m in marks}
        self.assertEqual(kinds, {"venv": "virtualenv", "dist": "build", "__pycache__": "cache"})

    def test_marks_ignore_git(self):
        # .git is filtered by scans but is NOT regenerable -> it must never become a mark.
        write(self.path("proj", "main.py"), "x")
        touch(self.path("proj", ".git", "HEAD"))
        marks = cleaner._collect_marks(self.path("proj"), *self._rules())
        self.assertEqual(marks, [])

    def test_marks_do_not_descend_into_reclaimable(self):
        # A nested node_modules inside node_modules is sized as part of the parent, not a second mark.
        write(self.path("proj", "node_modules", "a", "index.js"), "1")
        write(self.path("proj", "node_modules", "a", "node_modules", "b", "index.js"), "2")
        marks = cleaner._collect_marks(self.path("proj"), *self._rules())
        self.assertEqual(len(marks), 1)
        self.assertEqual(marks[0]["file_count"], 2)  # both files counted under the top node_modules


class TestPersistScan(ScannerTestCase):
    def test_persist_scan_stores_projects_and_deps(self):
        import db_manager
        write(self.path("backend", "requirements.txt"), "flask\nrequests\n")
        write(self.path("backend", "app.py"), "x = 1\n")
        db_path = self.path("out.db")

        scan_id, count = scanner.persist_scan(self.tmp, db_path=db_path)
        self.assertEqual(count, 1)  # only 'backend' is a recognised project

        db = db_manager.Database(db_path)
        try:
            backend = db.get_project(self.path("backend"))
            self.assertIsNotNone(backend)
            self.assertEqual(backend["language"], "python")
            self.assertEqual(sorted(backend["dependencies"]), ["flask", "requests"])
            self.assertEqual(db.latest_scan()["id"], scan_id)
            self.assertEqual(db.latest_scan()["project_count"], 1)
        finally:
            db.close()

    def test_persist_scan_records_reclaimable_marks(self):
        import db_manager
        write(self.path("backend", "requirements.txt"), "flask\n")
        write(self.path("backend", "app.py"), "x = 1\n")
        # regenerable bloat the scan filters out, but persist should size + record:
        write(self.path("backend", "node_modules", "dep", "index.js"), "module.exports = 1")
        db_path = self.path("out.db")

        scanner.persist_scan(self.tmp, db_path=db_path)

        db = db_manager.Database(db_path)
        try:
            backend = db.get_project(self.path("backend"))
            self.assertGreater(backend["reclaimable_bytes"], 0)
            marks = db.get_marks(backend["id"])
            self.assertEqual(len(marks), 1)
            self.assertEqual(marks[0]["name"], "node_modules")
            summary = db.reclaimable_summary()
            self.assertEqual(summary["total_bytes"], backend["reclaimable_bytes"])
        finally:
            db.close()


class TestSecrets(ScannerTestCase):
    def _rules(self):
        sc = scanner._default()
        return sc._name_rules, sc._path_rules

    def test_detects_aws_key_and_masks_it(self):
        write(self.path("config.py"), 'AWS = "AKIAIOSFODNN7EXAMPLE"\n')
        name_rules, path_rules = self._rules()
        finds = security.scan_secrets(self.tmp, name_rules, path_rules)
        self.assertEqual(len(finds), 1)
        self.assertEqual(finds[0]["rule"], "AWS access key id")
        self.assertEqual(finds[0]["severity"], "high")
        self.assertEqual(finds[0]["line"], 1)
        self.assertNotIn("AKIAIOSFODNN7EXAMPLE", finds[0]["detail"])  # masked, never the raw value
        self.assertTrue(finds[0]["detail"].startswith("AKIA"))

    def test_scans_dotenv_but_skips_excluded_dirs(self):
        write(self.path(".env"), "GITHUB_TOKEN=ghp_" + "a" * 36 + "\n")
        write(self.path("node_modules", "leak.js"), 'k = "AKIAIOSFODNN7EXAMPLE"\n')
        name_rules, path_rules = self._rules()
        finds = security.scan_secrets(self.tmp, name_rules, path_rules)
        rules = {f["rule"] for f in finds}
        self.assertIn("GitHub token", rules)          # hidden .env IS scanned
        self.assertNotIn("AWS access key id", rules)   # node_modules is excluded, so not scanned

    def test_clean_tree_has_no_findings(self):
        write(self.path("app.py"), "x = 1\nprint('hello')\n")
        name_rules, path_rules = self._rules()
        self.assertEqual(security.scan_secrets(self.tmp, name_rules, path_rules), [])

    def test_audit_is_graceful_without_tools(self):
        # pip-audit / npm audit are optional; with no manifest (and likely no tool) we get [], never a crash.
        self.assertEqual(security.audit_dependencies(self.tmp), [])

    def test_mask_keeps_only_a_prefix(self):
        self.assertEqual(security._mask("abcd1234567890"), "abcd" + "*" * 10)
        self.assertEqual(security._mask("abc"), "***")


class TestExcludeListLoading(ScannerTestCase):
    def test_loads_regardless_of_cwd(self):
        # Regression: the exclude list must resolve relative to scanner.py, NOT the current working
        # directory, so the CLI works when launched from anywhere (e.g. inside utils/), not just the repo root.
        original = os.getcwd()
        os.chdir(self.tmp)  # a temp dir with no utils/exclude_list beneath it
        try:
            self.assertTrue(scanner._load_exclude_list())  # the default list still loads (no FileNotFoundError)
        finally:
            os.chdir(original)


# =========================================================================== #
# Interactive runner
#
# Run 'python utils/tests/test_suite.py' for an interactive menu (questionary):
#   - pick which PARTS to test (toggle each group on/off)
#   - pick an output MODE: compact / verbose / detailed / quiet
#
# Run 'python -m unittest discover -s utils/tests' for the classic, non-interactive path (used by CI).
# The classes above are the single source of truth either way.
# =========================================================================== #

# Each "part" the user can select, in run order: (key, friendly label, TestCase).
GROUPS = [
    ("compile",  "Exclude rule compilation  (compile_exclude_rules)",      TestCompileExcludeRules),
    ("exclude",  "Exclusion matching        (is_excluded)",                TestIsExcluded),
    ("scan",     "Directory scanning        (scan_directory)",             TestScanDirectory),
    ("identify", "Project classification     (classify_directory)",         TestClassifyDirectory),
    ("resolve",  "Relationship resolution   (resolve_directory_relationships)", TestResolveRelationships),
    ("marks",    "Reclaimable marks         (_collect_marks / _dir_size)",       TestMarks),
    ("persist",  "Persistence bridge        (persist_scan -> db_manager)",      TestPersistScan),
    ("secrets",  "Secret detection          (security.scan_secrets)",           TestSecrets),
    ("exclload", "Exclude list loading       (cwd-independent)",                 TestExcludeListLoading),
]
GROUP_LABELS = {cls.__name__: label for _, label, cls in GROUPS}


class _Colors:
    """Tiny ANSI helper; produces empty strings when colour is disabled."""
    def __init__(self, enabled):
        e = (lambda code: code) if enabled else (lambda code: "")
        self.green = e("\033[32m")
        self.red = e("\033[31m")
        self.yellow = e("\033[33m")
        self.bold = e("\033[1m")
        self.dim = e("\033[2m")
        self.reset = e("\033[0m")


def _colors_enabled():
    return sys.stdout.isatty() and os.environ.get("NO_COLOR") is None


class LiveResult(unittest.TestResult):
    """
    A result that prints a line per test as it runs:
        OK     <Group>.<test_name>
        FAIL   <Group>.<test_name>      (+ full traceback)
    'detailed=True' also prints each test's docstring and elapsed time.
    """
    def __init__(self, detailed=False, color=True):
        super().__init__()
        self.detailed = detailed
        self.c = _Colors(color)
        self._start = {}
        self._cur_group = None

    # --- group header on first test of each class ------------------------- #
    def startTest(self, test):
        super().startTest(test)
        self._start[test] = time.perf_counter()
        group = test.__class__.__name__
        if group != self._cur_group:
            self._cur_group = group
            print(f"\n{self.c.bold}{GROUP_LABELS.get(group, group)}{self.c.reset}")

    def _elapsed_ms(self, test):
        return (time.perf_counter() - self._start.get(test, time.perf_counter())) * 1000

    def _line(self, status, color, test):
        name = test.id().split(".")[-1]
        timing = f" {self.c.dim}[{self._elapsed_ms(test):.1f}ms]{self.c.reset}" if self.detailed else ""
        print(f"  {color}{status:<6}{self.c.reset}{name}{timing}")
        if self.detailed:
            doc = test.shortDescription()
            if doc:
                print(f"         {self.c.dim}{doc}{self.c.reset}")

    def addSuccess(self, test):
        super().addSuccess(test)
        self._line("OK", self.c.green, test)

    def addFailure(self, test, err):
        super().addFailure(test, err)
        self._line("FAIL", self.c.red, test)
        self._print_trace(err)

    def addError(self, test, err):
        super().addError(test, err)
        self._line("ERROR", self.c.red, test)
        self._print_trace(err)

    def addSkip(self, test, reason):
        super().addSkip(test, reason)
        self._line("SKIP", self.c.yellow, test)
        print(f"         {self.c.dim}reason: {reason}{self.c.reset}")

    def _print_trace(self, err):
        tb = "".join(traceback.format_exception(*err)).rstrip()
        indented = "\n".join("         " + ln for ln in tb.splitlines())
        print(f"{self.c.red}{indented}{self.c.reset}")


def build_suite(keys):
    """Build a TestSuite containing only the selected group keys, in GROUPS order."""
    loader = unittest.TestLoader()
    suite = unittest.TestSuite()
    by_key = {key: cls for key, _, cls in GROUPS}
    for key in keys:
        cls = by_key.get(key)
        if cls is not None:
            suite.addTests(loader.loadTestsFromTestCase(cls))
    return suite


def _print_summary(result, elapsed, color=True):
    c = _Colors(color)
    total = result.testsRun
    failed, errored, skipped = len(result.failures), len(result.errors), len(result.skipped)
    passed = total - failed - errored - skipped
    parts = [f"{c.green}{passed} passed{c.reset}"]
    if failed:
        parts.append(f"{c.red}{failed} failed{c.reset}")
    if errored:
        parts.append(f"{c.red}{errored} errored{c.reset}")
    if skipped:
        parts.append(f"{c.yellow}{skipped} skipped{c.reset}")
    print("\n" + "─" * 64)
    print("  " + "   ".join(parts) + f"   {c.dim}({total} tests in {elapsed:.3f}s){c.reset}")
    ok = result.wasSuccessful()
    print(f"  Result: {(c.green + 'ALL OK') if ok else (c.red + 'FAILED')}{c.reset}")


def run_suite(suite, mode):
    """Run a suite in the chosen mode and return the result object."""
    color = _colors_enabled()
    start = time.perf_counter()
    if mode == "compact":
        result = unittest.TextTestRunner(verbosity=1).run(suite)   # dots + stdlib summary
    elif mode == "quiet":
        result = unittest.TextTestRunner(verbosity=0).run(suite)   # summary only
    else:  # "verbose" or "detailed"
        result = LiveResult(detailed=(mode == "detailed"), color=color)
        suite.run(result)
        _print_summary(result, time.perf_counter() - start, color)
    return result


def interactive_main():
    mode = questionary.select(
        "Select output mode:",
        choices=[
            questionary.Choice("Compact  — dots + summary (the original)", "compact"),
            questionary.Choice("Verbose  — OK / FAIL printed per test", "verbose"),
            questionary.Choice("Detailed — verbose + docstrings & timing", "detailed"),
            questionary.Choice("Quiet    — final summary only", "quiet"),
        ],
    ).ask()
    if mode is None:
        return None  # user cancelled (Ctrl-C / Esc)

    selected = questionary.checkbox(
        "Select which parts to test (space toggles, enter runs):",
        choices=[questionary.Choice(label, value=key, checked=True) for key, label, _ in GROUPS],
    ).ask()
    if selected is None:
        return None
    if not selected:
        print("No parts selected — nothing to run.")
        return None

    return run_suite(build_suite(selected), mode)


def main():
    # Interactive only when questionary is present AND we have a real terminal.
    if questionary is not None and sys.stdin.isatty():
        interactive_main()
        return
    # Fallback (CI, piped stdin, or questionary missing): run everything, verbose.
    if questionary is None:
        print("(questionary not installed — running all parts non-interactively)\n")
    result = run_suite(build_suite([key for key, _, _ in GROUPS]), "verbose")
    sys.exit(0 if result.wasSuccessful() else 1)


if __name__ == "__main__":
    main()
