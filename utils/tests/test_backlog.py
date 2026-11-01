"""
Regression tests for the pre-v1 backlog: SQLite WAL + batched writes, robust manifest parsing,
honest bloat sizing (symlinks / hard links), atomic settings, and the private session DB path.
"""

import os
import sys
import json
import shutil
import sqlite3
import tempfile
import unittest
from unittest import mock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_ROOT)
sys.path.insert(0, os.path.join(REPO_ROOT, "utils"))

import classifier  # noqa: E402
import cleaner  # noqa: E402
import scanner  # noqa: E402
import settings  # noqa: E402
from db_tools import manager as db_manager  # noqa: E402


def _read(path):
    with open(path) as f:
        return f.read()


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mnemo_bl_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def p(self, *parts):
        return os.path.join(self.tmp, *parts)

    def write(self, rel, text="", mode="w"):
        path = self.p(rel)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, mode) as f:
            f.write(text)
        return path


class TestDatabase(TmpCase):
    def test_file_db_uses_wal(self):
        db = db_manager.Database(self.p("w.db"))
        try:
            self.assertEqual(db.con.execute("PRAGMA journal_mode").fetchone()[0].lower(), "wal")
        finally:
            db.close()

    def test_batch_commits_once_and_rolls_back_on_error(self):
        db = db_manager.Database(self.p("b.db"))
        try:
            with db.batch():
                db.upsert_project({"path": "/tmp/a"})
                db.upsert_project({"path": "/tmp/b"})
            self.assertEqual(len(db.all_projects()), 2)
            with self.assertRaises(RuntimeError):
                with db.batch():
                    db.upsert_project({"path": "/tmp/c"})
                    raise RuntimeError("boom")
            self.assertIsNone(db.get_project("/tmp/c"))  # rolled back
        finally:
            db.close()

    def test_failed_merge_leaves_target_untouched(self):
        src = db_manager.Database(self.p("src.db"))
        src.upsert_project({"path": "/tmp/m1"})
        src.upsert_project({"path": "/tmp/m2"})
        src.close()
        dst = db_manager.Database(self.p("dst.db"))
        try:
            real = dst.save_files
            calls = {"n": 0}

            def flaky(*a, **k):
                calls["n"] += 1
                if calls["n"] == 2:
                    raise sqlite3.OperationalError("disk I/O error")
                return real(*a, **k)
            with mock.patch.object(dst, "save_files", side_effect=flaky):
                with self.assertRaises(sqlite3.OperationalError):
                    dst.merge_from(self.p("src.db"))
            self.assertEqual(dst.all_projects(), [])  # all-or-nothing
        finally:
            dst.close()

    def test_all_projects_batches_dependencies_correctly(self):
        db = db_manager.Database(self.p("d.db"))
        try:
            a = db.upsert_project({"path": "/tmp/a"})
            b = db.upsert_project({"path": "/tmp/b"})
            db.save_dependencies(a, ["flask", "requests"])
            db.save_dependencies(b, ["react"])
            deps = {p["path"]: p["dependencies"] for p in db.all_projects()}
            self.assertEqual(deps, {"/tmp/a": ["flask", "requests"], "/tmp/b": ["react"]})
            self.assertEqual(db.find_projects(language=None)[0]["dependencies"], ["flask", "requests"])
        finally:
            db.close()


class TestManifestParsing(TmpCase):
    def test_utf16_requirements(self):
        self.write("p/requirements.txt", "flask==2.0\nrequests\n".encode("utf-16"), mode="wb")
        self.assertEqual(classifier._python_dependencies(self.p("p")), {"flask": "==2.0", "requests": ""})

    def test_options_urls_and_paths_are_not_packages(self):
        self.write("p/requirements.txt",
                   "-r base.txt\n-e .\n-i https://evil.example/simple\n--hash=sha256:abc\n"
                   "git+https://example.com/x/y.git\n./local_pkg\n/abs/thing.whl\n"
                   "Django>=4 ; python_version>'3'  # web\nmypkg @ https://example.com/y.whl\n"
                   "numpy \\\n  >=1.2\n")
        self.assertEqual(classifier._python_dependencies(self.p("p")),
                         {"django": ">=4", "mypkg": "", "numpy": ">=1.2"})

    def test_odd_but_valid_toml_does_not_crash(self):
        if classifier.tomllib is None:
            self.skipTest("tomllib unavailable")
        self.write("p/pyproject.toml", 'project = "x"\n[tool]\npoetry = 3\n')
        self.assertEqual(classifier._python_dependencies(self.p("p")), {})
        self.write("q/pyproject.toml", '[project]\ndependencies = "flask"\n[tool.poetry.dependencies]\npython = "^3"\n')
        self.assertEqual(classifier._python_dependencies(self.p("q")), {})
        self.write("r/pyproject.toml", "[project]\ndependencies = [1, {a = 2}, \"flask>=2\"]\n")
        self.assertEqual(classifier._python_dependencies(self.p("r")), {"flask": ">=2"})

    def test_cargo_dependencies_string_does_not_crash(self):
        if classifier.tomllib is None:
            self.skipTest("tomllib unavailable")
        self.write("rs/Cargo.toml", '[package]\nname = "x"\ndependencies = "oops"\n')
        self.write("rs/src/main.rs", "fn main() {}\n")
        info = scanner.classify_directory(self.p("rs"))
        self.assertEqual(info["language"], "rust")


class TestBloatSizing(TmpCase):
    def test_hard_links_to_an_outside_store_free_nothing(self):
        store = self.write("store/big", "x" * 50000)
        os.makedirs(self.p("proj/node_modules"))
        os.link(store, self.p("proj/node_modules/big"))           # pnpm-style hard link
        self.write("proj/node_modules/own", "y" * 300)
        size, count = cleaner._dir_size(self.p("proj/node_modules"))
        self.assertEqual((size, count), (300, 2))

    def test_hard_links_wholly_inside_count_once(self):
        a = self.write("proj/node_modules/a", "z" * 1000)
        os.link(a, self.p("proj/node_modules/b"))
        self.assertEqual(cleaner._dir_size(self.p("proj/node_modules")), (1000, 2))

    def test_symlinked_marker_is_not_a_mark(self):
        self.write("real_venv/lib/x", "v" * 4000)
        os.makedirs(self.p("proj"))
        os.symlink(self.p("real_venv"), self.p("proj/venv"))
        self.assertEqual(cleaner._collect_marks(self.p("proj"), set(), set()), [])


class TestSettingsAtomic(TmpCase):
    def test_failed_write_keeps_previous_file(self):
        path = self.p("settings.json")
        with mock.patch.object(settings, "SETTINGS_PATH", path):
            cfg = settings.load()
            cfg["configured"] = True
            self.assertTrue(settings.save(cfg))
            before = _read(path)
            with mock.patch.object(settings.json, "dump", side_effect=OSError("disk full")):
                self.assertFalse(settings.save(cfg))
            self.assertEqual(_read(path), before)                     # intact, not truncated
            self.assertTrue(json.loads(before)["configured"])
            self.assertEqual([f for f in os.listdir(self.tmp) if f.endswith(".tmp")], [])  # no litter


class TestSessionDbPath(unittest.TestCase):
    @unittest.skipUnless(hasattr(os, "getuid"), "POSIX only")
    def test_session_db_is_in_a_private_dir(self):
        import cli
        path = cli._session_db_path()
        st = os.stat(os.path.dirname(path))
        self.assertEqual(st.st_uid, os.getuid())
        self.assertEqual(st.st_mode & 0o077, 0)  # no group / other access
        self.assertNotEqual(os.path.dirname(path), tempfile.gettempdir())


if __name__ == "__main__":
    unittest.main()
