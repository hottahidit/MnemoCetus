"""
Test suite for utils/db_manager.py (the v0.4 SQLite metadata engine).

Pure stdlib 'unittest' -> no external deps. Run with:

    python -m unittest discover -s utils/tests        # from the repo root

Every test gets its own in-memory database (":memory:"), so nothing touches disk and tests can't leak into each other.
The one on-disk test below proves the whole point of v0.4 -> "data survives restart".
"""

import os, sys, shutil, sqlite3, tempfile, unittest

# Make db_manager importable no matter where the tests are launched from.
REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "utils"))

import db_manager  # noqa: E402


def sample_project(path="/tmp/example", **overrides):
    """A classifier-shaped record, the way scanner.classify_directory hands it over."""
    record = {
        "path": path,
        "language": "python",
        "category": "backend",
        "confidence": 0.9,
        "frameworks": ["flask"],
        "markers": ["requirements.txt"],
        "metrics": {"file_count": 12, "size_bytes": 34567, "dependency_count": 2},
        "parent_path": None,
        "role": "root",
        "is_symlink": False,
        "symlink_target": None,
    }
    record.update(overrides)
    return record


class DBTestCase(unittest.TestCase):
    """Base: fresh in-memory DB per test."""

    def setUp(self):
        self.db = db_manager.Database(":memory:")

    def tearDown(self):
        self.db.close()


# --------------------------------------------------------------------------- #
# Schema / initialisation
# --------------------------------------------------------------------------- #
class TestInitialisation(DBTestCase):
    def test_all_four_tables_created(self):
        rows = self.db.con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'"
        ).fetchall()
        names = {r["name"] for r in rows}
        self.assertTrue({"projects", "dependencies", "files", "scans"}.issubset(names))

    def test_schema_version_stamped(self):
        version = self.db.con.execute("PRAGMA user_version").fetchone()[0]
        self.assertEqual(version, db_manager.SCHEMA_VERSION)

    def test_reinitialising_is_idempotent(self):
        # Re-running init on an already-initialised DB must not blow up or wipe data.
        self.db.upsert_project(sample_project())
        self.db._initialise()  # should be a no-op now
        self.assertEqual(len(self.db.all_projects()), 1)

    def test_foreign_keys_enabled(self):
        self.assertEqual(self.db.con.execute("PRAGMA foreign_keys").fetchone()[0], 1)


# --------------------------------------------------------------------------- #
# Projects: insert / upsert
# --------------------------------------------------------------------------- #
class TestProjects(DBTestCase):
    def test_insert_and_read_back(self):
        pid = self.db.upsert_project(sample_project(path="/tmp/proj"))
        got = self.db.get_project("/tmp/proj")
        self.assertIsNotNone(got)
        self.assertEqual(got["id"], pid)
        self.assertEqual(got["language"], "python")
        self.assertEqual(got["category"], "backend")
        self.assertEqual(got["file_count"], 12)
        self.assertEqual(got["dependency_count"], 2)

    def test_json_columns_roundtrip(self):
        self.db.upsert_project(sample_project(frameworks=["react", "express"]))
        got = self.db.get_project("/tmp/example")
        self.assertEqual(got["frameworks"], ["react", "express"])
        self.assertEqual(got["markers"], ["requirements.txt"])

    def test_path_is_normalised(self):
        # A messy path and its clean form must resolve to the SAME row.
        self.db.upsert_project(sample_project(path="/tmp/foo/../foo"))
        self.assertIsNotNone(self.db.get_project("/tmp/foo"))

    def test_upsert_updates_existing_row(self):
        """The v0.4 completion criterion: a re-scan updates, never duplicates."""
        self.db.upsert_project(sample_project(path="/tmp/p", confidence=0.7))
        self.db.upsert_project(sample_project(path="/tmp/p", confidence=0.95,
                                              category="full stack"))
        projects = self.db.all_projects()
        self.assertEqual(len(projects), 1)               # not two rows
        self.assertEqual(projects[0]["confidence"], 0.95)  # refreshed
        self.assertEqual(projects[0]["category"], "full stack")

    def test_upsert_preserves_first_seen(self):
        pid = self.db.upsert_project(sample_project(path="/tmp/p"))
        first_seen = self.db.get_project("/tmp/p")["first_seen"]
        self.db.upsert_project(sample_project(path="/tmp/p", category="cli"))
        again = self.db.get_project("/tmp/p")
        self.assertEqual(again["first_seen"], first_seen)  # unchanged
        self.assertEqual(again["id"], pid)

    def test_missing_path_raises(self):
        with self.assertRaises(ValueError):
            self.db.upsert_project({"language": "python"})

    def test_get_unknown_project_returns_none(self):
        self.assertIsNone(self.db.get_project("/nope/not/here"))

    def test_symlink_bool_roundtrips(self):
        self.db.upsert_project(sample_project(is_symlink=True,
                                              symlink_target="/real/target"))
        got = self.db.get_project("/tmp/example")
        self.assertIs(got["is_symlink"], True)
        self.assertEqual(got["symlink_target"], "/real/target")


# --------------------------------------------------------------------------- #
# Dependencies
# --------------------------------------------------------------------------- #
class TestDependencies(DBTestCase):
    def test_save_and_read(self):
        pid = self.db.upsert_project(sample_project())
        self.db.save_dependencies(pid, ["flask", "requests"], ecosystem="python")
        self.assertEqual(
            sorted(d["name"] for d in self.db.get_dependencies(pid)),
            ["flask", "requests"],
        )

    def test_dependencies_appear_on_project(self):
        pid = self.db.upsert_project(sample_project())
        self.db.save_dependencies(pid, ["flask"], ecosystem="python")
        self.assertEqual(self.db.get_project("/tmp/example")["dependencies"], ["flask"])

    def test_replace_drops_removed_deps(self):
        pid = self.db.upsert_project(sample_project())
        self.db.save_dependencies(pid, ["flask", "requests"])
        self.db.save_dependencies(pid, ["flask"])  # requests dropped
        self.assertEqual([d["name"] for d in self.db.get_dependencies(pid)], ["flask"])

    def test_cascade_delete_removes_deps(self):
        pid = self.db.upsert_project(sample_project(path="/tmp/cascade"))
        self.db.save_dependencies(pid, ["flask"])
        self.db.delete_project("/tmp/cascade")
        # With the project gone, its deps must be gone too (FK cascade).
        leftover = self.db.con.execute(
            "SELECT COUNT(*) FROM dependencies WHERE project_id = ?", (pid,)
        ).fetchone()[0]
        self.assertEqual(leftover, 0)


# --------------------------------------------------------------------------- #
# Files
# --------------------------------------------------------------------------- #
class TestFiles(DBTestCase):
    def test_save_files_with_sizes(self):
        pid = self.db.upsert_project(sample_project())
        self.db.save_files(pid, [("/tmp/example/app.py", 100), ("/tmp/example/README.md", 50)])
        rows = self.db.con.execute(
            "SELECT path, extension, size_bytes FROM files WHERE project_id = ? ORDER BY path",
            (pid,),
        ).fetchall()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["extension"], ".md")
        self.assertEqual(rows[1]["size_bytes"], 100)

    def test_save_files_bare_paths(self):
        pid = self.db.upsert_project(sample_project())
        self.db.save_files(pid, ["/tmp/example/main.py"])
        row = self.db.con.execute(
            "SELECT extension, size_bytes FROM files WHERE project_id = ?", (pid,)
        ).fetchone()
        self.assertEqual(row["extension"], ".py")
        self.assertEqual(row["size_bytes"], 0)


# --------------------------------------------------------------------------- #
# Scans
# --------------------------------------------------------------------------- #
class TestScans(DBTestCase):
    def test_start_and_finish_scan(self):
        sid = self.db.start_scan("/home/me/Projects")
        self.db.finish_scan(sid, project_count=3, file_count=120, total_bytes=999)
        latest = self.db.latest_scan()
        self.assertEqual(latest["id"], sid)
        self.assertEqual(latest["project_count"], 3)
        self.assertIsNotNone(latest["finished_at"])

    def test_project_links_to_scan(self):
        sid = self.db.start_scan("/home/me/Projects")
        self.db.upsert_project(sample_project(path="/tmp/p"), scan_id=sid)
        self.assertEqual(self.db.get_project("/tmp/p")["last_scan_id"], sid)

    def test_latest_scan_none_when_empty(self):
        self.assertIsNone(self.db.latest_scan())


# --------------------------------------------------------------------------- #
# Search
# --------------------------------------------------------------------------- #
class TestSearch(DBTestCase):
    def _seed(self):
        self.db.upsert_project(sample_project(path="/a", language="python", category="backend"))
        self.db.upsert_project(sample_project(path="/b", language="javascript",
                                              category="frontend", frameworks=["react"]))
        self.db.upsert_project(sample_project(path="/c", language="python",
                                              category="cli", frameworks=["typer"]))

    def test_filter_by_language(self):
        self._seed()
        self.assertEqual(len(self.db.find_projects(language="python")), 2)

    def test_filter_by_category(self):
        self._seed()
        results = self.db.find_projects(category="frontend")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["path"], os.path.normpath(os.path.abspath("/b")))

    def test_filter_by_framework(self):
        self._seed()
        results = self.db.find_projects(framework="react")
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]["language"], "javascript")

    def test_combined_filters(self):
        self._seed()
        self.assertEqual(len(self.db.find_projects(language="python", category="cli")), 1)


# --------------------------------------------------------------------------- #
# Delete
# --------------------------------------------------------------------------- #
class TestDelete(DBTestCase):
    def test_delete_returns_true_when_present(self):
        self.db.upsert_project(sample_project(path="/tmp/gone"))
        self.assertTrue(self.db.delete_project("/tmp/gone"))
        self.assertIsNone(self.db.get_project("/tmp/gone"))

    def test_delete_returns_false_when_absent(self):
        self.assertFalse(self.db.delete_project("/never/existed"))


# --------------------------------------------------------------------------- #
# Persistence  (the headline v0.4 criterion: data survives restart)
# --------------------------------------------------------------------------- #
class TestPersistence(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mnemo_db_")
        self.db_path = os.path.join(self.tmp, "test.db")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_data_survives_reopen(self):
        db = db_manager.Database(self.db_path)
        pid = db.upsert_project(sample_project(path="/tmp/persist"))
        db.save_dependencies(pid, ["flask", "requests"], ecosystem="python")
        db.close()

        # Reopen the SAME file -> everything should still be there.
        db2 = db_manager.Database(self.db_path)
        got = db2.get_project("/tmp/persist")
        self.assertIsNotNone(got)
        self.assertEqual(got["language"], "python")
        self.assertEqual(sorted(got["dependencies"]), ["flask", "requests"])
        db2.close()

    def test_reopen_does_not_reset_schema_version(self):
        db_manager.Database(self.db_path).close()
        db2 = db_manager.Database(self.db_path)
        self.assertEqual(
            db2.con.execute("PRAGMA user_version").fetchone()[0],
            db_manager.SCHEMA_VERSION,
        )
        db2.close()

    def test_context_manager_closes(self):
        with db_manager.Database(self.db_path) as db:
            db.upsert_project(sample_project(path="/tmp/ctx"))
        # Connection should be closed after the block.
        self.assertIsNone(db.con)


# --------------------------------------------------------------------------- #
# Overrides / low-confidence review  (v0.5)
# --------------------------------------------------------------------------- #
class TestOverride(DBTestCase):
    def test_set_override_wins_and_locks_confidence(self):
        self.db.upsert_project(sample_project(path="/tmp/o", category="backend", confidence=0.5))
        self.db.set_override("/tmp/o", category="frontend", note="frontend still to build")
        got = self.db.get_project("/tmp/o")
        self.assertEqual(got["category"], "frontend")          # effective value wins
        self.assertEqual(got["auto"]["category"], "backend")   # original auto-detection kept
        self.assertTrue(got["user_confirmed"])
        self.assertEqual(got["confidence"], 1.0)               # locked at full confidence
        self.assertEqual(got["override_note"], "frontend still to build")

    def test_override_survives_rescan(self):
        self.db.upsert_project(sample_project(path="/tmp/o", category="backend", confidence=0.5))
        self.db.set_override("/tmp/o", category="frontend")
        # a re-scan re-upserts the auto-detection -> override must NOT be clobbered
        self.db.upsert_project(sample_project(path="/tmp/o", category="backend", confidence=0.55))
        got = self.db.get_project("/tmp/o")
        self.assertEqual(got["category"], "frontend")
        self.assertTrue(got["user_confirmed"])
        self.assertEqual(got["auto"]["category"], "backend")
        self.assertAlmostEqual(got["auto"]["confidence"], 0.55)

    def test_approve_locks_the_auto_guess(self):
        self.db.upsert_project(sample_project(path="/tmp/o", category="cli", confidence=0.4))
        self.db.approve("/tmp/o")
        got = self.db.get_project("/tmp/o")
        self.assertEqual(got["category"], "cli")   # guess unchanged
        self.assertEqual(got["confidence"], 1.0)   # but signed off
        self.assertTrue(got["user_confirmed"])

    def test_clear_override_reverts_to_auto(self):
        self.db.upsert_project(sample_project(path="/tmp/o", category="backend", confidence=0.5))
        self.db.set_override("/tmp/o", category="frontend")
        self.db.clear_override("/tmp/o")
        got = self.db.get_project("/tmp/o")
        self.assertEqual(got["category"], "backend")
        self.assertFalse(got["user_confirmed"])
        self.assertEqual(got["confidence"], 0.5)

    def test_low_confidence_filtering(self):
        self.db.upsert_project(sample_project(path="/tmp/lo", confidence=0.4))
        self.db.upsert_project(sample_project(path="/tmp/hi", confidence=0.95))
        pending = self.db.low_confidence_projects(0.6)
        self.assertEqual([p["path"] for p in pending],
                         [os.path.normpath(os.path.abspath("/tmp/lo"))])
        self.db.approve("/tmp/lo")  # confirmed -> drops out of the review list
        self.assertEqual(self.db.low_confidence_projects(0.6), [])

    def test_breakdown_roundtrips(self):
        rec = sample_project(path="/tmp/b")
        rec["breakdown"] = {"languages": {"python": 0.8, "html": 0.2}, "categories": {"backend": 1.0}}
        self.db.upsert_project(rec)
        got = self.db.get_project("/tmp/b")
        self.assertEqual(got["breakdown"]["languages"]["python"], 0.8)
        self.assertEqual(got["breakdown"]["categories"], {"backend": 1.0})


# --------------------------------------------------------------------------- #
# Schema migration  (v1 -> v2)
# --------------------------------------------------------------------------- #
class TestMigration(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mnemo_mig_")
        self.db_path = os.path.join(self.tmp, "old.db")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_v1_db_gains_v2_columns(self):
        # Hand-build a minimal v1 projects table and stamp it as version 1.
        con = sqlite3.connect(self.db_path)
        con.executescript(
            "CREATE TABLE projects (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "path TEXT UNIQUE, language TEXT, category TEXT, confidence REAL);"
        )
        con.execute("PRAGMA user_version = 1")
        con.commit()
        con.close()

        db = db_manager.Database(self.db_path)  # opening it should migrate all the way up
        try:
            cols = {r["name"] for r in db.con.execute("PRAGMA table_info(projects)")}
            self.assertIn("breakdown", cols)
            self.assertIn("override_category", cols)
            self.assertIn("user_confirmed", cols)
            self.assertIn("reclaimable_bytes", cols)  # v3
            tables = {r["name"] for r in db.con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertIn("marks", tables)            # v3
            self.assertEqual(
                db.con.execute("PRAGMA user_version").fetchone()[0],
                db_manager.SCHEMA_VERSION,
            )
        finally:
            db.close()

    def test_v2_db_gains_v3_marks(self):
        # A v2 DB (breakdown/override columns present, but no marks) should gain the v3 pieces.
        con = sqlite3.connect(self.db_path)
        con.executescript(
            "CREATE TABLE projects (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "path TEXT UNIQUE, language TEXT, category TEXT, confidence REAL, "
            "breakdown TEXT, override_category TEXT, user_confirmed INTEGER DEFAULT 0);"
        )
        con.execute("PRAGMA user_version = 2")
        con.commit()
        con.close()

        db = db_manager.Database(self.db_path)  # opening it should migrate v2 -> v3
        try:
            cols = {r["name"] for r in db.con.execute("PRAGMA table_info(projects)")}
            self.assertIn("reclaimable_bytes", cols)
            tables = {r["name"] for r in db.con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertIn("marks", tables)
        finally:
            db.close()

    def test_v3_db_gains_v4_version_spec(self):
        # A v3 DB (dependencies table present, but no version_spec column) should gain it.
        con = sqlite3.connect(self.db_path)
        con.executescript(
            "CREATE TABLE projects (id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT UNIQUE);"
            "CREATE TABLE dependencies (id INTEGER PRIMARY KEY AUTOINCREMENT, "
            "project_id INTEGER, name TEXT, ecosystem TEXT, UNIQUE(project_id, name));"
        )
        con.execute("PRAGMA user_version = 3")
        con.commit()
        con.close()

        db = db_manager.Database(self.db_path)  # opening it should migrate v3 -> v4
        try:
            cols = {r["name"] for r in db.con.execute("PRAGMA table_info(dependencies)")}
            self.assertIn("version_spec", cols)
        finally:
            db.close()

    def test_v4_db_gains_v5_security_table(self):
        # A v4 DB (no security_findings table) should gain it.
        con = sqlite3.connect(self.db_path)
        con.executescript(
            "CREATE TABLE projects (id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT UNIQUE);"
        )
        con.execute("PRAGMA user_version = 4")
        con.commit()
        con.close()

        db = db_manager.Database(self.db_path)  # opening it should migrate v4 -> v5
        try:
            tables = {r["name"] for r in db.con.execute(
                "SELECT name FROM sqlite_master WHERE type='table'")}
            self.assertIn("security_findings", tables)
        finally:
            db.close()


# --------------------------------------------------------------------------- #
# Marks: reclaimable / regenerable bloat (v0.5 Stage B)
# --------------------------------------------------------------------------- #
class TestMarks(DBTestCase):
    def _seed(self, path="/tmp/proj", reclaimable=0):
        return self.db.upsert_project(sample_project(path=path, reclaimable_bytes=reclaimable))

    def test_marks_table_exists(self):
        tables = {r["name"] for r in self.db.con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        self.assertIn("marks", tables)

    def test_save_and_get_marks(self):
        pid = self._seed()
        self.db.save_marks(pid, [
            {"kind": "dependencies", "name": "node_modules", "path": "/tmp/proj/node_modules",
             "size_bytes": 5000, "file_count": 120, "reason": "npm install"},
            {"kind": "build", "name": "dist", "path": "/tmp/proj/dist",
             "size_bytes": 200, "file_count": 3, "reason": "build output"},
        ])
        marks = self.db.get_marks(pid)
        self.assertEqual(len(marks), 2)
        self.assertEqual(marks[0]["name"], "node_modules")  # biggest first
        self.assertEqual(marks[0]["size_bytes"], 5000)

    def test_reclaimable_bytes_stored_on_project(self):
        self._seed(reclaimable=5200)
        p = self.db.get_project("/tmp/proj")
        self.assertEqual(p["reclaimable_bytes"], 5200)

    def test_save_marks_replaces_by_default(self):
        pid = self._seed()
        self.db.save_marks(pid, [{"name": "node_modules", "path": "/tmp/proj/node_modules", "size_bytes": 10}])
        self.db.save_marks(pid, [{"name": "venv", "path": "/tmp/proj/venv", "size_bytes": 20}])
        names = {m["name"] for m in self.db.get_marks(pid)}
        self.assertEqual(names, {"venv"})  # the node_modules mark was wiped

    def test_reclaimable_summary(self):
        p1 = self._seed(path="/tmp/a", reclaimable=5200)
        p2 = self._seed(path="/tmp/b", reclaimable=300)
        self.db.save_marks(p1, [
            {"kind": "dependencies", "name": "node_modules", "path": "/tmp/a/node_modules", "size_bytes": 5000},
            {"kind": "build", "name": "dist", "path": "/tmp/a/dist", "size_bytes": 200},
        ])
        self.db.save_marks(p2, [
            {"kind": "cache", "name": "__pycache__", "path": "/tmp/b/__pycache__", "size_bytes": 300},
        ])
        summary = self.db.reclaimable_summary()
        self.assertEqual(summary["total_bytes"], 5500)
        self.assertEqual(summary["by_kind"]["dependencies"]["bytes"], 5000)
        self.assertEqual(summary["by_kind"]["cache"]["count"], 1)
        self.assertEqual(summary["top_projects"][0]["path"], "/tmp/a")  # heaviest first

    def test_marks_cascade_delete(self):
        pid = self._seed()
        self.db.save_marks(pid, [{"name": "node_modules", "path": "/tmp/proj/node_modules", "size_bytes": 10}])
        self.db.delete_project("/tmp/proj")
        self.assertEqual(self.db.get_marks(pid), [])


# --------------------------------------------------------------------------- #
# Cleanup recommendations (v0.6) - advisory only, never destructive
# --------------------------------------------------------------------------- #
class TestCleanupRecommendations(DBTestCase):
    def _seed_marks(self, path, marks):
        pid = self.db.upsert_project(sample_project(
            path=path, reclaimable_bytes=sum(m["size_bytes"] for m in marks)))
        self.db.save_marks(pid, marks)
        return pid

    def test_empty_when_no_marks(self):
        recs = self.db.cleanup_recommendations()
        self.assertEqual(recs["total_savings"], 0)
        self.assertEqual(recs["item_count"], 0)
        self.assertEqual(recs["items"], [])

    def test_itemised_recommendations_ranked_with_commands(self):
        self._seed_marks("/tmp/a", [
            {"kind": "dependencies", "name": "node_modules", "path": "/tmp/a/node_modules",
             "size_bytes": 5000, "file_count": 100, "reason": "npm install"},
            {"kind": "build", "name": "dist", "path": "/tmp/a/dist",
             "size_bytes": 200, "file_count": 4, "reason": "build output"},
        ])
        recs = self.db.cleanup_recommendations()
        self.assertEqual(recs["total_savings"], 5200)
        self.assertEqual(recs["item_count"], 2)
        first = recs["items"][0]
        self.assertEqual(first["name"], "node_modules")  # biggest first
        self.assertEqual(first["project_path"], "/tmp/a")
        self.assertEqual(first["command"], "rm -rf /tmp/a/node_modules")
        self.assertEqual(first["reason"], "npm install")
        self.assertEqual(recs["by_kind"]["dependencies"]["bytes"], 5000)

    def test_min_bytes_filters_small_dirs(self):
        self._seed_marks("/tmp/a", [
            {"kind": "dependencies", "name": "node_modules", "path": "/tmp/a/node_modules", "size_bytes": 5000},
            {"kind": "cache", "name": "__pycache__", "path": "/tmp/a/__pycache__", "size_bytes": 50},
        ])
        recs = self.db.cleanup_recommendations(min_bytes=1000)
        self.assertEqual(recs["item_count"], 1)
        self.assertEqual(recs["items"][0]["name"], "node_modules")

    def test_recommendations_are_non_destructive(self):
        # Generating recommendations must not touch the marks or the project row.
        self._seed_marks("/tmp/a", [
            {"kind": "build", "name": "target", "path": "/tmp/a/target", "size_bytes": 900},
        ])
        self.db.cleanup_recommendations()
        p = self.db.get_project("/tmp/a")
        self.assertEqual(p["reclaimable_bytes"], 900)
        self.assertEqual(len(self.db.get_marks(p["id"])), 1)


# --------------------------------------------------------------------------- #
# Dependency overlap - cross-project shared deps + rough env savings (uni-venv idea)
# --------------------------------------------------------------------------- #
class TestDependencyOverlap(DBTestCase):
    def _seed(self, path, deps, ecosystem, env_bytes=0, kind="virtualenv", name=".venv"):
        pid = self.db.upsert_project(sample_project(path=path, reclaimable_bytes=env_bytes))
        self.db.save_dependencies(pid, deps, ecosystem=ecosystem)
        if env_bytes:
            self.db.save_marks(pid, [{"kind": kind, "name": name,
                                      "path": f"{path}/{name}", "size_bytes": env_bytes}])
        return pid

    def test_empty_when_no_deps(self):
        o = self.db.dependency_overlap()
        self.assertEqual(o["total_instances"], 0)
        self.assertEqual(o["duplication_ratio"], 0.0)
        self.assertEqual(o["estimated_savings"], 0)
        self.assertEqual(o["shared"], [])

    def test_counts_distinct_and_duplicates(self):
        self._seed("/w/a", ["flask", "requests", "sqlalchemy"], "python")
        self._seed("/w/b", ["flask", "requests", "pandas"], "python")
        o = self.db.dependency_overlap()
        self.assertEqual(o["distinct_deps"], 4)       # flask, requests, sqlalchemy, pandas
        self.assertEqual(o["total_instances"], 6)     # 3 + 3
        self.assertEqual(o["duplicate_instances"], 2) # flask & requests each seen twice
        self.assertAlmostEqual(o["duplication_ratio"], 2 / 6)

    def test_shared_ranked_most_shared_first(self):
        self._seed("/w/a", ["flask", "requests"], "python")
        self._seed("/w/b", ["flask", "requests"], "python")
        self._seed("/w/c", ["flask"], "python")
        o = self.db.dependency_overlap()
        names = [d["name"] for d in o["shared"]]
        self.assertEqual(names[0], "flask")           # in 3 projects
        self.assertEqual(o["shared"][0]["project_count"], 3)
        self.assertEqual(o["shared"][0]["projects"], ["/w/a", "/w/b", "/w/c"])
        self.assertIn("requests", names)              # in 2 projects

    def test_min_projects_filters_singletons(self):
        self._seed("/w/a", ["flask", "lonelydep"], "python")
        self._seed("/w/b", ["flask"], "python")
        o = self.db.dependency_overlap(min_projects=2)
        self.assertEqual([d["name"] for d in o["shared"]], ["flask"])

    def test_same_name_different_ecosystem_not_merged(self):
        # "parser" in python and "parser" in javascript are distinct packages.
        self._seed("/w/py", ["parser"], "python")
        self._seed("/w/js", ["parser"], "javascript")
        o = self.db.dependency_overlap()
        self.assertEqual(o["distinct_deps"], 2)
        self.assertEqual(o["shared"], [])             # neither is shared across projects

    def test_estimated_savings_scales_env_bytes_by_duplication(self):
        # Only virtualenv + dependencies marks count toward the reclaimable pool.
        self._seed("/w/a", ["flask", "requests", "sqlalchemy"], "python", env_bytes=100)
        self._seed("/w/b", ["flask", "requests", "pandas"], "python", env_bytes=300)
        o = self.db.dependency_overlap()
        self.assertEqual(o["env_bytes"], 400)
        # ratio 2/6 * 400 == 133 (int-truncated)
        self.assertEqual(o["estimated_savings"], int(400 * (2 / 6)))

    def test_env_bytes_ignores_non_env_marks(self):
        # A build/cache mark is reclaimable but isn't the per-project dependency duplication a shared store would dedup, so it must not inflate env_bytes.
        self._seed("/w/a", ["flask"], "python", env_bytes=500, kind="build", name="dist")
        o = self.db.dependency_overlap()
        self.assertEqual(o["env_bytes"], 0)

    def test_by_ecosystem_breakdown(self):
        self._seed("/w/a", ["flask", "requests"], "python")
        self._seed("/w/b", ["react", "react-dom", "vite"], "javascript")
        o = self.db.dependency_overlap()
        self.assertEqual(o["by_ecosystem"]["javascript"]["distinct"], 3)
        self.assertEqual(o["by_ecosystem"]["python"]["projects"], 1)


# --------------------------------------------------------------------------- #
# Storage report - largest projects / files / dirs + workspace rollup (v0.4.3)
# --------------------------------------------------------------------------- #
class TestStorageReport(DBTestCase):
    def _seed_files(self, path, files, reclaimable=0):
        pid = self.db.upsert_project(sample_project(path=path, reclaimable_bytes=reclaimable))
        self.db.save_files(pid, files)
        return pid

    def test_empty_when_no_files(self):
        r = self.db.storage_report()
        self.assertEqual(r["total_files"], 0)
        self.assertEqual(r["total_bytes"], 0)
        self.assertEqual(r["largest_files"], [])

    def test_totals_dedupe_nested_files(self):
        self._seed_files("/w/a", [("/w/a/big.bin", 250), ("/w/a/app.py", 50)])
        self._seed_files("/w/b", [("/w/b/main.go", 80)])
        self._seed_files("/w/b/sub", [("/w/b/main.go", 80)])  # same file re-stored under a child project
        r = self.db.storage_report()
        self.assertEqual(r["total_files"], 3)   # the shared file counts once, not twice
        self.assertEqual(r["total_bytes"], 380)

    def test_largest_files_ranked(self):
        self._seed_files("/w/a", [("/w/a/big.bin", 250), ("/w/a/app.py", 50)])
        r = self.db.storage_report()
        self.assertEqual(r["largest_files"][0]["path"], "/w/a/big.bin")
        self.assertEqual(r["largest_files"][0]["size_bytes"], 250)

    def test_largest_projects_ranked_by_size(self):
        self.db.upsert_project(sample_project(path="/w/big",
            metrics={"size_bytes": 900, "file_count": 1, "dependency_count": 0}))
        self.db.upsert_project(sample_project(path="/w/small",
            metrics={"size_bytes": 10, "file_count": 1, "dependency_count": 0}))
        r = self.db.storage_report()
        self.assertEqual(r["largest_projects"][0]["path"], "/w/big")

    def test_largest_dirs_group_by_parent(self):
        self._seed_files("/w/a", [("/w/a/big.bin", 250), ("/w/a/app.py", 50)])
        top = self.db.storage_report()["largest_dirs"][0]
        self.assertEqual(top["path"], "/w/a")
        self.assertEqual(top["size_bytes"], 300)
        self.assertEqual(top["file_count"], 2)

    def test_limit_respected(self):
        for i in range(5):
            self._seed_files(f"/w/p{i}", [(f"/w/p{i}/f", i + 1)])
        self.assertEqual(len(self.db.storage_report(limit=2)["largest_files"]), 2)

    def test_reclaimable_rolled_up(self):
        self._seed_files("/w/a", [("/w/a/f", 10)], reclaimable=400)
        self._seed_files("/w/b", [("/w/b/f", 10)], reclaimable=100)
        self.assertEqual(self.db.storage_report()["reclaimable_bytes"], 500)


# --------------------------------------------------------------------------- #
# Dependency intelligence - version conflicts / shareable-venv check (v0.5)
# --------------------------------------------------------------------------- #
class TestDependencyIntel(DBTestCase):
    def _seed(self, path, specs, ecosystem="python"):
        pid = self.db.upsert_project(sample_project(path=path))
        self.db.save_dependencies(pid, list(specs), ecosystem=ecosystem, specs=specs)
        return pid

    def test_empty_when_under_min_projects(self):
        self._seed("/w/a", {"flask": "==2.0"})
        self.assertEqual(self.db.dependency_intel()["ecosystems"], {})

    def test_shareable_when_no_exact_conflict(self):
        self._seed("/w/a", {"flask": ">=2.0", "requests": ""})
        self._seed("/w/b", {"flask": ">=2.1", "requests": ""})
        py = self.db.dependency_intel()["ecosystems"]["python"]
        self.assertTrue(py["shareable"])
        self.assertEqual(py["conflicts"], [])
        self.assertEqual(py["shareable_projects"], ["/w/a", "/w/b"])

    def test_conflict_on_differing_exact_pins(self):
        self._seed("/w/a", {"flask": "==2.0"})
        self._seed("/w/b", {"flask": "==3.0"})
        py = self.db.dependency_intel()["ecosystems"]["python"]
        self.assertFalse(py["shareable"])
        self.assertEqual(py["conflicts"][0]["name"], "flask")
        self.assertEqual(set(py["conflicts"][0]["pins"]), {"2.0", "3.0"})
        self.assertEqual(py["conflicting_projects"], ["/w/a", "/w/b"])
        self.assertEqual(py["shareable_projects"], [])

    def test_same_exact_pin_is_not_a_conflict(self):
        self._seed("/w/a", {"flask": "==2.0"})
        self._seed("/w/b", {"flask": "==2.0"})
        self.assertTrue(self.db.dependency_intel()["ecosystems"]["python"]["shareable"])

    def test_range_specs_are_not_flagged(self):
        # Caret ranges aren't exact pins -> we don't claim a hard conflict (conservative).
        self._seed("/w/a", {"flask": "^2.0"})
        self._seed("/w/b", {"flask": "^3.0"})
        self.assertTrue(self.db.dependency_intel()["ecosystems"]["python"]["shareable"])

    def test_ecosystems_are_separated(self):
        self._seed("/w/a", {"flask": "==2.0"}, ecosystem="python")
        self._seed("/w/b", {"flask": "==3.0"}, ecosystem="python")
        self._seed("/w/js1", {"react": "==18"}, ecosystem="javascript")
        self._seed("/w/js2", {"react": "==18"}, ecosystem="javascript")
        ecos = self.db.dependency_intel()["ecosystems"]
        self.assertFalse(ecos["python"]["shareable"])
        self.assertTrue(ecos["javascript"]["shareable"])

    def test_conflict_isolates_the_shareable_remainder(self):
        self._seed("/w/a", {"flask": "==2.0"})
        self._seed("/w/b", {"flask": "==3.0"})
        self._seed("/w/c", {"click": "==8.0"})  # shares nothing conflicting
        py = self.db.dependency_intel()["ecosystems"]["python"]
        self.assertEqual(py["shareable_projects"], ["/w/c"])
        self.assertEqual(py["conflicting_projects"], ["/w/a", "/w/b"])


# --------------------------------------------------------------------------- #
# Security findings - MnemoScan secrets / vulns (v0.5)
# --------------------------------------------------------------------------- #
class TestSecurityFindings(DBTestCase):
    def _seed(self, path, findings):
        pid = self.db.upsert_project(sample_project(path=path))
        self.db.save_security_findings(pid, findings)
        return pid

    def test_save_and_get(self):
        pid = self._seed("/w/a", [
            {"kind": "secret", "rule": "AWS access key id", "severity": "high",
             "path": "/w/a/c.py", "line": 3, "detail": "AKIA****"},
        ])
        got = self.db.get_security_findings(pid)
        self.assertEqual(len(got), 1)
        self.assertEqual(got[0]["rule"], "AWS access key id")
        self.assertEqual(got[0]["detail"], "AKIA****")

    def test_summary_ordered_most_severe_first(self):
        self._seed("/w/a", [
            {"kind": "secret", "rule": "low one", "severity": "low", "path": "/w/a/x", "line": 1, "detail": "m"},
            {"kind": "secret", "rule": "high one", "severity": "high", "path": "/w/a/y", "line": 2, "detail": "m"},
        ])
        self.assertEqual(self.db.security_summary()["findings"][0]["severity"], "high")

    def test_summary_counts_by_severity_and_kind(self):
        self._seed("/w/a", [
            {"kind": "secret", "rule": "r1", "severity": "high", "path": "/w/a/x", "line": 1, "detail": "m"},
            {"kind": "secret", "rule": "r2", "severity": "low", "path": "/w/a/y", "line": 2, "detail": "m"},
        ])
        self._seed("/w/b", [
            {"kind": "vuln", "rule": "pkg CVE-1", "severity": "high",
             "path": "/w/b/requirements.txt", "line": 0, "detail": "bad"},
        ])
        s = self.db.security_summary()
        self.assertEqual(s["total"], 3)
        self.assertEqual(s["by_severity"]["high"], 2)
        self.assertEqual(s["by_kind"], {"secret": 2, "vuln": 1})

    def test_replace_wipes_previous(self):
        pid = self._seed("/w/a", [{"kind": "secret", "rule": "r1", "severity": "high",
                                   "path": "/w/a/x", "line": 1, "detail": "m"}])
        self.db.save_security_findings(pid, [{"kind": "secret", "rule": "r2", "severity": "low",
                                             "path": "/w/a/y", "line": 1, "detail": "m"}])
        self.assertEqual({f["rule"] for f in self.db.get_security_findings(pid)}, {"r2"})

    def test_cascade_delete(self):
        pid = self._seed("/w/a", [{"kind": "secret", "rule": "r1", "severity": "high",
                                   "path": "/w/a/x", "line": 1, "detail": "m"}])
        self.db.delete_project("/w/a")
        self.assertEqual(self.db.get_security_findings(pid), [])


if __name__ == "__main__":
    unittest.main()
