"""
Test suite for the Flask web app (utils/web/app.py) - the v0.5 Stage D dashboard + DB viewer.

Uses Flask's test client (no real server).
Skips cleanly if flask isn't installed, so CI without the optional web dependency still passes.

    python -m unittest discover -s utils/tests        # from the repo root
"""

import os, sys, shutil, tempfile, unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "utils"))

try:
    import db_manager
    from web.app import create_app
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False


def _record(path, **overrides):
    rec = {
        "path": path, "language": "python", "category": "backend", "confidence": 0.9,
        "frameworks": ["flask"], "markers": ["requirements.txt"],
        "metrics": {"file_count": 3, "size_bytes": 100, "dependency_count": 1},
        "breakdown": {"languages": {"python": 1.0}, "categories": {"backend": 1.0}},
    }
    rec.update(overrides)
    return rec


@unittest.skipUnless(HAS_FLASK, "flask not installed")
class WebTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mnemo_web_")
        self.db_path = os.path.join(self.tmp, "web.db")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def seed(self, *records):
        db = db_manager.Database(self.db_path)
        try:
            for r in records:
                db.upsert_project(r)
        finally:
            db.close()

    def client(self):
        return create_app(db_path=self.db_path).test_client()

    def get_project(self, path):
        db = db_manager.Database(self.db_path)
        try:
            return db.get_project(path)
        finally:
            db.close()

    def seed_marks(self, path, marks):
        """Upsert a project carrying reclaimable bloat, and store its marks."""
        db = db_manager.Database(self.db_path)
        try:
            reclaimable = sum(m["size_bytes"] for m in marks)
            pid = db.upsert_project(_record(path, reclaimable_bytes=reclaimable))
            db.save_marks(pid, marks)
        finally:
            db.close()

    def seed_deps(self, path, deps, ecosystem="python", env_bytes=0):
        """Upsert a project with a dependency list (and optionally a venv/node_modules mark)."""
        db = db_manager.Database(self.db_path)
        try:
            pid = db.upsert_project(_record(path, reclaimable_bytes=env_bytes))
            db.save_dependencies(pid, deps, ecosystem=ecosystem)
            if env_bytes:
                db.save_marks(pid, [{"kind": "virtualenv", "name": ".venv",
                                     "path": f"{path}/.venv", "size_bytes": env_bytes}])
        finally:
            db.close()


class TestDashboard(WebTestCase):
    def test_dashboard_without_database(self):
        resp = self.client().get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"No projects yet", resp.data)

    def test_dashboard_with_projects(self):
        self.seed(_record("/tmp/a"), _record("/tmp/b", language="javascript", category="frontend"))
        resp = self.client().get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"projects", resp.data)
        self.assertIn(b"javascript", resp.data)
        self.assertIn(b"By category", resp.data)


class TestReclaimable(WebTestCase):
    def test_dashboard_shows_reclaimable_panel(self):
        self.seed_marks("/tmp/big", [
            {"kind": "dependencies", "name": "node_modules",
             "path": "/tmp/big/node_modules", "size_bytes": 4096, "file_count": 50},
        ])
        resp = self.client().get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Reclaimable space", resp.data)
        self.assertIn(b"dependencies", resp.data)  # the mark's kind row

    def test_dashboard_hides_panel_when_nothing_reclaimable(self):
        self.seed(_record("/tmp/clean"))  # no marks, reclaimable_bytes defaults to 0
        resp = self.client().get("/")
        self.assertNotIn(b"Reclaimable space", resp.data)


class TestCleanupView(WebTestCase):
    def test_cleanup_page_lists_recommendations(self):
        self.seed_marks("/tmp/big", [
            {"kind": "dependencies", "name": "node_modules",
             "path": "/tmp/big/node_modules", "size_bytes": 4096, "file_count": 50,
             "reason": "npm install"},
        ])
        resp = self.client().get("/cleanup")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Cleanup recommendations", resp.data)
        self.assertIn(b"rm -rf /tmp/big/node_modules", resp.data)  # suggested command shown

    def test_cleanup_min_filter(self):
        self.seed_marks("/tmp/big", [
            {"kind": "dependencies", "name": "node_modules",
             "path": "/tmp/big/node_modules", "size_bytes": 4096, "file_count": 50},
            {"kind": "cache", "name": "__pycache__",
             "path": "/tmp/big/__pycache__", "size_bytes": 50, "file_count": 2},
        ])
        # min=1 MB filters out the tiny __pycache__ but keeps... actually both are < 1MB here,
        # so nothing survives -> the empty-state copy shows.
        resp = self.client().get("/cleanup?min=1")
        self.assertIn(b"Nothing to recommend", resp.data)

    def test_cleanup_empty_state(self):
        self.seed(_record("/tmp/clean"))
        resp = self.client().get("/cleanup")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Nothing to recommend", resp.data)


class TestOverlapView(WebTestCase):
    def test_overlap_page_lists_shared_deps(self):
        self.seed_deps("/tmp/a", ["flask", "requests", "sqlalchemy"], env_bytes=100)
        self.seed_deps("/tmp/b", ["flask", "requests", "pandas"], env_bytes=300)
        resp = self.client().get("/overlap")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Dependency overlap", resp.data)
        self.assertIn(b"flask", resp.data)      # shared across both projects
        self.assertIn(b"requests", resp.data)

    def test_overlap_min_projects_filter(self):
        self.seed_deps("/tmp/a", ["flask", "lonelydep"])
        self.seed_deps("/tmp/b", ["flask"])
        # threshold 3 -> flask (in 2) no longer qualifies; the empty-shared copy shows.
        resp = self.client().get("/overlap?min=3")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"No dependency is shared", resp.data)

    def test_overlap_empty_state(self):
        self.seed(_record("/tmp/nodeps"))  # a project with no dependencies
        resp = self.client().get("/overlap")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"No dependencies recorded yet", resp.data)

    def test_overlap_shows_version_conflicts(self):
        db = db_manager.Database(self.db_path)
        try:
            a = db.upsert_project(_record("/w/a"))
            db.save_dependencies(a, ["flask"], ecosystem="python", specs={"flask": "==2.0"})
            b = db.upsert_project(_record("/w/b"))
            db.save_dependencies(b, ["flask"], ecosystem="python", specs={"flask": "==3.0"})
        finally:
            db.close()
        resp = self.client().get("/overlap")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Version compatibility", resp.data)   # the shareable-venv section
        self.assertIn(b"conflict on exact pins", resp.data)


class TestStorageView(WebTestCase):
    def _seed_files(self, path, files):
        db = db_manager.Database(self.db_path)
        try:
            pid = db.upsert_project(_record(path))
            db.save_files(pid, files)
        finally:
            db.close()

    def test_storage_page_lists_largest(self):
        self._seed_files("/w/a", [("/w/a/big.bin", 5000), ("/w/a/app.py", 50)])
        resp = self.client().get("/storage")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Storage analysis", resp.data)
        self.assertIn(b"/w/a/big.bin", resp.data)  # largest file shown

    def test_storage_empty_state(self):
        self.seed(_record("/w/nofiles"))  # a project with no stored file inventory
        resp = self.client().get("/storage")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"No file inventory recorded yet", resp.data)


class TestSecurityView(WebTestCase):
    def _seed_findings(self, path, findings):
        db = db_manager.Database(self.db_path)
        try:
            pid = db.upsert_project(_record(path))
            db.save_security_findings(pid, findings)
        finally:
            db.close()

    def test_security_page_lists_findings(self):
        self._seed_findings("/w/a", [
            {"kind": "secret", "rule": "AWS access key id", "severity": "high",
             "path": "/w/a/c.py", "line": 3, "detail": "AKIA****"},
        ])
        resp = self.client().get("/security")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"Security findings", resp.data)
        self.assertIn(b"AWS access key id", resp.data)
        self.assertIn(b"AKIA****", resp.data)          # masked value shown, not a raw secret

    def test_security_empty_state(self):
        self.seed(_record("/w/clean"))
        resp = self.client().get("/security")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"No security findings recorded", resp.data)


class TestProjectsViewer(WebTestCase):
    def test_lists_and_filters_by_language(self):
        self.seed(_record("/tmp/py"), _record("/tmp/js", language="javascript", category="frontend"))
        resp = self.client().get("/projects?language=python")
        self.assertEqual(resp.status_code, 200)
        self.assertIn(b"/tmp/py", resp.data)
        self.assertNotIn(b"/tmp/js", resp.data)

    def test_uncertain_filter(self):
        self.seed(_record("/tmp/sure", confidence=0.95),
                  _record("/tmp/unsure", confidence=0.4))
        resp = self.client().get("/projects?uncertain=1")
        self.assertIn(b"/tmp/unsure", resp.data)
        self.assertNotIn(b"/tmp/sure", resp.data)


class TestRecategorise(WebTestCase):
    def test_override_post_sets_category(self):
        self.seed(_record("/tmp/x", category="backend", confidence=0.5))
        resp = self.client().post("/projects/override",
                                  data={"path": "/tmp/x", "category": "frontend", "note": "fe pending"})
        self.assertEqual(resp.status_code, 302)  # redirect back
        got = self.get_project("/tmp/x")
        self.assertEqual(got["category"], "frontend")
        self.assertTrue(got["user_confirmed"])
        self.assertEqual(got["confidence"], 1.0)
        self.assertEqual(got["override_note"], "fe pending")

    def test_approve_post_locks_guess(self):
        self.seed(_record("/tmp/x", category="cli", confidence=0.4))
        self.client().post("/projects/approve", data={"path": "/tmp/x"})
        got = self.get_project("/tmp/x")
        self.assertEqual(got["category"], "cli")
        self.assertTrue(got["user_confirmed"])

    def test_delete_post_removes_project(self):
        self.seed(_record("/tmp/gone"))
        self.client().post("/projects/delete", data={"path": "/tmp/gone"})
        self.assertIsNone(self.get_project("/tmp/gone"))


if __name__ == "__main__":
    unittest.main()
