"""
Regression tests for the v0.9.5 security hotfix: web request guard + XSS, quoted cleanup commands,
reclaimer content checks, arbiter redaction, hardened git calls, pip name validation.
"""

import os
import sys
import json
import shutil
import tempfile
import unittest
import subprocess
from unittest import mock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "utils"))

import arbiter  # noqa: E402
import gitinfo  # noqa: E402
import reclaimer  # noqa: E402
from db_tools import manager as db_manager  # noqa: E402

try:
    from web.app import create_app
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False

HAS_GIT = gitinfo.git_available()


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)


def _repo(path):
    os.makedirs(path, exist_ok=True)
    _git(path, "init", "-b", "main")
    _git(path, "config", "user.email", "t@example.com")
    _git(path, "config", "user.name", "Tester")
    _git(path, "config", "commit.gpgsign", "false")


def _record(path):
    return {"path": path, "language": "python", "category": "backend", "confidence": 0.9,
            "frameworks": [], "markers": [], "metrics": {"file_count": 1, "size_bytes": 1, "dependency_count": 0},
            "breakdown": {"languages": {"python": 1.0}, "categories": {"backend": 1.0}}}


@unittest.skipUnless(HAS_FLASK, "flask not installed")
class TestWebGuard(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mnemo_hard_")
        self.db_path = os.path.join(self.tmp, "w.db")
        db = db_manager.Database(self.db_path)
        db.upsert_project(_record("/tmp/keep"))
        db.upsert_project(_record("/tmp/Bob's app"))
        db.upsert_project(_record("/tmp/x'+alert(1)+'"))
        db.close()
        self.c = create_app(db_path=self.db_path).test_client()

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def _exists(self, path):
        db = db_manager.Database(self.db_path)
        try:
            return db.get_project(path) is not None
        finally:
            db.close()

    def test_foreign_host_rejected(self):  # DNS rebinding
        self.assertEqual(self.c.get("/", headers={"Host": "attacker.example"}).status_code, 403)
        self.assertEqual(self.c.get("/export?format=json", headers={"Host": "attacker.example:5000"}).status_code, 403)

    def test_local_hosts_allowed(self):
        for h in ("localhost", "127.0.0.1:5000", "[::1]:5000"):
            self.assertEqual(self.c.get("/", headers={"Host": h}).status_code, 200, h)

    def test_cross_site_post_rejected(self):  # CSRF
        r = self.c.post("/projects/delete", data={"path": "/tmp/keep"}, headers={"Origin": "https://evil.example"})
        self.assertEqual(r.status_code, 403)
        r = self.c.post("/projects/delete", data={"path": "/tmp/keep"}, headers={"Referer": "https://evil.example/x"})
        self.assertEqual(r.status_code, 403)
        self.assertTrue(self._exists("/tmp/keep"))

    def test_same_origin_post_allowed(self):
        r = self.c.post("/projects/delete", data={"path": "/tmp/keep"}, headers={"Origin": "http://127.0.0.1:5000"})
        self.assertEqual(r.status_code, 302)
        self.assertFalse(self._exists("/tmp/keep"))

    def test_open_redirect_blocked(self):
        for nxt in ("https://evil.example/", "//evil.example/", "/\\evil.example"):
            r = self.c.post("/projects/approve", data={"path": "/tmp/keep", "next": nxt})
            self.assertTrue(r.headers["Location"].endswith("/projects"), (nxt, r.headers["Location"]))
        r = self.c.post("/projects/approve", data={"path": "/tmp/keep", "next": "/projects?q=a"})
        self.assertTrue(r.headers["Location"].endswith("/projects?q=a"))

    def test_delete_confirm_is_js_safe(self):
        html = self.c.get("/projects").get_data(as_text=True)
        self.assertNotIn("confirm('Delete", html)  # old single-quoted form is gone
        # the JS string is JSON-encoded -> a quote in the path can't close it
        q = "%su0027" % chr(92)  # the JSON escape for a single quote
        self.assertIn("x" + q + "+alert(1)+" + q, html)
        self.assertIn("Bob" + q + "s app", html)
        self.assertNotIn("confirm(&#39;", html)


class TestQuotedCommand(unittest.TestCase):
    def test_path_with_spaces_is_quoted(self):
        tmp = tempfile.mkdtemp(prefix="mnemo_hard_")
        try:
            db = db_manager.Database(os.path.join(tmp, "q.db"))
            pid = db.upsert_project(_record("/w/My Proj"))
            db.save_marks(pid, [{"kind": "dependencies", "name": "node_modules", "path": "/w/My Proj/node_modules",
                                 "size_bytes": 10, "file_count": 1, "reason": "npm install"}])
            items = db.cleanup_recommendations()["items"]
            db.close()
            self.assertEqual(items[0]["command"], "rm -rf -- '/w/My Proj/node_modules'")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestReclaimGuard(unittest.TestCase):
    def setUp(self):
        self.ws = tempfile.mkdtemp(prefix="mnemo_hard_")
        self.proj = os.path.join(self.ws, "proj")
        os.makedirs(self.proj)

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def _mk(self, rel, content="x"):
        p = os.path.join(self.proj, rel)
        os.makedirs(os.path.dirname(p), exist_ok=True)
        with open(p, "w") as f:
            f.write(content)
        return p

    def test_ambiguous_marker_needs_manifest(self):
        self._mk("dist/index.js")
        ok, why = reclaimer._safe_to_delete(os.path.join(self.proj, "dist"), self.ws)
        self.assertFalse(ok)
        self.assertIn("manifest", why)
        self._mk("package.json", "{}")
        self.assertTrue(reclaimer._safe_to_delete(os.path.join(self.proj, "dist"), self.ws)[0])

    def test_nested_git_repo_refused(self):
        self._mk("node_modules/pkg/.git/HEAD", "ref: refs/heads/main")
        ok, why = reclaimer._safe_to_delete(os.path.join(self.proj, "node_modules"), self.ws)
        self.assertFalse(ok)
        self.assertIn("nested git", why)

    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_tracked_dir_refused_but_ignored_dir_allowed(self):
        _repo(self.proj)
        self._mk("package.json", "{}")
        self._mk("dist/action.js")            # committed build output (e.g. a GitHub Action)
        self._mk("node_modules/a/index.js")   # ignored, regenerable
        self._mk(".gitignore", "node_modules/\n")
        _git(self.proj, "add", "-A")
        _git(self.proj, "commit", "-m", "init")
        ok, why = reclaimer._safe_to_delete(os.path.join(self.proj, "dist"), self.ws)
        self.assertFalse(ok)
        self.assertIn("tracks", why)
        self.assertEqual(reclaimer._safe_to_delete(os.path.join(self.proj, "node_modules"), self.ws), (True, ""))

    def test_execute_reclaim_keeps_refused_dirs(self):
        self._mk("build/icon.png")  # no manifest -> hand-written assets
        r = reclaimer.execute_reclaim([{"path": os.path.join(self.proj, "build"), "size_bytes": 1}], self.ws)
        self.assertEqual(r["deleted"], [])
        self.assertTrue(os.path.isdir(os.path.join(self.proj, "build")))


class TestUniVenvNames(unittest.TestCase):
    def test_invalid_names_never_reach_pip(self):
        tmp = tempfile.mkdtemp(prefix="mnemo_hard_")
        calls = []

        def fake_run(cmd, **kw):
            calls.append(cmd)
            if "venv" in cmd:
                os.makedirs(os.path.join(cmd[-1], "bin"), exist_ok=True)
                open(os.path.join(cmd[-1], "bin", "pip"), "w").close()
            return subprocess.CompletedProcess(cmd, 0, "", "")
        try:
            with mock.patch.object(reclaimer.subprocess, "run", side_effect=fake_run):
                v = reclaimer.create_uni_venv(os.path.join(tmp, "uv"),
                                              ["requests", "-ihttps://evil/simple", "git+https://x/y", "-e", "flask"])
            pip_cmd = calls[-1]
            self.assertEqual(pip_cmd[1:], ["install", "--", "flask", "requests"])
            self.assertEqual(v["installed"], 2)
            self.assertIn("-ihttps://evil/simple", v["failed"])
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


class TestArbiterRedaction(unittest.TestCase):
    def test_empty_url_is_not_local(self):
        self.assertFalse(arbiter.is_local(""))
        self.assertFalse(arbiter.is_local(None))

    def test_blank_base_url_falls_back_to_cloud_and_redacts(self):
        cfg = {"enabled": True, "provider": "openai", "base_url": "", "model": "m", "api_key_env": ""}
        seen = {}
        with mock.patch.object(arbiter.OpenAICompatibleProvider, "classify",
                               lambda self, facts: seen.setdefault("facts", facts)):
            arbiter.classify_project({"path": "/home/me/secret-client/proj"}, cfg, workspace_root="/home/me")
        self.assertNotIn("/home/me", json.dumps(seen["facts"]))


class TestHardenedGit(unittest.TestCase):
    def test_git_command_neutralises_fsmonitor(self):
        cmd = gitinfo.git_command(["status"])
        self.assertIn("core.fsmonitor=false", cmd)
        self.assertEqual(gitinfo.git_env()["GIT_OPTIONAL_LOCKS"], "0")

    @unittest.skipUnless(HAS_GIT and os.name == "posix", "needs git on POSIX")
    def test_hostile_fsmonitor_does_not_run(self):
        tmp = tempfile.mkdtemp(prefix="mnemo_hard_")
        try:
            _repo(tmp)
            canary = os.path.join(tmp, "PWNED")
            _git(tmp, "config", "core.fsmonitor", f"touch {canary}; false")
            gitinfo.status(tmp)
            self.assertFalse(os.path.exists(canary))
        finally:
            shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
