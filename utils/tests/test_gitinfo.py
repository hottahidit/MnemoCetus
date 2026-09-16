"""
Tests for the v0.9 git-awareness layer (utils/gitinfo.py).

Two halves:
  - pure-logic tests on hand-built state dicts (is_stale / at_risk / is_archivable / change_key / badge)
  - integration tests that create real throwaway git repos and read them back through `git`.
"""

import os
import sys
import time
import shutil
import tempfile
import subprocess
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "utils"))

import gitinfo   # noqa: E402
import security  # noqa: E402
import reclaimer  # noqa: E402

NOW = 1_700_000_000  # fixed "now" for deterministic staleness tests
DAY = 86400


def _run_git(cwd, *args, when=None):
    env = dict(os.environ)
    if when is not None:
        env["GIT_AUTHOR_DATE"] = env["GIT_COMMITTER_DATE"] = when
    subprocess.run(["git", *args], cwd=cwd, env=env, capture_output=True, text=True, check=True)


def _make_repo(path, commit=True):
    os.makedirs(path, exist_ok=True)
    _run_git(path, "init", "-b", "main")
    _run_git(path, "config", "user.email", "t@example.com")
    _run_git(path, "config", "user.name", "Tester")
    _run_git(path, "config", "commit.gpgsign", "false")
    if commit:
        with open(os.path.join(path, "README.md"), "w") as f:
            f.write("# test\n")
        _run_git(path, "add", "-A")
        _run_git(path, "commit", "-m", "init")


# --------------------------------------------------------------------------- pure logic
class TestPureLogic(unittest.TestCase):
    def test_is_stale(self):
        self.assertTrue(gitinfo.is_stale({"last_commit_ts": NOW - 200 * DAY}, now=NOW))
        self.assertFalse(gitinfo.is_stale({"last_commit_ts": NOW - 10 * DAY}, now=NOW))
        self.assertFalse(gitinfo.is_stale({"last_commit_ts": None}, now=NOW))  # unknown -> not stale

    def test_at_risk(self):
        self.assertEqual(gitinfo.at_risk({"is_repo": False}), [])
        self.assertEqual(
            gitinfo.at_risk({"is_repo": True, "dirty": True, "has_remote": False}),
            ["uncommitted", "no-remote"])
        self.assertEqual(
            gitinfo.at_risk({"is_repo": True, "dirty": False, "has_remote": True,
                             "has_upstream": True, "ahead": 3}),
            ["unpushed"])
        self.assertEqual(
            gitinfo.at_risk({"is_repo": True, "dirty": False, "has_remote": True,
                             "has_upstream": True, "ahead": 0}),
            [])

    def test_is_archivable(self):
        safe = {"is_repo": True, "has_remote": True, "has_upstream": True, "dirty": False,
                "untracked": 0, "ahead": 0, "last_commit_ts": NOW - 300 * DAY}
        self.assertTrue(gitinfo.is_archivable(safe, now=NOW))
        self.assertFalse(gitinfo.is_archivable({**safe, "dirty": True}, now=NOW))          # local changes
        self.assertFalse(gitinfo.is_archivable({**safe, "ahead": 2}, now=NOW))             # unpushed
        self.assertFalse(gitinfo.is_archivable({**safe, "has_upstream": False}, now=NOW))  # not tracked
        self.assertFalse(gitinfo.is_archivable({**safe, "last_commit_ts": NOW}, now=NOW))  # not stale

    def test_change_key(self):
        self.assertIsNone(gitinfo.change_key({"is_repo": False}))
        self.assertEqual(gitinfo.change_key({"is_repo": True, "head": "abc", "dirty": False}),
                         ("abc", False))

    def test_badge(self):
        self.assertEqual(gitinfo.badge({"is_repo": False}), "")
        self.assertEqual(
            gitinfo.badge({"is_repo": True, "branch": "main", "dirty": False, "has_remote": True}),
            "⎇ main ✓")
        self.assertIn("(no remote)", gitinfo.badge({"is_repo": True, "branch": "main", "dirty": False}))
        b = gitinfo.badge({"is_repo": True, "branch": "feat", "dirty": True, "modified": 1,
                           "untracked": 1, "ahead": 3, "has_remote": True})
        self.assertIn("●2", b)
        self.assertIn("↑3", b)


# --------------------------------------------------------------------------- integration
@unittest.skipUnless(gitinfo.git_available(), "git not on PATH")
class TestRealRepos(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mc_git_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def test_not_a_repo(self):
        d = os.path.join(self.tmp, "plain")
        os.makedirs(d)
        self.assertEqual(gitinfo.status(d), {"is_repo": False})

    def test_clean_repo(self):
        d = os.path.join(self.tmp, "repo")
        _make_repo(d)
        s = gitinfo.status(d)
        self.assertTrue(s["is_repo"])
        self.assertTrue(s["is_root"])
        self.assertEqual(s["branch"], "main")
        self.assertIsNotNone(s["head"])
        self.assertFalse(s["dirty"])
        self.assertEqual(s["modified"], 0)
        self.assertEqual(s["untracked"], 0)
        self.assertFalse(s["has_remote"])
        self.assertFalse(s["has_upstream"])
        self.assertEqual((s["ahead"], s["behind"]), (0, 0))
        self.assertIsInstance(s["last_commit_ts"], int)
        self.assertEqual(gitinfo.change_key(s), (s["head"], False))

    def test_dirty_untracked_and_modified(self):
        d = os.path.join(self.tmp, "repo")
        _make_repo(d)
        # untracked file
        with open(os.path.join(d, "new.txt"), "w") as f:
            f.write("x\n")
        s = gitinfo.status(d)
        self.assertTrue(s["dirty"])
        self.assertEqual(s["untracked"], 1)
        # modify a tracked file too
        with open(os.path.join(d, "README.md"), "a") as f:
            f.write("more\n")
        s = gitinfo.status(d)
        self.assertGreaterEqual(s["modified"], 1)

    def test_git_dir_size(self):
        d = os.path.join(self.tmp, "repo")
        _make_repo(d)
        size = gitinfo.git_dir_size(d)
        self.assertIsNotNone(size)
        for k in ("total_bytes", "reclaimable_estimate", "loose_objects"):
            self.assertIn(k, size)
            self.assertGreaterEqual(size[k], 0)
        self.assertGreater(size["total_bytes"], 0)   # a repo with one commit holds objects

    def test_git_dir_size_none_for_non_repo(self):
        d = os.path.join(self.tmp, "plain")
        os.makedirs(d)
        self.assertIsNone(gitinfo.git_dir_size(d))

    def test_is_ignored(self):
        d = os.path.join(self.tmp, "repo")
        _make_repo(d)
        with open(os.path.join(d, ".gitignore"), "w") as f:
            f.write("*.log\n")
        self.assertTrue(gitinfo.is_ignored(d, "debug.log"))
        self.assertFalse(gitinfo.is_ignored(d, "README.md"))

    def test_env_exposure(self):
        d = os.path.join(self.tmp, "repo")
        _make_repo(d)
        open(os.path.join(d, ".env"), "w").write("SECRET=1\n")
        # not gitignored -> flagged
        f = security.check_env_exposure(d, True)
        self.assertEqual(len(f), 1)
        self.assertEqual(f[0]["rule"], "exposed dotenv")
        self.assertEqual(f[0]["severity"], "high")
        # once gitignored -> not flagged
        with open(os.path.join(d, ".gitignore"), "w") as fh:
            fh.write(".env\n")
        self.assertEqual(security.check_env_exposure(d, True), [])
        # non-repo -> nothing (risk is git-specific)
        self.assertEqual(security.check_env_exposure(d, False), [])

    def test_run_git_gc(self):
        d = os.path.join(self.tmp, "repo")
        _make_repo(d)
        res = reclaimer.run_git_gc([d])
        self.assertEqual(res["ran"], [d])
        self.assertEqual(res["failed"], [])
        self.assertGreaterEqual(res["freed_bytes"], 0)


if __name__ == "__main__":
    unittest.main()
