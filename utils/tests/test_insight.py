"""Tests for the v0.9 insight layer (utils/insight.py) -> the "what changed" diff + at-risk flags."""

import os
import sys
import time
import tempfile
import subprocess
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "utils"))

from db_tools import manager as db_manager  # noqa: E402
import insight  # noqa: E402

DAY = 86400


def _rec(path, **o):
    r = {"path": path, "language": "python", "category": "cli", "confidence": 0.9,
         "metrics": {"file_count": 1, "size_bytes": 100, "dependency_count": 0}}
    r.update(o)
    return r


class TestDiff(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _db(self, name):
        db = db_manager.Database(os.path.join(self.tmp, name))
        db.start_scan(self.tmp)
        return db

    def test_new_removed_changed_grown(self):
        base = self._db("base.db")
        base.upsert_project(_rec("/w/keep", git_head="aaa"), 1)
        base.upsert_project(_rec("/w/gone", git_head="bbb"), 1)
        base.upsert_project(_rec("/w/grow", git_head="ccc", metrics={"file_count": 1, "size_bytes": 100, "dependency_count": 0}), 1)
        base.upsert_project(_rec("/w/moved", git_head="ddd"), 1)
        base.close()

        cur = self._db("cur.db")
        cur.upsert_project(_rec("/w/keep", git_head="aaa"), 1)                 # unchanged
        cur.upsert_project(_rec("/w/grow", git_head="ccc", metrics={"file_count": 5, "size_bytes": 900, "dependency_count": 0}), 1)  # grew
        cur.upsert_project(_rec("/w/moved", git_head="EEE"), 1)               # commit moved -> changed
        cur.upsert_project(_rec("/w/fresh", git_head="fff"), 1)              # new
        cur.close()

        with db_manager.Database(os.path.join(self.tmp, "cur.db")) as c, \
             db_manager.Database(os.path.join(self.tmp, "base.db")) as b:
            d = insight.diff_databases(c, b)

        self.assertEqual({e["path"] for e in d["new"]}, {"/w/fresh"})
        self.assertEqual({e["path"] for e in d["removed"]}, {"/w/gone"})
        self.assertIn("/w/moved", {e["path"] for e in d["changed"]})
        grew = {e["path"]: e["delta_bytes"] for e in d["grown"]}
        self.assertEqual(grew.get("/w/grow"), 800)
        self.assertNotIn("/w/keep", {e["path"] for e in d["changed"]})       # untouched -> not changed

    def test_summarise(self):
        d = {"new": [1, 2], "removed": [1], "changed": [], "grown": [1]}
        s = insight.summarise_diff(d)
        self.assertIn("+2 new", s)
        self.assertIn("-1 removed", s)
        self.assertIn("1 grew/shrank", s)
        self.assertEqual(insight.summarise_diff({"new": [], "removed": [], "changed": [], "grown": []}),
                         "no changes since the baseline")


class TestAtRisk(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def test_flags(self):
        now = 1_700_000_000
        db = db_manager.Database(os.path.join(self.tmp, "r.db"))
        db.start_scan(self.tmp)
        db.upsert_project(_rec("/w/clean", git_branch="main", git_head="a", git_dirty=False,
                               git_ahead=0, git_last_commit=now - 5 * DAY), 1)
        db.upsert_project(_rec("/w/dirty", git_branch="main", git_head="b", git_dirty=True,
                               git_ahead=0, git_last_commit=now - 5 * DAY), 1)
        db.upsert_project(_rec("/w/unpushed", git_branch="main", git_head="c", git_dirty=False,
                               git_ahead=3, git_last_commit=now - 5 * DAY), 1)
        db.upsert_project(_rec("/w/stale", git_branch="main", git_head="d", git_dirty=False,
                               git_ahead=0, git_last_commit=now - 300 * DAY), 1)
        db.upsert_project(_rec("/w/plain"), 1)  # not a repo -> ignored
        risks = {e["path"]: e["risks"] for e in insight.at_risk_projects(db, now=now)}
        db.close()
        self.assertNotIn("/w/clean", risks)
        self.assertNotIn("/w/plain", risks)
        self.assertEqual(risks["/w/dirty"], ["uncommitted"])
        self.assertEqual(risks["/w/unpushed"], ["unpushed"])
        self.assertEqual(risks["/w/stale"], ["stale"])


import gitinfo  # noqa: E402


@unittest.skipUnless(gitinfo.git_available(), "git not on PATH")
class TestGitGcRecommendations(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def _repo(self, name):
        d = os.path.join(self.tmp, name)
        os.makedirs(d)
        for a in (("init", "-b", "main"), ("config", "user.email", "t@t"),
                  ("config", "user.name", "T"), ("config", "commit.gpgsign", "false")):
            subprocess.run(["git", *a], cwd=d, capture_output=True, check=True)
        open(os.path.join(d, "f.txt"), "w").write("x\n")
        subprocess.run(["git", "add", "-A"], cwd=d, capture_output=True, check=True)
        subprocess.run(["git", "commit", "-m", "init"], cwd=d, capture_output=True, check=True)
        return d

    def test_lists_git_repos_by_reclaimable(self):
        repo = self._repo("repo")
        db = db_manager.Database(os.path.join(self.tmp, "r.db"))
        db.start_scan(self.tmp)
        db.upsert_project(_rec(repo, git_branch="main", git_head="abc"), 1)   # a git repo
        db.upsert_project(_rec(os.path.join(self.tmp, "plain")), 1)           # not a repo -> ignored
        recs = insight.git_gc_recommendations(db, min_bytes=0)               # min 0 -> include the fresh repo
        db.close()
        paths = {it["path"] for it in recs["items"]}
        self.assertIn(repo, paths)
        self.assertNotIn(os.path.join(self.tmp, "plain"), paths)
        self.assertGreaterEqual(recs["total_reclaimable"], 0)


if __name__ == "__main__":
    unittest.main()
