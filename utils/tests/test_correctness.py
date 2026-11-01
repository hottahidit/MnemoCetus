"""
Regression tests for the correctness pass (review items 7-14):
  7  unknown git state / failed history scan are never reported as "clean"
  8  incremental reuse can't serve stale or never-checked secret findings
  9  merge_from keeps git + change-detection state and per-dependency ecosystems
  10 a partial (web) override keeps the earlier override's other fields
  11 nested projects aren't double-counted (marks / findings / totals / git views)
  12 long menus don't crash questionary's 36-shortcut limit
  13 a '[' in a path can't crash rich output
  14 Ctrl-C cancels instead of acting
"""

import os
import sys
import time
import shutil
import tempfile
import unittest
import subprocess
from unittest import mock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "utils"))

import gitinfo  # noqa: E402
import insight  # noqa: E402
import security  # noqa: E402
import scanner  # noqa: E402
import utils  # noqa: E402
from db_tools import manager as db_manager  # noqa: E402

HAS_GIT = gitinfo.git_available()
AWS = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'


def _git(cwd, *args):
    subprocess.run(["git", *args], cwd=cwd, capture_output=True, text=True, check=True)


def _repo(path):
    os.makedirs(path, exist_ok=True)
    _git(path, "init", "-b", "main")
    _git(path, "config", "user.email", "t@example.com")
    _git(path, "config", "user.name", "Tester")
    _git(path, "config", "commit.gpgsign", "false")


def _write(path, text="x"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def _bump(path, seconds=5):
    """Push a path's mtime forward so a change is visible even on coarse-mtime filesystems."""
    t = time.time() + seconds
    os.utime(path, (t, t))


class TmpCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mnemo_corr_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def p(self, *parts):
        return os.path.join(self.tmp, *parts)


# --------------------------------------------------------------------------- #
# 7 - unknown is not clean
# --------------------------------------------------------------------------- #
class TestUnknownGitState(TmpCase):
    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_status_timeout_is_unknown_not_clean(self):
        _repo(self.p("r"))
        _write(self.p("r", "a.txt"))
        _git(self.p("r"), "add", "-A")
        _git(self.p("r"), "commit", "-m", "x")
        real = gitinfo._git

        def flaky(args, cwd, timeout=gitinfo._TIMEOUT):
            return None if args[:1] == ["status"] else real(args, cwd, timeout)
        with mock.patch.object(gitinfo, "_git", side_effect=flaky):
            info = gitinfo.status(self.p("r"))
        self.assertIsNone(info["dirty"])
        self.assertIsNone(gitinfo.change_signature(info["head"], info["dirty"], 123.0))  # never reused
        self.assertIn("unverified", gitinfo.at_risk(info))
        self.assertFalse(gitinfo.is_archivable(info, days=0))
        self.assertIn("?", gitinfo.badge(info))

    def test_unknown_dirty_is_stored_as_null(self):
        db = db_manager.Database(self.p("u.db"))
        try:
            db.upsert_project({"path": "/tmp/u", "git_head": "abc", "git_branch": "main", "git_dirty": None})
            row = db.get_project("/tmp/u")
            self.assertIsNone(row["git_dirty"])
            self.assertIn("?", gitinfo.badge_from_row(row))
            risky = insight.at_risk_projects(db)
            self.assertEqual(risky[0]["risks"][0], "unverified")
        finally:
            db.close()

    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_history_scan_failure_raises(self):
        _repo(self.p("r"))
        real = gitinfo._git

        def broken(args, cwd, timeout=gitinfo._TIMEOUT):
            return None if args[:1] == ["rev-list"] else real(args, cwd, timeout)
        with mock.patch.object(gitinfo, "_git", side_effect=broken):
            with self.assertRaises(security.HistoryScanError):
                security.scan_git_history(self.p("r"))

    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_history_stream_skips_huge_blob_and_stays_aligned(self):
        _repo(self.p("r"))
        # an oversized blob (skipped, streamed past) plus a small one with a secret (must still be found)
        _write(self.p("r", "big.txt"), AWS + "z" * (security.MAX_FILE_BYTES + 10))
        _write(self.p("r", "small.py"), AWS)
        _git(self.p("r"), "add", "-A")
        _git(self.p("r"), "commit", "-m", "x")
        hits = security.scan_git_history(self.p("r"))
        paths = {h["detail"].split("in git history: ")[1].rstrip(")") for h in hits}
        self.assertEqual(paths, {"small.py"})


# --------------------------------------------------------------------------- #
# 8 - incremental reuse
# --------------------------------------------------------------------------- #
class TestIncrementalSafety(TmpCase):
    def _scan(self, ws, db, baseline=None, security_on=True):
        scanner.persist_scan(ws, db_path=db, confirm_filters=True, security=security_on, baseline_db=baseline)
        d = db_manager.Database(db)
        try:
            return {p["path"]: d.get_security_findings(p["id"]) for p in d.all_projects()}
        finally:
            d.close()

    def _project(self):
        ws = self.p("ws")
        _write(os.path.join(ws, "app", "requirements.txt"), "flask\n")
        _write(os.path.join(ws, "app", "main.py"), "print(1)\n")
        return ws, os.path.join(ws, "app")

    def test_baseline_without_secret_scan_is_not_trusted(self):
        ws, app = self._project()
        _write(os.path.join(app, "config.py"), AWS)
        base = self.p("base.db")
        self._scan(ws, base, security_on=False)            # baseline: secrets NOT checked
        found = self._scan(ws, self.p("new.db"), baseline=base)
        self.assertTrue(found[app], "an unchecked baseline must not be reused as 'clean'")

    def test_hidden_env_edit_invalidates_reuse(self):
        ws, app = self._project()
        base = self.p("base.db")
        self._scan(ws, base)
        _write(os.path.join(app, ".env"), "GITHUB_TOKEN=ghp_" + "a" * 36 + "\n")
        _bump(os.path.join(app, ".env"))
        found = self._scan(ws, self.p("new.db"), baseline=base)
        self.assertTrue(any(f["path"].endswith(".env") for f in found[app]))

    def test_deleted_file_invalidates_reuse(self):
        ws, app = self._project()
        _write(os.path.join(app, "config.py"), AWS)
        base = self.p("base.db")
        self.assertTrue(self._scan(ws, base)[app])
        os.remove(os.path.join(app, "config.py"))
        _bump(app)  # the directory's mtime moves when an entry is removed
        self.assertEqual(self._scan(ws, self.p("new.db"), baseline=base)[app], [])

    @unittest.skipUnless(HAS_GIT, "git not installed")
    def test_gitignored_secret_in_clean_repo_is_found(self):
        ws, app = self._project()
        _repo(app)
        _write(os.path.join(app, ".gitignore"), ".env\n")
        _git(app, "add", "-A")
        _git(app, "commit", "-m", "init")
        base = self.p("base.db")
        self._scan(ws, base)
        _write(os.path.join(app, ".env"), "GITHUB_TOKEN=ghp_" + "b" * 36 + "\n")  # ignored -> repo stays clean
        _bump(os.path.join(app, ".env"))
        found = self._scan(ws, self.p("new.db"), baseline=base)
        self.assertTrue(any(f["path"].endswith(".env") for f in found[app]))


# --------------------------------------------------------------------------- #
# 9 / 10 - DB data loss
# --------------------------------------------------------------------------- #
class TestMergeAndOverride(TmpCase):
    def test_merge_keeps_git_state_and_ecosystems(self):
        src = db_manager.Database(self.p("src.db"))
        pid = src.upsert_project({"path": "/tmp/m", "git_head": "abc123", "git_branch": "main", "git_dirty": False,
                                  "git_ahead": 2, "git_last_commit": 1700000000, "content_mtime": 1700000001.5,
                                  "git_root": "/tmp", "security_scanned": True})
        src.save_dependencies(pid, ["flask"], ecosystem="python")
        src.save_dependencies(pid, ["react"], ecosystem="javascript", replace=False)
        src.close()
        dst = db_manager.Database(self.p("dst.db"))
        try:
            dst.merge_from(self.p("src.db"))
            row = dst.get_project("/tmp/m")
            for k, v in (("git_head", "abc123"), ("git_ahead", 2), ("git_last_commit", 1700000000),
                         ("content_mtime", 1700000001.5), ("git_root", "/tmp"), ("security_scanned", 1)):
                self.assertEqual(row[k], v, k)
            ecos = dict(dst.con.execute(
                "SELECT name, ecosystem FROM dependencies WHERE project_id = ?", (row["id"],)).fetchall())
            self.assertEqual(ecos, {"flask": "python", "react": "javascript"})
        finally:
            dst.close()

    def test_partial_override_keeps_earlier_fields(self):
        db = db_manager.Database(self.p("o.db"))
        try:
            db.upsert_project({"path": "/tmp/o", "category": "backend", "confidence": 0.4})
            db.set_override("/tmp/o", language="python", category="backend", frameworks=["flask"],
                            note="AI arbiter: looks like flask")
            db.set_override("/tmp/o", category="full stack", partial=True)  # what the web Save does
            row = db.get_project("/tmp/o")
            self.assertEqual(row["category"], "full stack")
            self.assertEqual(row["override_language"], "python")
            self.assertEqual(row["frameworks"], ["flask"])
            self.assertEqual(row["override_note"], "AI arbiter: looks like flask")
        finally:
            db.close()


# --------------------------------------------------------------------------- #
# 11 - nested projects
# --------------------------------------------------------------------------- #
class TestNestedNoDoubleCount(TmpCase):
    def test_parent_excludes_child_subtree(self):
        ws = self.p("ws")
        parent = os.path.join(ws, "mono")
        child = os.path.join(parent, "web")
        _write(os.path.join(parent, "requirements.txt"), "flask\n")
        _write(os.path.join(parent, "app.py"), "print(1)\n")
        _write(os.path.join(child, "package.json"), '{"dependencies": {"react": "18"}}')
        _write(os.path.join(child, "index.js"), "1\n")
        _write(os.path.join(child, "node_modules", "react", "index.js"), "x" * 100)
        _write(os.path.join(child, "secret.js"), AWS)
        db_path = self.p("n.db")
        scanner.persist_scan(ws, db_path=db_path, mode="CLASSIFY")
        db = db_manager.Database(db_path)
        try:
            rows = {p["path"]: p for p in db.all_projects()}
            self.assertIn(parent, rows)
            self.assertIn(child, rows)
            marks = db.con.execute("SELECT path FROM marks").fetchall()
            self.assertEqual(len(marks), 1, "node_modules must be marked once (by its own project)")
            secrets = db.con.execute("SELECT path FROM security_findings WHERE kind = 'secret'").fetchall()
            self.assertEqual(len(secrets), 1, "the child's secret must be reported once")
            self.assertEqual(db.reclaimable_summary()["total_bytes"],
                             rows[child]["reclaimable_bytes"])
        finally:
            db.close()

    def test_git_views_one_row_per_repo(self):
        db = db_manager.Database(self.p("g.db"))
        try:
            for path in ("/r", "/r/backend", "/r/frontend"):
                db.upsert_project({"path": path, "git_head": "abc", "git_branch": "main", "git_dirty": True,
                                   "git_root": "/r"})
            risky = insight.at_risk_projects(db)
            self.assertEqual(len(risky), 1)
            self.assertEqual(risky[0]["path"], "/r")
            self.assertEqual(risky[0]["projects"], 3)
            calls = []
            with mock.patch.object(gitinfo, "git_dir_size",
                                   side_effect=lambda p: calls.append(p) or {"reclaimable_estimate": 10 ** 9,
                                                                            "total_bytes": 2 * 10 ** 9}):
                gc = insight.git_gc_recommendations(db)
            self.assertEqual(calls, ["/r"])                       # measured once
            self.assertEqual(gc["total_reclaimable"], 10 ** 9)    # not summed 3x
        finally:
            db.close()


# --------------------------------------------------------------------------- #
# 12 / 13 / 14 - CLI robustness
# --------------------------------------------------------------------------- #
class TestCliRobustness(TmpCase):
    def test_long_menu_uses_filter_not_shortcuts(self):
        from cli_tools import ui
        with mock.patch.object(ui.questionary, "select") as sel:
            ui._menu("Model:", choices=[f"m{i}" for i in range(200)])
            kw = sel.call_args.kwargs
            self.assertFalse(kw["use_shortcuts"])
            self.assertTrue(kw["use_search_filter"])
            ui._menu("Short:", choices=["a", "b"])
            self.assertTrue(sel.call_args.kwargs["use_shortcuts"])

    def test_safe_print_survives_bad_markup(self):
        from rich.panel import Panel
        from rich.table import Table
        t = Table()
        t.add_column("p")
        t.add_row("/w/x[/]y")
        utils.safe_print("dir /w/a[/]b")   # would raise MarkupError with plain rich.print
        utils.safe_print(Panel("/w/[/]bad"))
        utils.safe_print(t)

    def test_review_category_cancel_does_not_confirm(self):
        from cli_tools import actions
        db_path = self.p("r.db")
        db = db_manager.Database(db_path)
        db.upsert_project({"path": "/tmp/low", "category": "backend", "confidence": 0.2,
                           "breakdown": {"languages": {}, "categories": {"backend": 1.0}}})
        db.close()
        answers = iter(["Set the real type", None, "Stop"])  # pick "set type", then Ctrl-C at Category
        with mock.patch.object(actions, "_menu", side_effect=lambda *a, **k: next(answers)), \
                mock.patch.object(actions.questionary, "text") as txt:
            txt.return_value.ask.return_value = "0.6"
            actions.do_review(db_path)
        db = db_manager.Database(db_path)
        try:
            self.assertFalse(db.get_project("/tmp/low")["user_confirmed"])
        finally:
            db.close()


if __name__ == "__main__":
    unittest.main()
