"""
Tests for the `nemc` command layer (mnemocetus.commands + mnemocetus.ops): scan / changes / rescan / status
(+ prompt light) / projects / secrets / db / reclaim / serve, exit codes, and clean --json stdout.
Every test points --db at a temp database, so the user's real one is never touched.
"""

import io
import os
import sys
import json
import time
import shutil
import tempfile
import unittest
import contextlib
from unittest import mock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_ROOT)

from mnemocetus import commands, ops  # noqa: E402

AWS = 'AWS_KEY = "AKIAIOSFODNN7EXAMPLE"\n'


def _write(path, text="x"):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(text)


def _bump(path, seconds=5):
    t = time.time() + seconds
    os.utime(path, (t, t))


class CmdCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mnemo_cmd_")
        self.db = os.path.join(self.tmp, "lt.db")
        self.ws = os.path.join(self.tmp, "ws")
        self.api = os.path.join(self.ws, "api")
        self.web = os.path.join(self.ws, "web")
        _write(os.path.join(self.api, "requirements.txt"), "flask\n")
        _write(os.path.join(self.api, "app.py"), "print(1)\n")
        _write(os.path.join(self.web, "package.json"), '{"dependencies": {"react": "18"}}')
        _write(os.path.join(self.web, "index.js"), "1\n")
        _write(os.path.join(self.web, "node_modules", "react", "i.js"), "y" * 50)

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def run_cmd(self, *argv):
        """Run `nemc --db <tmp> argv...` -> (exit code, stdout, stderr)."""
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = commands.main(["--db", self.db, *argv])
        return code, out.getvalue(), err.getvalue()

    def json_cmd(self, *argv):
        code, out, _ = self.run_cmd(*argv, "--json")
        return code, json.loads(out)  # stdout must be PURE json (diagnostics go to stderr)


class TestScanCommands(CmdCase):
    def test_scan_saves_and_records_the_root(self):
        code, res = self.json_cmd("scan", self.ws)
        self.assertEqual(code, 0)
        self.assertEqual(res["saved"], 2)
        self.assertIsNone(res["changes"])                       # first save -> nothing to compare
        self.assertEqual(ops.saved_roots(self.db), [self.ws])

    def test_changes_does_not_save_and_flags_new_findings(self):
        self.json_cmd("scan", self.ws)
        _write(os.path.join(self.api, "cfg.py"), AWS)
        code, res = self.json_cmd("changes", self.ws, "--fail-on-findings")
        self.assertEqual(code, commands.EXIT_FINDINGS)
        self.assertEqual(len(res["changes"]["new_findings"]), 1)
        self.assertIsNone(res["saved"])
        _, again = self.json_cmd("changes", self.ws)            # still "new": nothing was saved
        self.assertEqual(len(again["changes"]["new_findings"]), 1)

    def test_no_save(self):
        code, res = self.json_cmd("scan", self.ws, "--no-save")
        self.assertIsNone(res["saved"])
        self.assertFalse(os.path.exists(self.db))

    def test_rescan_and_prune(self):
        self.json_cmd("scan", self.ws)
        shutil.rmtree(self.web)
        code, results = self.json_cmd("rescan")
        self.assertEqual(code, 0)
        self.assertEqual([r["root"] for r in results], [self.ws])
        self.assertEqual(results[0]["pruned"], [self.web])
        _, projects = self.json_cmd("projects")
        self.assertEqual([p["path"] for p in projects], [self.api])

    def test_rescan_with_nothing_saved_is_an_error(self):
        code, _, err = self.run_cmd("rescan")
        self.assertEqual(code, commands.EXIT_ERROR)
        self.assertIn("nemc scan", err)

    def test_scan_missing_dir(self):
        code, _, err = self.run_cmd("scan", os.path.join(self.tmp, "nope"))
        self.assertEqual(code, commands.EXIT_ERROR)
        self.assertIn("not a directory", err)

    def test_saved_roots_keep_outermost_only(self):
        self.json_cmd("scan", self.api)
        self.json_cmd("scan", self.ws)
        self.assertEqual(ops.saved_roots(self.db), [self.ws])


class TestStatus(CmdCase):
    def setUp(self):
        super().setUp()
        self.json_cmd("scan", self.ws)

    def status(self, path, *extra):
        code, out, _ = self.run_cmd("status", path, "--exit-code", *extra)
        return code, out

    def test_clean_then_changed(self):
        self.assertEqual(self.status(self.api)[0], 0)
        _write(os.path.join(self.api, "app.py"), "print(2)\n")
        _bump(os.path.join(self.api, "app.py"))
        self.assertEqual(self.status(self.api)[0], 1)

    def test_deleted_file_is_a_change(self):
        os.remove(os.path.join(self.api, "app.py"))
        _bump(self.api)
        self.assertEqual(self.status(self.api)[0], 1)

    def test_child_project_change_does_not_dirty_parent(self):
        _write(os.path.join(self.ws, "requirements.txt"), "requests\n")  # make ws itself a project
        self.json_cmd("scan", self.ws)
        _write(os.path.join(self.api, "new.py"), "x\n")
        _bump(os.path.join(self.api, "new.py"))
        self.assertEqual(self.status(self.api)[0], 1)  # the child changed
        self.assertEqual(self.status(self.ws)[0], 0)   # the parent didn't

    def test_security_wins(self):
        _write(os.path.join(self.api, "cfg.py"), AWS)
        self.json_cmd("scan", self.ws)
        code, out = self.status(self.api)
        self.assertEqual(code, 2)
        self.assertIn("security", out)

    def test_unscanned(self):
        self.assertEqual(self.status(self.tmp)[0], 3)

    def test_subdirectory_resolves_to_its_project(self):
        os.makedirs(os.path.join(self.api, "pkg"))
        _, st = self.json_cmd("status", os.path.join(self.api, "pkg"))
        self.assertEqual(st["project"], self.api)

    def test_prompt_segments(self):
        _, out, err = self.run_cmd("status", self.api, "--prompt", "--shell", "zsh")
        self.assertEqual(out, "%F{green}●%f")
        self.assertEqual(err, "")
        _, out, _ = self.run_cmd("status", self.api, "--prompt", "--shell", "bash")
        self.assertEqual(out, "\001\033[32m\002●\001\033[0m\002")
        _, out, _ = self.run_cmd("status", self.tmp, "--prompt")
        self.assertEqual(out, "")  # unscanned -> no light at all

    def test_prompt_never_breaks_on_a_bad_db(self):
        out = io.StringIO()
        with contextlib.redirect_stdout(out), mock.patch.object(ops, "status", side_effect=RuntimeError("boom")):
            code = commands.main(["--db", self.db, "status", "--prompt"])
        self.assertEqual((code, out.getvalue()), (0, ""))

    def test_budget_exhausted_is_unknown(self):
        with mock.patch.object(ops.time, "monotonic", side_effect=[0.0] + [99.0] * 50):
            st = ops.status(self.api, db_path=self.db, budget=0.1)
        self.assertEqual(st["state"], ops.UNKNOWN)

    def test_new_commit_is_a_change(self):
        with mock.patch("mnemocetus.gitinfo._git", return_value="b" * 40):
            from mnemocetus.db import manager
            with manager.Database(self.db) as db:
                db.con.execute("UPDATE projects SET git_head = ?", ("a" * 40,))
                db.con.commit()
            st = ops.status(self.api, db_path=self.db)
        self.assertEqual(st["state"], ops.CHANGED)
        self.assertIn("commit", st["reason"])


class TestReadCommands(CmdCase):
    def setUp(self):
        super().setUp()
        _write(os.path.join(self.api, "cfg.py"), AWS)
        self.json_cmd("scan", self.ws)

    def test_projects_filters(self):
        _, js = self.json_cmd("projects", "--language", "javascript")
        self.assertEqual([p["path"] for p in js], [self.web])
        _, under = self.json_cmd("projects", "--under", self.api)
        self.assertEqual([p["path"] for p in under], [self.api])

    def test_secrets(self):
        code, f = self.json_cmd("secrets", "--fail-on-findings")
        self.assertEqual(code, commands.EXIT_FINDINGS)
        self.assertEqual([x["rule"] for x in f], ["AWS access key id"])
        _, none = self.json_cmd("secrets", self.web)
        self.assertEqual(none, [])

    def test_db_stats_path_and_report(self):
        _, stats = self.json_cmd("db")
        self.assertEqual(stats["projects"], 2)
        self.assertEqual(stats["security_findings"], 1)
        code, out, _ = self.run_cmd("db", "--path")
        self.assertEqual(out.strip(), self.db)
        out_file = os.path.join(self.tmp, "r.md")
        code, _, _ = self.run_cmd("db", "--report", "-o", out_file)
        with open(out_file) as fh:
            self.assertIn("# MnemoCetus workspace report", fh.read())

    def test_read_commands_need_a_db(self):
        os.remove(self.db)
        code, _, err = self.run_cmd("projects")
        self.assertEqual(code, commands.EXIT_ERROR)
        self.assertIn("nemc scan", err)


class TestReclaimCommand(CmdCase):
    def setUp(self):
        super().setUp()
        self.json_cmd("scan", self.ws)
        self.nm = os.path.join(self.web, "node_modules")

    def test_default_is_a_dry_run(self):
        code, plan = self.json_cmd("reclaim")
        self.assertEqual([i["path"] for i in plan["items"]], [self.nm])
        self.assertTrue(os.path.isdir(self.nm))

    def test_execute_needs_confirmation_when_not_interactive(self):
        with mock.patch.object(sys.stdin, "isatty", return_value=False):
            code, _, err = self.run_cmd("reclaim", "--execute")
        self.assertEqual(code, commands.EXIT_ERROR)
        self.assertTrue(os.path.isdir(self.nm))

    def test_execute_yes_deletes(self):
        code, res = self.json_cmd("reclaim", "--execute", "--yes")
        self.assertEqual(res["deleted"], [self.nm])
        self.assertFalse(os.path.exists(self.nm))

    def test_kind_filter(self):
        _, plan = self.json_cmd("reclaim", "--kind", "virtualenv")
        self.assertEqual(plan["items"], [])


class TestServeAndMenu(CmdCase):
    def test_serve_local_by_default(self):
        with mock.patch("werkzeug.serving.run_simple") as rs:
            code, out, err = self.run_cmd("serve", "-p", "5123")
        self.assertEqual(code, 0)
        host, port, app = rs.call_args.args[:3]
        self.assertEqual((host, port), ("127.0.0.1", 5123))
        self.assertEqual(app.config["ALLOWED_HOSTS"], {"localhost", "127.0.0.1", "::1"})
        self.assertEqual(err, "")

    def test_serve_on_network_warns_and_allows_its_names(self):
        with mock.patch("werkzeug.serving.run_simple") as rs:
            code, _, err = self.run_cmd("serve", "--host", "192.168.1.20", "--allow-host", "box.lan")
        app = rs.call_args.args[2]
        self.assertIn("192.168.1.20", app.config["ALLOWED_HOSTS"])
        self.assertIn("box.lan", app.config["ALLOWED_HOSTS"])
        self.assertIn("WARNING", err)

    def test_no_command_opens_the_menu(self):
        with mock.patch("mnemocetus.cli.menu.main") as menu:
            self.assertEqual(commands.main([]), 0)
        menu.assert_called_once()

    def test_entry_points_agree(self):
        from mnemocetus import __main__ as entry
        with mock.patch.object(commands, "main", return_value=7) as m:
            self.assertEqual(entry.main(["status"]), 7)
        m.assert_called_once_with(["status"])


if __name__ == "__main__":
    unittest.main()
