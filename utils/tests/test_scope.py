"""
Tests for the scan-scope / targeted-file-scan layer (utils/cli_tools/actions.py).

Covers the non-interactive core: enumerating scannable files (excludes honoured, hidden FILES kept,
special files skipped) and the display-only targeted file scan over a hand-picked, cross-folder set.
The questionary pickers themselves (_pick_tree / _pick_glob / _pick_paths) are interactive and not
unit-tested here.
"""

import os
import sys
import socket
import shutil
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "utils"))

from cli_tools import actions  # noqa: E402


def _touch(path, content=""):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as f:
        f.write(content)


class TestEnumerateScannable(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mnemo_scope_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def p(self, *parts):
        return os.path.join(self.tmp, *parts)

    def test_excludes_hidden_dirs_and_bloat_but_keeps_hidden_files(self):
        _touch(self.p("a", "settings.py"), "x=1\n")
        _touch(self.p("a", ".env.prod"), "SECRET=1\n")          # hidden FILE -> kept (secrets hide here)
        _touch(self.p("node_modules", "x", "junk.js"), "junk")  # excluded bloat
        _touch(self.p(".git", "config"), "[core]\n")            # hidden DIR -> pruned
        enum = actions._enumerate_scannable(self.tmp)
        self.assertIn(os.path.join("a", ".env.prod"), enum)
        self.assertIn(os.path.join("a", "settings.py"), enum)
        self.assertFalse(any("node_modules" in e for e in enum))
        self.assertFalse(any(".git" in e for e in enum))

    def test_skips_special_files(self):
        _touch(self.p("real.py"), "x=1\n")
        s = socket.socket(socket.AF_UNIX)
        try:
            s.bind(self.p("SingletonSocket"))
            os.mkfifo(self.p("pipe.fifo"))
            enum = actions._enumerate_scannable(self.tmp)
        finally:
            s.close()
        self.assertEqual(enum, ["real.py"])  # socket + FIFO never enumerated

    def test_cap_returns_none_when_too_many(self):
        for i in range(12):
            _touch(self.p(f"f{i}.txt"), "x")
        self.assertIsNone(actions._enumerate_scannable(self.tmp, cap=5))


class TestDoFileScan(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mnemo_fscan_")

    def tearDown(self):
        shutil.rmtree(self.tmp, ignore_errors=True)

    def p(self, *parts):
        return os.path.join(self.tmp, *parts)

    def test_cross_folder_secret_scan_display_only(self):
        _touch(self.p("a", ".env.prod"), 'AWS="AKIAIOSFODNN7EXAMPLE"\n')
        _touch(self.p("b", "keys.txt"), 'gh = "ghp_abcdefghijklmnopqrstuvwxyzABCDEFGHIJ"\n')
        _touch(self.p("b", "clean.md"), "nothing here\n")
        picked = [self.p("a", ".env.prod"), self.p("b", "keys.txt"), self.p("b", "clean.md")]
        # Smoke: runs without error over a cross-folder set and never writes a database.
        actions.do_file_scan(self.tmp, picked)
        self.assertFalse(any(f.endswith(".db") for f in os.listdir(self.tmp)),
                         "targeted scan must not persist a database")

    def test_skips_missing_and_special_files(self):
        _touch(self.p("real.py"), "x=1\n")
        s = socket.socket(socket.AF_UNIX)
        try:
            s.bind(self.p("sock"))
            picked = [self.p("real.py"), self.p("sock"), self.p("does_not_exist.py")]
            actions.do_file_scan(self.tmp, picked)  # must not raise or hang
        finally:
            s.close()


if __name__ == "__main__":
    unittest.main()
