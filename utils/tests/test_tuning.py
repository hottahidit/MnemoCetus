"""
Tests for scan auto-tuning (utils/tuning.py).

persist_scan is mocked so the timing is deterministic and no real scanning happens -> we're testing
autotune's logic (candidate sweep, picking the fastest, progress, cleanup), not the scanner itself.
"""

import os
import sys
import time
import tempfile
import unittest
from unittest import mock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "utils"))

import tuning        # noqa: E402
import scanner       # noqa: E402
import settings      # noqa: E402


class TestAutotune(unittest.TestCase):
    def test_picks_fastest_worker_count(self):
        # fake persist_scan: more workers -> faster, so the top candidate should win
        def fake(directory, db_path=None, security=True, workers=1, **k):
            time.sleep(0.004 / max(workers, 1))
            return 1, 0
        prog = []
        with mock.patch.object(scanner, "persist_scan", side_effect=fake):
            best, results = tuning.autotune(candidates=[1, 2, 4], repeats=1,
                                            probe_projects=2, probe_files=1,
                                            progress=lambda d, t: prog.append((d, t)))
        self.assertEqual([w for w, _ in results], [1, 2, 4])   # sorted by workers
        self.assertEqual(best, 4)                              # fastest per the fake timing
        self.assertEqual(prog[-1], (3, 3))                     # progress reached total (3 candidates x 1 repeat)

    def test_default_candidates_scale_and_are_sane(self):
        for cpu in (1, 2, 4, 24):
            c = tuning._candidates(cpu)
            self.assertTrue(all(isinstance(x, int) and x >= 1 for x in c), cpu)
            self.assertEqual(c, sorted(c), cpu)
            self.assertLessEqual(max(c), 16, cpu)
            self.assertGreaterEqual(len(c), 1, cpu)

    def test_probe_workspace_is_cleaned_up(self):
        seen = {}
        def fake(directory, db_path=None, security=True, workers=1, **k):
            seen["root"] = directory
            return 1, 0
        with mock.patch.object(scanner, "persist_scan", side_effect=fake):
            tuning.autotune(candidates=[1], repeats=1, probe_projects=1, probe_files=1)
        self.assertIn("root", seen)
        self.assertFalse(os.path.exists(seen["root"]))          # temp workspace removed


class TestSettingsScanWorkers(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self._orig = settings.SETTINGS_PATH
        settings.SETTINGS_PATH = os.path.join(self.tmp, ".mnemocetus.json")

    def tearDown(self):
        settings.SETTINGS_PATH = self._orig

    def test_default_is_zero(self):
        self.assertEqual(settings.load()["scan_workers"], 0)

    def test_round_trips(self):
        cfg = settings.load()
        cfg["scan_workers"] = 8
        self.assertTrue(settings.save(cfg))
        self.assertEqual(settings.load()["scan_workers"], 8)


if __name__ == "__main__":
    unittest.main()
