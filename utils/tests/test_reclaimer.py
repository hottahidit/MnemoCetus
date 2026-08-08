"""
Tests for utils/reclaimer.py - the destructive MnemoClean execution half.

These lean on the safety guard: nothing outside the curated markers / the workspace, and never through a symlink.
"""

import os
import sys
import shutil
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "utils"))

import reclaimer  # noqa: E402


class ReclaimTestCase(unittest.TestCase):
    def setUp(self):
        self.ws = tempfile.mkdtemp(prefix="mnemo_rec_")
        self.proj = os.path.join(self.ws, "proj")
        os.makedirs(self.proj)

    def tearDown(self):
        shutil.rmtree(self.ws, ignore_errors=True)

    def _mk(self, name, size=10):
        p = os.path.join(self.proj, name)
        os.makedirs(p)
        with open(os.path.join(p, "x"), "w") as f:
            f.write("j" * size)
        return p


class TestSafeToDelete(ReclaimTestCase):
    def test_marker_dir_ok(self):
        self.assertEqual(reclaimer._safe_to_delete(self._mk("node_modules"), self.ws), (True, ""))

    def test_non_marker_refused(self):
        ok, reason = reclaimer._safe_to_delete(self._mk("src"), self.ws)
        self.assertFalse(ok)
        self.assertIn("recognised", reason)

    def test_symlink_refused(self):
        outside = tempfile.mkdtemp()
        try:
            link = os.path.join(self.proj, "venv")
            os.symlink(outside, link)
            ok, reason = reclaimer._safe_to_delete(link, self.ws)
            self.assertFalse(ok)
            self.assertIn("symlink", reason)
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_outside_workspace_refused(self):
        outside = tempfile.mkdtemp()
        try:
            nm = os.path.join(outside, "node_modules")
            os.makedirs(nm)
            ok, reason = reclaimer._safe_to_delete(nm, self.ws)
            self.assertFalse(ok)
            self.assertIn("outside", reason)
        finally:
            shutil.rmtree(outside, ignore_errors=True)

    def test_missing_dir_refused(self):
        ok, _ = reclaimer._safe_to_delete(os.path.join(self.proj, "gone"), self.ws)
        self.assertFalse(ok)

    def test_workspace_root_itself_refused(self):
        # A workspace whose own basename is a marker must not be deletable as its own root.
        root = tempfile.mkdtemp()
        marker_root = os.path.join(root, "node_modules")
        os.makedirs(marker_root)
        try:
            ok, reason = reclaimer._safe_to_delete(marker_root, marker_root)
            self.assertFalse(ok)
            self.assertIn("root", reason)
        finally:
            shutil.rmtree(root, ignore_errors=True)


class TestExecuteReclaim(ReclaimTestCase):
    def test_deletes_markers_only(self):
        self._mk("node_modules")
        self._mk("__pycache__")
        os.makedirs(os.path.join(self.proj, "src"))
        items = [{"path": os.path.join(self.proj, d), "size_bytes": 10}
                 for d in ("node_modules", "__pycache__", "src")]
        r = reclaimer.execute_reclaim(items, self.ws)
        self.assertEqual(len(r["deleted"]), 2)
        self.assertEqual(r["freed_bytes"], 20)
        self.assertEqual(len(r["skipped"]), 1)  # src refused
        self.assertTrue(os.path.isdir(os.path.join(self.proj, "src")))
        self.assertFalse(os.path.isdir(os.path.join(self.proj, "node_modules")))

    def test_symlink_target_survives(self):
        outside = tempfile.mkdtemp()
        try:
            with open(os.path.join(outside, "keep"), "w") as f:
                f.write("x")
            os.symlink(outside, os.path.join(self.proj, "venv"))
            r = reclaimer.execute_reclaim([{"path": os.path.join(self.proj, "venv"), "size_bytes": 1}], self.ws)
            self.assertEqual(r["deleted"], [])
            self.assertTrue(os.path.exists(os.path.join(outside, "keep")))  # never followed
        finally:
            shutil.rmtree(outside, ignore_errors=True)


class TestCreateUniVenv(unittest.TestCase):
    def test_creates_empty_venv(self):
        ws = tempfile.mkdtemp()
        try:
            v = reclaimer.create_uni_venv(os.path.join(ws, ".uni-venv"))  # no deps -> offline
            self.assertTrue(v["created"])
            self.assertTrue(any(os.path.exists(os.path.join(ws, ".uni-venv", "bin", b))
                                for b in ("python", "python3")))
        finally:
            shutil.rmtree(ws, ignore_errors=True)

    def test_refuses_nonempty_target(self):
        ws = tempfile.mkdtemp()
        try:
            target = os.path.join(ws, "existing")
            os.makedirs(target)
            with open(os.path.join(target, "keep"), "w") as f:
                f.write("x")
            v = reclaimer.create_uni_venv(target)
            self.assertFalse(v["created"])
            self.assertIn("exists", v["error"])
            self.assertTrue(os.path.exists(os.path.join(target, "keep")))  # left untouched
        finally:
            shutil.rmtree(ws, ignore_errors=True)


if __name__ == "__main__":
    unittest.main()
