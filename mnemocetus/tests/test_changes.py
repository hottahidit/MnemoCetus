"""
Tests for the finished scan diff ("what changed since last save"): new / resolved security findings,
new reclaimable bloat, root scoping, and the CLI / web / export surfaces.
"""

import os
import sys
import json
import shutil
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_ROOT)

from mnemocetus import insight  # noqa: E402
from mnemocetus import report  # noqa: E402
from mnemocetus.db import manager as db_manager  # noqa: E402

try:
    from mnemocetus.web.app import create_app
    HAS_FLASK = True
except ImportError:
    HAS_FLASK = False


def _proj(db, path, scan_id=None, security=True, reclaimable=0, **extra):
    rec = {"path": path, "language": "python", "category": "backend", "confidence": 0.9,
           "metrics": {"file_count": 1, "size_bytes": extra.pop("size", 100), "dependency_count": 0},
           "security_scanned": security, "reclaimable_bytes": reclaimable}
    rec.update(extra)
    return db.upsert_project(rec, scan_id=scan_id)


def _secret(path, detail="AKIA************", line=3, rule="AWS access key id", severity="high"):
    return {"kind": "secret", "rule": rule, "severity": severity, "path": path, "line": line, "detail": detail}


def _mark(path, size=1000):
    return {"kind": "dependencies", "name": os.path.basename(path), "path": path, "size_bytes": size,
            "file_count": 1, "reason": "npm install"}


class ChangesCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="mnemo_chg_")
        self.base_path = os.path.join(self.tmp, "base.db")
        self.cur_path = os.path.join(self.tmp, "cur.db")
        self.base = db_manager.Database(self.base_path)
        self.cur = db_manager.Database(self.cur_path)
        self.scan = self.cur.start_scan("/w")

    def tearDown(self):
        self.base.close()
        self.cur.close()
        shutil.rmtree(self.tmp, ignore_errors=True)

    def diff(self, **kw):
        return insight.diff_databases(self.cur, self.base, **kw)


class TestFindingsDiff(ChangesCase):
    def test_new_and_resolved_findings(self):
        b = _proj(self.base, "/w/app")
        self.base.save_security_findings(b, [_secret("/w/app/old.py", detail="ghp_****")])
        c = _proj(self.cur, "/w/app", self.scan)
        self.cur.save_security_findings(c, [_secret("/w/app/config.py")])
        d = self.diff()
        self.assertEqual([f["path"] for f in d["new_findings"]], ["/w/app/config.py"])
        self.assertEqual([f["path"] for f in d["resolved_findings"]], ["/w/app/old.py"])

    def test_moved_line_is_not_new(self):
        b = _proj(self.base, "/w/app")
        self.base.save_security_findings(b, [_secret("/w/app/config.py", line=3)])
        c = _proj(self.cur, "/w/app", self.scan)
        self.cur.save_security_findings(c, [_secret("/w/app/config.py", line=40)])
        d = self.diff()
        self.assertEqual(d["new_findings"], [])
        self.assertEqual(d["resolved_findings"], [])

    def test_new_project_findings_count_as_new(self):
        c = _proj(self.cur, "/w/fresh", self.scan)
        self.cur.save_security_findings(c, [_secret("/w/fresh/.env")])
        d = self.diff()
        self.assertEqual(len(d["new_findings"]), 1)
        self.assertEqual([p["path"] for p in d["new"]], ["/w/fresh"])

    def test_unscanned_side_is_unchecked_not_new(self):
        _proj(self.base, "/w/app", security=False)  # baseline never ran the secret scan
        c = _proj(self.cur, "/w/app", self.scan)
        self.cur.save_security_findings(c, [_secret("/w/app/config.py")])
        d = self.diff()
        self.assertEqual(d["new_findings"], [])
        self.assertEqual(d["unchecked"], ["/w/app"])

    def test_most_severe_first(self):
        c = _proj(self.cur, "/w/app", self.scan)
        self.cur.save_security_findings(c, [_secret("/w/app/a", severity="low", rule="r1"),
                                            _secret("/w/app/b", severity="high", rule="r2")])
        self.assertEqual([f["severity"] for f in self.diff()["new_findings"]], ["high", "low"])


class TestBloatDiff(ChangesCase):
    def test_new_and_removed_bloat(self):
        b = _proj(self.base, "/w/app", reclaimable=500)
        self.base.save_marks(b, [_mark("/w/app/venv", 500)])
        c = _proj(self.cur, "/w/app", self.scan, reclaimable=3000)
        self.cur.save_marks(c, [_mark("/w/app/node_modules", 3000)])
        d = self.diff()
        self.assertEqual([m["path"] for m in d["new_bloat"]], ["/w/app/node_modules"])
        self.assertEqual([m["path"] for m in d["removed_bloat"]], ["/w/app/venv"])
        self.assertEqual(d["bloat_delta_bytes"], 2500)
        self.assertIn("new bloat", insight.summarise_diff(d))


class TestRootScope(ChangesCase):
    def test_projects_outside_the_scanned_root_are_not_removed(self):
        _proj(self.base, "/w/app")
        _proj(self.base, "/elsewhere/other")      # saved from a different scan
        _proj(self.cur, "/w/app", self.scan)
        d = self.diff()                            # root defaults to the current scan's root (/w)
        self.assertEqual(d["removed"], [])
        self.assertEqual(d["root"], "/w")

    def test_removed_inside_root(self):
        _proj(self.base, "/w/app")
        _proj(self.base, "/w/gone")
        _proj(self.cur, "/w/app", self.scan)
        self.assertEqual([p["path"] for p in self.diff()["removed"]], ["/w/gone"])

    def test_prefix_sibling_is_not_inside(self):
        _proj(self.base, "/w2/app")               # '/w2' must not count as under '/w'
        _proj(self.cur, "/w/app", self.scan)
        self.assertEqual(self.diff()["removed"], [])


class TestReportSection(ChangesCase):
    def test_report_has_changes_only_with_a_baseline(self):
        c = _proj(self.cur, "/w/app", self.scan)
        self.cur.save_security_findings(c, [_secret("/w/app/config.py")])
        self.assertIsNone(report.build_report(self.cur_path)["changes"])
        self.assertIsNone(report.build_report(self.cur_path, baseline_db=self.cur_path)["changes"])  # same DB
        rep = report.build_report(self.cur_path, baseline_db=self.base_path)
        self.assertEqual(len(rep["changes"]["new_findings"]), 1)
        md = report.render_markdown(rep)
        self.assertIn("## Changes since last save", md)
        self.assertIn("### New security findings", md)
        json.loads(report.render_json(rep))  # stays serialisable


@unittest.skipUnless(HAS_FLASK, "flask not installed")
class TestChangesPage(ChangesCase):
    def test_page_lists_new_findings(self):
        c = _proj(self.cur, "/w/app", self.scan)
        self.cur.save_security_findings(c, [_secret("/w/app/config.py")])
        self.cur.con.commit()
        client = create_app(db_path=self.cur_path, baseline_db=self.base_path).test_client()
        html = client.get("/changes").get_data(as_text=True)
        self.assertIn("New security findings", html)
        self.assertIn("/w/app/config.py", html)
        self.assertIn(b"Changes since last save", client.get("/export?format=md").data)

    def test_page_explains_when_no_baseline(self):
        html = create_app(db_path=self.cur_path).test_client().get("/changes").get_data(as_text=True)
        self.assertIn("No saved (long-term) database", html)
        same = create_app(db_path=self.cur_path, baseline_db=self.cur_path).test_client()
        self.assertIn("viewing the saved database itself", same.get("/changes").get_data(as_text=True))


if __name__ == "__main__":
    unittest.main()
