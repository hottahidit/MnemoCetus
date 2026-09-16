# Database manager for MnemoCetus ( implemented v0.4 - the MnemoIndex store).
#
# This is just the messenger between the schema.sql file and the project; all the data is stored in schema.sql, but we interact with it through this file.

from datetime import datetime, timezone
import os
import json
import sqlite3

from db_tools.analytics import AnalyticsMixin

SCHEMA_VERSION = 7  # NOTE: Remember to bump this value with every new update
# schema.sql sits next to this file inside db_tools/; the DB lives at the project root (two levels up from db_tools/).
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")
DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "mnemocetus.db")


def _now():
    """Current time as an ISO-8601 string (UTC) which we stamp rows with."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _json_or_none(value):
    """Dump a list/dict to a JSON string for storage, or None if there's nothing."""
    if not value:
        return None
    return json.dumps(value)


def _loads(value):
    """Reverse of _json_or_none; turn a stored JSON string back into a list (or [])."""
    if not value:
        return []
    try:
        return json.loads(value)
    except (ValueError, TypeError):
        return []


def _loads_breakdown(value):
    """Like _loads, but for the breakdown object (defaults to the empty {languages,categories} shape)."""
    if not value:
        return {"languages": {}, "categories": {}}
    try:
        data = json.loads(value)
        return data if isinstance(data, dict) else {"languages": {}, "categories": {}}
    except (ValueError, TypeError):
        return {"languages": {}, "categories": {}}


class Database(AnalyticsMixin):
    """
    A thin wrapper around the SQLite file.

    Open it, and it makes sure the schema exists (running schema.sql) and that the DB is migrated up to SCHEMA_VERSION.
    Every method here is a small, parametrised query -> no SQL strings get built from user input, so there's nothing to inject.
    """

    def __init__(self, db_path=DEFAULT_DB_PATH, schema_path=SCHEMA_PATH):
        """
        Args:
            db_path (str): where the .db file lives. Use ":memory:" for a throwaway in-memory DB (for tests).
            schema_path (str): the schema.sql to initialise from.
        """
        self.db_path = db_path
        self.schema_path = schema_path
        self.con = sqlite3.connect(db_path)
        self.con.row_factory = sqlite3.Row            # rows behave like dicts
        self.con.execute("PRAGMA foreign_keys = ON")  # per-connection; off by default
        self._initialise()

    # -- Setup / Migrations -------------------------------------------------- #
    def _initialise(self):
        """Create the tables if they're missing, then run any pending migrations."""
        version = self.con.execute("PRAGMA user_version").fetchone()[0]
        if version == 0:
            # Fresh database -> lay down the whole schema and stamp it as v1.
            with open(self.schema_path, "r", encoding="utf-8") as f:
                self.con.executescript(f.read())
            self.con.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
            self.con.commit()
        elif version < SCHEMA_VERSION:
            self._migrate(version)

    def _migrate(self, from_version):
        """
        Walk the DB forward one version at a time, then stamp the new version.

        Args:
            from_version (int): the current DB version.
        """
        if from_version < 2:
            self._migrate_to_v2()  # v0.5 recognition breakdown + user override columns
        if from_version < 3:
            self._migrate_to_v3()  # v0.5 Stage B reclaimable "marks"
        if from_version < 4:
            self._migrate_to_v4()  # v0.5 dependency version specs
        if from_version < 5:
            self._migrate_to_v5()  # v0.5 MnemoScan security findings
        if from_version < 6:
            self._migrate_to_v6()  # v0.7 covering index on files(path, size_bytes) for the storage rollup
        if from_version < 7:
            self._migrate_to_v7()  # v0.9 per-project git-awareness columns + content_mtime
        self.con.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self.con.commit()

    def _migrate_to_v2(self):
        """Add the v0.5 breakdown + override columns to an existing projects table (idempotent)."""
        existing = {r["name"] for r in self.con.execute("PRAGMA table_info(projects)")}
        additions = [
            ("breakdown", "TEXT"),
            ("override_language", "TEXT"),
            ("override_category", "TEXT"),
            ("override_frameworks", "TEXT"),
            ("override_note", "TEXT"),
            ("user_confirmed", "INTEGER DEFAULT 0"),
        ]
        for name, decl in additions:
            if name not in existing:
                self.con.execute(f"ALTER TABLE projects ADD COLUMN {name} {decl}")

    def _migrate_to_v3(self):
        """Add the reclaimable_bytes rollup column + the marks table to an existing DB (idempotent)."""
        existing = {r["name"] for r in self.con.execute("PRAGMA table_info(projects)")}
        if "reclaimable_bytes" not in existing:
            self.con.execute("ALTER TABLE projects ADD COLUMN reclaimable_bytes INTEGER DEFAULT 0")
        self.con.execute(
            """
            CREATE TABLE IF NOT EXISTS marks (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                kind        TEXT,
                name        TEXT,
                path        TEXT    NOT NULL,
                size_bytes  INTEGER DEFAULT 0,
                file_count  INTEGER DEFAULT 0,
                reason      TEXT,
                UNIQUE(project_id, path)
            )
            """
        )
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_marks_project ON marks(project_id)")

    def _migrate_to_v4(self):
        """Add the version_spec column to the dependencies table, if that table exists (idempotent)."""
        tables = {r["name"] for r in self.con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if "dependencies" not in tables:
            return  # a partial old DB with no dependencies table -> nothing to migrate
        existing = {r["name"] for r in self.con.execute("PRAGMA table_info(dependencies)")}
        if "version_spec" not in existing:
            self.con.execute("ALTER TABLE dependencies ADD COLUMN version_spec TEXT")

    def _migrate_to_v5(self):
        """Add the security_findings table + its index to an existing DB (idempotent)."""
        self.con.execute(
            """
            CREATE TABLE IF NOT EXISTS security_findings (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
                kind        TEXT,
                rule        TEXT,
                severity    TEXT,
                path        TEXT,
                line        INTEGER DEFAULT 0,
                detail      TEXT,
                UNIQUE(project_id, kind, rule, path, line)
            )
            """
        )
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_security_project ON security_findings(project_id)")

    def _migrate_to_v6(self):
        """Covering-index files(path, size_bytes) so the storage rollup's 'GROUP BY path' is served from the index (idempotent; skips a partial DB with no files table)."""
        tables = {r["name"] for r in self.con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if "files" not in tables:
            return  # a partial old DB with no files table -> nothing to index
        self.con.execute("CREATE INDEX IF NOT EXISTS idx_files_path ON files(path, size_bytes)")

    def _migrate_to_v7(self):
        """Add the per-project git-awareness columns + content_mtime (v0.9; idempotent; skips a partial DB with no projects table)."""
        tables = {r["name"] for r in self.con.execute(
            "SELECT name FROM sqlite_master WHERE type='table'")}
        if "projects" not in tables:
            return  # a partial old DB with no projects table -> nothing to alter
        existing = {r["name"] for r in self.con.execute("PRAGMA table_info(projects)")}
        for name, decl in (("git_branch", "TEXT"), ("git_head", "TEXT"),
                           ("git_dirty", "INTEGER DEFAULT 0"), ("git_ahead", "INTEGER DEFAULT 0"),
                           ("git_last_commit", "INTEGER"), ("content_mtime", "REAL")):
            if name not in existing:
                self.con.execute(f"ALTER TABLE projects ADD COLUMN {name} {decl}")
    # ------------------------------------------------------------------------ #

    # -- Scans --------------------------------------------------------------- #
    def start_scan(self, root_path):
        """
        Open a new scan row and return its id. Call finish_scan() once you've got the totals.

        Args:
            root_path (str): the directory this scan covers.

        Returns:
            int: the new scan's id.
        """
        cur = self.con.execute(
            "INSERT INTO scans (root_path, started_at) VALUES (?, ?)",
            (root_path, _now()),
        )
        self.con.commit()
        return cur.lastrowid

    def finish_scan(self, scan_id, project_count=0, file_count=0, total_bytes=0):
        """Close off a scan with its final tallies."""
        self.con.execute(
            "UPDATE scans SET finished_at = ?, project_count = ?, file_count = ?, "
            "total_bytes = ? WHERE id = ?",
            (_now(), project_count, file_count, total_bytes, scan_id),
        )
        self.con.commit()
    # ------------------------------------------------------------------------ #

    # -- Projects ------------------------------------------------------------ #
    def upsert_project(self, record, scan_id=None):
        """
        Insert a project, or update it in place if we've seen its path before.
        Makes "scans update existing records" true -> the UNIQUE(path) constraint turns a repeat insert into an update.

        Args:
            record (dict): a classifier result, optionally carrying relationship fields. 
                Recognised keys:
                    path (required), language, category, confidence, frameworks, markers, breakdown, parent_path, role, is_symlink, symlink_target,
                    metrics{file_count, size_bytes, dependency_count}
            scan_id (int): the scan this sighting belongs to (optional).

        Returns:
            int: the project's id (new or existing).

        Note: the user-override columns (override_*, user_confirmed) are deliberately NOT touched here, so a re-scan refreshes the auto-detection without ever clobbering the user's choices.
        """
        path = record.get("path")
        if not path:
            raise ValueError("upsert_project needs a 'path' in the record")
        path = os.path.normpath(os.path.abspath(path))
        metrics = record.get("metrics") or {}
        now = _now()

        row = {
            "path": path,
            "language": record.get("language"),
            "category": record.get("category"),
            "confidence": record.get("confidence", 0.0),
            "frameworks": _json_or_none(record.get("frameworks")),
            "markers": _json_or_none(record.get("markers")),
            "breakdown": _json_or_none(record.get("breakdown")),
            "file_count": metrics.get("file_count", 0),
            "size_bytes": metrics.get("size_bytes", 0),
            "dependency_count": metrics.get("dependency_count", 0),
            "parent_path": record.get("parent_path"),
            "role": record.get("role"),
            "is_symlink": 1 if record.get("is_symlink") else 0,
            "symlink_target": record.get("symlink_target"),
            "reclaimable_bytes": record.get("reclaimable_bytes", 0),
            "git_branch": record.get("git_branch"),
            "git_head": record.get("git_head"),
            "git_dirty": 1 if record.get("git_dirty") else 0,
            "git_ahead": record.get("git_ahead", 0) or 0,
            "git_last_commit": record.get("git_last_commit"),
            "content_mtime": record.get("content_mtime"),
            "scan_id": scan_id,
            "now": now,
        }

        # ON CONFLICT(path): keep first_seen; refresh everything else. excluded.* is the row we just tried to insert.
        self.con.execute(
            """
            INSERT INTO projects (
                path, language, category, confidence, frameworks, markers, breakdown, file_count, size_bytes, dependency_count, parent_path, role, is_symlink, symlink_target, reclaimable_bytes,
                git_branch, git_head, git_dirty, git_ahead, git_last_commit, content_mtime,
                first_seen, updated_at, last_scan_id
            ) VALUES (
                :path, :language, :category, :confidence, :frameworks, :markers, :breakdown,
                :file_count, :size_bytes, :dependency_count,
                :parent_path, :role, :is_symlink, :symlink_target, :reclaimable_bytes,
                :git_branch, :git_head, :git_dirty, :git_ahead, :git_last_commit, :content_mtime,
                :now, :now, :scan_id
            )
            ON CONFLICT(path) DO UPDATE SET
                language          = excluded.language,
                category          = excluded.category,
                confidence        = excluded.confidence,
                frameworks        = excluded.frameworks,
                markers           = excluded.markers,
                breakdown         = excluded.breakdown,
                file_count        = excluded.file_count,
                size_bytes        = excluded.size_bytes,
                dependency_count  = excluded.dependency_count,
                parent_path       = excluded.parent_path,
                role              = excluded.role,
                is_symlink        = excluded.is_symlink,
                symlink_target    = excluded.symlink_target,
                reclaimable_bytes = excluded.reclaimable_bytes,
                git_branch        = excluded.git_branch,
                git_head          = excluded.git_head,
                git_dirty         = excluded.git_dirty,
                git_ahead         = excluded.git_ahead,
                git_last_commit   = excluded.git_last_commit,
                content_mtime     = excluded.content_mtime,
                updated_at        = excluded.updated_at,
                last_scan_id      = excluded.last_scan_id
            """,
            row,
        )
        self.con.commit()
        return self.con.execute(
            "SELECT id FROM projects WHERE path = ?", (path,)
        ).fetchone()[0]

    def save_dependencies(self, project_id, names, ecosystem=None, specs=None, replace=True):
        """
        Store a project's dependency names (and their declared version specs).
        By default this REPLACES the project's existing deps so a re-scan reflects what's currently declared (drops removed ones).
        Set replace=False to only add.

        Args:
            project_id (int): which project these belong to.
            names (iterable): dependency names.
            ecosystem (str): python / javascript / rust / go (optional tag).
            specs (dict): optional {name: version_spec} -> the declared constraint per dep (e.g. "==2.0").
            replace (bool): wipe existing deps first (default True).
        """
        if replace:
            self.con.execute("DELETE FROM dependencies WHERE project_id = ?", (project_id,))
        specs = specs or {}
        self.con.executemany(
            "INSERT OR IGNORE INTO dependencies (project_id, name, ecosystem, version_spec) VALUES (?, ?, ?, ?)",
            [(project_id, n, ecosystem, specs.get(n) or None) for n in names],
        )
        self.con.commit()

    def save_files(self, project_id, files, replace=True):
        """
        Store a project's file inventory.

        Args:
            project_id (int): which project these belong to.
            files (iterable): each item is either a path string, or a (path, size_bytes) pair. Extension is derived from the path.
            replace (bool): wipe the existing inventory first (default True).
        """
        if replace:
            self.con.execute("DELETE FROM files WHERE project_id = ?", (project_id,))
        rows = []
        for item in files:
            if isinstance(item, (tuple, list)):
                path, size = item[0], (item[1] if len(item) > 1 else 0)
            else:
                path, size = item, 0
            ext = os.path.splitext(path)[1].lower() or None
            rows.append((project_id, path, ext, size))
        self.con.executemany(
            "INSERT OR IGNORE INTO files (project_id, path, extension, size_bytes) "
            "VALUES (?, ?, ?, ?)",
            rows,
        )
        self.con.commit()

    def save_marks(self, project_id, marks, replace=True):
        """
        Store a project's reclaimable "marks" (regenerable/bloat dirs like node_modules, venv, target).

        Args:
            project_id (int): which project these belong to.
            marks (iterable): each a dict {kind, name, path, size_bytes, file_count, reason}.
            replace (bool): wipe the project's existing marks first (default True), so a re-scan
                reflects what's currently on disk (drops ones the user has since cleaned up).
        """
        if replace:
            self.con.execute("DELETE FROM marks WHERE project_id = ?", (project_id,))
        self.con.executemany(
            "INSERT OR IGNORE INTO marks (project_id, kind, name, path, size_bytes, file_count, reason) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(project_id, m.get("kind"), m.get("name"), m["path"],
              m.get("size_bytes", 0), m.get("file_count", 0), m.get("reason")) for m in marks],
        )
        self.con.commit()

    def save_security_findings(self, project_id, findings, replace=True):
        """
        Store a project's MnemoScan security findings (secrets and/or dependency vulnerabilities).

        Args:
            project_id (int): which project these belong to.
            findings (iterable): each a dict {kind, rule, severity, path, line, detail}. For a secret, 'detail' must already be MASKED -> we never persist a raw secret.
            replace (bool): wipe the project's existing findings first (default True), so a re-scan reflects what's currently there.
        """
        if replace:
            self.con.execute("DELETE FROM security_findings WHERE project_id = ?", (project_id,))
        self.con.executemany(
            "INSERT OR IGNORE INTO security_findings (project_id, kind, rule, severity, path, line, detail) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            [(project_id, f.get("kind"), f.get("rule"), f.get("severity"),
              f.get("path"), f.get("line", 0), f.get("detail")) for f in findings],
        )
        self.con.commit()

    def merge_from(self, src_db_path, only_paths=None):
        """
        Merge projects from another database file into this one, upserting by path.

        Each project (optionally filtered to only_paths) is upserted -> existing rows refresh, new ones are added, nothing duplicates. Its dependencies, files, marks and security findings come across too, and afterwards relationships are recomputed so a project nested inside another saved project links up correctly.

        Args:
            src_db_path (str): the database to pull projects from (e.g. a temporary session db).
            only_paths (set | None): if given, only merge projects whose path is in this set.

        Returns:
            int: how many projects were merged.
        """
        src = Database(src_db_path)
        try:
            merged = 0
            for row in src.con.execute("SELECT * FROM projects").fetchall():
                if only_paths is not None and row["path"] not in only_paths:
                    continue
                src_pid = row["id"]
                pid = self.upsert_project({
                    "path": row["path"], "language": row["language"], "category": row["category"],
                    "confidence": row["confidence"],
                    "frameworks": _loads(row["frameworks"]), "markers": _loads(row["markers"]),
                    "breakdown": _loads_breakdown(row["breakdown"]),
                    "metrics": {"file_count": row["file_count"], "size_bytes": row["size_bytes"],
                                "dependency_count": row["dependency_count"]},
                    "parent_path": row["parent_path"], "role": row["role"],
                    "is_symlink": bool(row["is_symlink"]), "symlink_target": row["symlink_target"],
                    "reclaimable_bytes": row["reclaimable_bytes"],
                })
                deps = src.con.execute(
                    "SELECT name, ecosystem, version_spec FROM dependencies WHERE project_id = ?", (src_pid,)).fetchall()
                self.save_dependencies(pid, [d["name"] for d in deps],
                                       ecosystem=(deps[0]["ecosystem"] if deps else None),
                                       specs={d["name"]: d["version_spec"] for d in deps})
                self.save_files(pid, [(f["path"], f["size_bytes"]) for f in src.con.execute(
                    "SELECT path, size_bytes FROM files WHERE project_id = ?", (src_pid,))])
                self.save_marks(pid, [dict(m) for m in src.con.execute(
                    "SELECT kind, name, path, size_bytes, file_count, reason FROM marks WHERE project_id = ?", (src_pid,))])
                self.save_security_findings(pid, [dict(s) for s in src.con.execute(
                    "SELECT kind, rule, severity, path, line, detail FROM security_findings WHERE project_id = ?", (src_pid,))])
                if row["user_confirmed"]:  # carry the user's override across the merge
                    self.set_override(row["path"], language=row["override_language"],
                                      category=row["override_category"],
                                      frameworks=_loads(row["override_frameworks"]), note=row["override_note"])
                merged += 1
            self.recompute_relationships()
            return merged
        finally:
            src.close()

    def _nearest_ancestor_path(self, path, pathset):
        """The closest ancestor directory of 'path' that is itself a project path in 'pathset', or None."""
        parent = os.path.dirname(path)
        while parent and parent != os.path.dirname(parent):
            if parent in pathset:
                return parent
            parent = os.path.dirname(parent)
        return None

    def recompute_relationships(self):
        """
        Rebuild every project's parent_path / role from the paths currently in the database.

        A project physically nested inside another saved project becomes its child; everything else is a root. This keeps nesting consistent even when the two were saved from separate scans, so nothing breaks when one saved project sits inside another.
        """
        rows = self.con.execute("SELECT id, path FROM projects").fetchall()
        pathset = {r["path"] for r in rows}
        for r in rows:
            parent = self._nearest_ancestor_path(r["path"], pathset)
            self.con.execute("UPDATE projects SET parent_path = ?, role = ? WHERE id = ?",
                             (parent, "child" if parent else "root", r["id"]))
        self.con.commit()
    # ------------------------------------------------------------------------ #

    # -- Reads --------------------------------------------------------------- #
    def get_project(self, path):
        """
        Pull a single project back out by path, with its deps and frameworks re-inflated.
        Returns None if we've never indexed it.

        Args:
            path (str): the project path (gets abspath-normalised to match storage).

        Returns:
            dict | None: the project row plus 'frameworks', 'markers', 'dependencies'.
        """
        path = os.path.normpath(os.path.abspath(path))
        row = self.con.execute("SELECT * FROM projects WHERE path = ?", (path,)).fetchone()
        if row is None:
            return None
        return self._inflate_project(row)

    def all_projects(self):
        """Return every indexed project (each as a dict), ordered by path."""
        rows = self.con.execute("SELECT * FROM projects ORDER BY path").fetchall()
        return [self._inflate_project(r) for r in rows]

    def find_projects(self, language=None, category=None, framework=None):
        """
        Simple filtered search.

        Args:
            language (str): exact language match (optional).
            category (str): exact category match (optional).
            framework (str): matches if the project lists this framework (optional).

        Returns:
            list[dict]: matching projects.
        """
        clauses, params = [], []
        if language:
            clauses.append("language = ?")
            params.append(language)
        if category:
            clauses.append("category = ?")
            params.append(category)
        where = ("WHERE " + " AND ".join(clauses)) if clauses else ""
        rows = self.con.execute(f"SELECT * FROM projects {where} ORDER BY path", params).fetchall()
        projects = [self._inflate_project(r) for r in rows]
        if framework:
            projects = [p for p in projects if framework in p["frameworks"]]
        return projects

    def get_dependencies(self, project_id):
        """Return the dependency rows (as dicts) for a project."""
        rows = self.con.execute(
            "SELECT name, ecosystem, version_spec FROM dependencies WHERE project_id = ? ORDER BY name",
            (project_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_marks(self, project_id):
        """Return a project's reclaimable marks (as dicts), biggest first."""
        rows = self.con.execute(
            "SELECT kind, name, path, size_bytes, file_count, reason FROM marks "
            "WHERE project_id = ? ORDER BY size_bytes DESC",
            (project_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    _SEVERITY_ORDER = "CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 WHEN 'low' THEN 2 ELSE 3 END"

    def get_security_findings(self, project_id):
        """Return a project's security findings (as dicts), most severe first."""
        rows = self.con.execute(
            "SELECT kind, rule, severity, path, line, detail FROM security_findings "
            f"WHERE project_id = ? ORDER BY {self._SEVERITY_ORDER}, path, line",
            (project_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def latest_scan(self):
        """The most recent scan row as a dict, or None if nothing's been scanned yet."""
        row = self.con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def _inflate_project(self, row):
        """
        Turn a raw projects row into a friendly dict (JSON columns -> lists/objects, + deps).

        Also resolves the user override: 'language'/'category'/'frameworks'/'confidence' reflect
        the user's choice when they've confirmed one (locked at confidence 1.0), while the original
        auto-detection stays available under data['auto'].
        """
        data = dict(row)
        data["frameworks"] = _loads(data.get("frameworks"))
        data["markers"] = _loads(data.get("markers"))
        data["breakdown"] = _loads_breakdown(data.get("breakdown"))
        data["is_symlink"] = bool(data.get("is_symlink"))
        data["git_dirty"] = bool(data.get("git_dirty"))
        data["user_confirmed"] = bool(data.get("user_confirmed"))
        data["override_frameworks"] = _loads(data.get("override_frameworks"))
        data["dependencies"] = [d["name"] for d in self.get_dependencies(data["id"])]

        # Keep the raw auto-detection, then let a confirmed override win on the headline fields.
        data["auto"] = {
            "language": row["language"],
            "category": row["category"],
            "confidence": row["confidence"],
            "frameworks": data["frameworks"],
        }
        if data["user_confirmed"]:
            if data.get("override_language"):
                data["language"] = data["override_language"]
            if data.get("override_category"):
                data["category"] = data["override_category"]
            if data["override_frameworks"]:
                data["frameworks"] = data["override_frameworks"]
            data["confidence"] = 1.0  # the user signed off -> we're certain
        return data
    # ------------------------------------------------------------------------ #

    # -- Overrides / Review -------------------------------------------------- #
    def low_confidence_projects(self, threshold=0.6):
        """
        Projects the recogniser wasn't sure about and the user hasn't settled yet.

        Args:
            threshold (float): confidence below this counts as "uncertain".

        Returns:
            list[dict]: sub-threshold, not-yet-confirmed projects, lowest confidence first.
        """
        rows = self.con.execute(
            "SELECT * FROM projects WHERE confidence < ? AND COALESCE(user_confirmed, 0) = 0 "
            "ORDER BY confidence ASC, path",
            (threshold,),
        ).fetchall()
        return [self._inflate_project(r) for r in rows]

    def set_override(self, path, language=None, category=None, frameworks=None, note=None):
        """
        Record the user's call on what a project actually is, and lock it in (user_confirmed).

        Any field left None keeps the auto-detected value. Survives re-scans.

        Returns:
            bool: True if a project matched that path.
        """
        path = os.path.normpath(os.path.abspath(path))
        cur = self.con.execute(
            "UPDATE projects SET override_language = ?, override_category = ?, "
            "override_frameworks = ?, override_note = ?, user_confirmed = 1, updated_at = ? "
            "WHERE path = ?",
            (language, category, _json_or_none(frameworks), note, _now(), path),
        )
        self.con.commit()
        return cur.rowcount > 0

    def approve(self, path):
        """
        Accept the auto-detection as-is (lock it at full confidence, no field changes).
        This is what "Yes to all" does for each remaining low-confidence project.

        Returns:
            bool: True if a project matched that path.
        """
        path = os.path.normpath(os.path.abspath(path))
        cur = self.con.execute(
            "UPDATE projects SET user_confirmed = 1, updated_at = ? WHERE path = ?",
            (_now(), path),
        )
        self.con.commit()
        return cur.rowcount > 0

    def clear_override(self, path):
        """Drop a user override / confirmation so the project falls back to auto-detection."""
        path = os.path.normpath(os.path.abspath(path))
        cur = self.con.execute(
            "UPDATE projects SET override_language = NULL, override_category = NULL, "
            "override_frameworks = NULL, override_note = NULL, user_confirmed = 0, updated_at = ? "
            "WHERE path = ?",
            (_now(), path),
        )
        self.con.commit()
        return cur.rowcount > 0
    # ------------------------------------------------------------------------ #

    # -- Deletes ------------------------------------------------------------- #
    def delete_project(self, path):
        """
        Remove a project by path (its deps and files cascade away too).

        Returns:
            bool: True if a row was deleted, False if there was nothing to delete.
        """
        path = os.path.normpath(os.path.abspath(path))
        cur = self.con.execute("DELETE FROM projects WHERE path = ?", (path,))
        self.con.commit()
        return cur.rowcount > 0
    # ------------------------------------------------------------------------ #

    # -- Lifecycle ----------------------------------------------------------- #
    def close(self):
        """Close the underlying connection. This is safe to call more than once."""
        if self.con is not None:
            self.con.close()
            self.con = None

    # Let the DB be used as a context manager: 'with Database(...) as db:'
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False
    # ------------------------------------------------------------------------ #
