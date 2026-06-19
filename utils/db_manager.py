# Database manager for MnemoCetus ( implemented v0.4 - the MnemoIndex store).
#
# This is just the messenger between the schema.sql file and the project; 
# all the data is stored in schema.sql, but we interact with it through this file.

from datetime import datetime, timezone
import os
import json
import sqlite3

SCHEMA_VERSION = 1  # NOTE: Remember to bump this value with every new update
SCHEMA_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "schema.sql")
DEFAULT_DB_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "mnemocetus.db")


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


class Database:
    """
    Basically a thin wrapper around the SQLite file.

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
        Walk the DB forward one version at a time, it's a hook for future versions.

        Args:
            from_version (int): the current DB version.
        """
        self.con.execute(f"PRAGMA user_version = {SCHEMA_VERSION}")
        self.con.commit()
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
                    path (required), language, category, confidence, frameworks, markers, parent_path, role, is_symlink, symlink_target,
                    metrics{file_count, size_bytes, dependency_count}
            scan_id (int): the scan this sighting belongs to (optional).

        Returns:
            int: the project's id (new or existing).
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
            "file_count": metrics.get("file_count", 0),
            "size_bytes": metrics.get("size_bytes", 0),
            "dependency_count": metrics.get("dependency_count", 0),
            "parent_path": record.get("parent_path"),
            "role": record.get("role"),
            "is_symlink": 1 if record.get("is_symlink") else 0,
            "symlink_target": record.get("symlink_target"),
            "scan_id": scan_id,
            "now": now,
        }

        # ON CONFLICT(path): keep first_seen; refresh everything else. excluded.* is the row we just tried to insert.
        self.con.execute(
            """
            INSERT INTO projects (
                path, language, category, confidence, frameworks, markers, file_count, size_bytes, dependency_count, parent_path, role, is_symlink, symlink_target,
                first_seen, updated_at, last_scan_id
            ) VALUES (
                :path, :language, :category, :confidence, :frameworks, :markers,
                :file_count, :size_bytes, :dependency_count,
                :parent_path, :role, :is_symlink, :symlink_target,
                :now, :now, :scan_id
            )
            ON CONFLICT(path) DO UPDATE SET
                language         = excluded.language,
                category         = excluded.category,
                confidence       = excluded.confidence,
                frameworks       = excluded.frameworks,
                markers          = excluded.markers,
                file_count       = excluded.file_count,
                size_bytes       = excluded.size_bytes,
                dependency_count = excluded.dependency_count,
                parent_path      = excluded.parent_path,
                role             = excluded.role,
                is_symlink       = excluded.is_symlink,
                symlink_target   = excluded.symlink_target,
                updated_at       = excluded.updated_at,
                last_scan_id     = excluded.last_scan_id
            """,
            row,
        )
        self.con.commit()
        return self.con.execute(
            "SELECT id FROM projects WHERE path = ?", (path,)
        ).fetchone()[0]

    def save_dependencies(self, project_id, names, ecosystem=None, replace=True):
        """
        Store a project's dependency names. By default this REPLACES the project's existing deps so a re-scan reflects what's currently declared (drops removedones). 
        Set replace=False to only add.

        Args:
            project_id (int): which project these belong to.
            names (iterable): dependency names.
            ecosystem (str): python / javascript / rust / go (optional tag).
            replace (bool): wipe existing deps first (default True).
        """
        if replace:
            self.con.execute("DELETE FROM dependencies WHERE project_id = ?", (project_id,))
        self.con.executemany(
            "INSERT OR IGNORE INTO dependencies (project_id, name, ecosystem) VALUES (?, ?, ?)",
            [(project_id, n, ecosystem) for n in names],
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
    # ------------------------------------------------------------------------ #

    # -- Reads --------------------------------------------------------------- #
    def get_project(self, path):
        """
        Pull a single project back out by path, with its deps and frameworksre-inflated. 
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
            "SELECT name, ecosystem FROM dependencies WHERE project_id = ? ORDER BY name",
            (project_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def latest_scan(self):
        """The most recent scan row as a dict, or None if nothing's been scanned yet."""
        row = self.con.execute("SELECT * FROM scans ORDER BY id DESC LIMIT 1").fetchone()
        return dict(row) if row else None

    def _inflate_project(self, row):
        """Turn a raw projects row into a friendly dict (JSON columns -> lists, + deps)."""
        data = dict(row)
        data["frameworks"] = _loads(data.get("frameworks"))
        data["markers"] = _loads(data.get("markers"))
        data["is_symlink"] = bool(data.get("is_symlink"))
        data["dependencies"] = [d["name"] for d in self.get_dependencies(data["id"])]
        return data
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

    # Let the DB be used as a context manager: `with Database(...) as db:`
    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()
        return False
    # ------------------------------------------------------------------------ #
