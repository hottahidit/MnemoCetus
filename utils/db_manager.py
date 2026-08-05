# Database manager for MnemoCetus ( implemented v0.4 - the MnemoIndex store).
#
# This is just the messenger between the schema.sql file and the project; all the data is stored in schema.sql, but we interact with it through this file.

from datetime import datetime, timezone
import os
import json
import sqlite3

SCHEMA_VERSION = 3  # NOTE: Remember to bump this value with every new update
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


def _loads_breakdown(value):
    """Like _loads, but for the breakdown object (defaults to the empty {languages,categories} shape)."""
    if not value:
        return {"languages": {}, "categories": {}}
    try:
        data = json.loads(value)
        return data if isinstance(data, dict) else {"languages": {}, "categories": {}}
    except (ValueError, TypeError):
        return {"languages": {}, "categories": {}}


class Database:
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
            "scan_id": scan_id,
            "now": now,
        }

        # ON CONFLICT(path): keep first_seen; refresh everything else. excluded.* is the row we just tried to insert.
        self.con.execute(
            """
            INSERT INTO projects (
                path, language, category, confidence, frameworks, markers, breakdown, file_count, size_bytes, dependency_count, parent_path, role, is_symlink, symlink_target, reclaimable_bytes,
                first_seen, updated_at, last_scan_id
            ) VALUES (
                :path, :language, :category, :confidence, :frameworks, :markers, :breakdown,
                :file_count, :size_bytes, :dependency_count,
                :parent_path, :role, :is_symlink, :symlink_target, :reclaimable_bytes,
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
                updated_at        = excluded.updated_at,
                last_scan_id      = excluded.last_scan_id
            """,
            row,
        )
        self.con.commit()
        return self.con.execute(
            "SELECT id FROM projects WHERE path = ?", (path,)
        ).fetchone()[0]

    def save_dependencies(self, project_id, names, ecosystem=None, replace=True):
        """
        Store a project's dependency names.
        By default this REPLACES the project's existing deps so a re-scan reflects what's currently declared (drops removed ones).
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
            "SELECT name, ecosystem FROM dependencies WHERE project_id = ? ORDER BY name",
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

    def reclaimable_summary(self):
        """
        Workspace-wide reclaimable-space rollup for the dashboard.

        Returns:
            dict: {
                total_bytes: int,                                  # everything the marks add up to
                by_kind: {kind: {bytes, count}}                    # grouped by dependencies/build/cache/... (bytes desc)
                top_projects: [ {path, reclaimable_bytes}, ... ]   # heaviest projects first
            }
        """
        by_kind = {}
        total = 0
        for r in self.con.execute(
            "SELECT kind, COUNT(*) AS count, COALESCE(SUM(size_bytes), 0) AS bytes "
            "FROM marks GROUP BY kind ORDER BY bytes DESC"
        ):
            kind = r["kind"] or "other"
            by_kind[kind] = {"bytes": r["bytes"], "count": r["count"]}
            total += r["bytes"]
        top = self.con.execute(
            "SELECT path, reclaimable_bytes FROM projects "
            "WHERE COALESCE(reclaimable_bytes, 0) > 0 ORDER BY reclaimable_bytes DESC LIMIT 10"
        ).fetchall()
        return {
            "total_bytes": total,
            "by_kind": by_kind,
            "top_projects": [dict(r) for r in top],
        }

    def cleanup_recommendations(self, min_bytes=0):
        """
        Turn the recorded reclaimable marks into an itemised list of safe cleanup suggestions -> the recommendations half of MnemoClean.

        This is purely advisory -> it computes what *could* be freed and how each item is regenerated;
        it NEVER deletes anything (v0.6 does recommendations only).

        Args:
            min_bytes (int): ignore marks smaller than this (default 0 -> include everything),
                so callers can hide trivially small dirs and focus on the wins.

        Returns:
            dict: {
                total_savings: int,                       # sum of the suggested items
                item_count: int,
                by_kind: {kind: {bytes, count}},          # savings grouped by kind (bytes desc)
                items: [ {                                # biggest saving first
                    project_path, path, name, kind, size_bytes, file_count,
                    reason,        # how it's regenerated, e.g. "npm / yarn / pnpm install"
                    command,       # the suggested (un-run) reclaim command
                }, ... ],
            }
        """
        rows = self.con.execute(
            "SELECT m.name, m.kind, m.path, m.size_bytes, m.file_count, m.reason, "
            "p.path AS project_path FROM marks m JOIN projects p ON p.id = m.project_id "
            "WHERE m.size_bytes >= ? ORDER BY m.size_bytes DESC",
            (min_bytes,),
        ).fetchall()
        items, by_kind, total = [], {}, 0
        for r in rows:
            total += r["size_bytes"]
            bk = by_kind.setdefault(r["kind"] or "other", {"bytes": 0, "count": 0})
            bk["bytes"] += r["size_bytes"]
            bk["count"] += 1
            items.append({
                "project_path": r["project_path"],
                "path": r["path"],
                "name": r["name"],
                "kind": r["kind"],
                "size_bytes": r["size_bytes"],
                "file_count": r["file_count"],
                "reason": r["reason"],
                "command": f"rm -rf {r['path']}",  # suggestion only -> we never run this
            })
        return {
            "total_savings": total,
            "item_count": len(items),
            "by_kind": dict(sorted(by_kind.items(), key=lambda kv: kv[1]["bytes"], reverse=True)),
            "items": items,
        }

    def dependency_overlap(self, min_projects=2):
        """
        Cross-project dependency analysis -> how much of the installed-env bloat is the SAME packages copied into project after project, and roughly how much a shared/hardlinked package store (uv, pnpm, or a common venv for compatible projects) could reclaim.

        This reads only the recorded dependency NAMES (we don't keep version constraints yet), so estimated_savings is a coarse proxy, not a promise: it scales the installed-env bytes (the virtualenv + dependencies marks -> venv / node_modules) by the share of package copies that are duplicates.
        Real dedup depends on versions actually matching.

        Args:
            min_projects (int): only list deps shared by at least this many projects (default 2).

        Returns:
            dict: {
                shared: [ {name, ecosystem, project_count, projects:[path,...]}, ... ],  # most-shared first
                distinct_deps: int,          # unique (name, ecosystem) pairs
                total_instances: int,        # every project<->dep pairing
                duplicate_instances: int,    # copies beyond the first (total_instances - distinct_deps)
                duplication_ratio: float,    # duplicate_instances / total_instances (0.0 if empty)
                env_bytes: int,              # installed-env bloat: virtualenv + dependencies marks
                estimated_savings: int,      # env_bytes * duplication_ratio (coarse)
                by_ecosystem: {eco: {distinct, instances, projects}},  # instances desc
            }
        """
        # One pass over every project<->dep edge; assemble the grouping in Python (workspace scale).
        edges = self.con.execute(
            "SELECT d.name, d.ecosystem, p.path FROM dependencies d "
            "JOIN projects p ON p.id = d.project_id"
        ).fetchall()

        by_dep = {}          # (name, ecosystem) -> [project paths]
        by_eco = {}          # ecosystem -> {names:set, instances:int, projects:set}
        for r in edges:
            eco = r["ecosystem"] or "other"
            by_dep.setdefault((r["name"], eco), []).append(r["path"])
            e = by_eco.setdefault(eco, {"names": set(), "instances": 0, "projects": set()})
            e["names"].add(r["name"])
            e["instances"] += 1
            e["projects"].add(r["path"])

        distinct_deps = len(by_dep)
        total_instances = len(edges)
        duplicate_instances = total_instances - distinct_deps
        ratio = (duplicate_instances / total_instances) if total_instances else 0.0

        shared = [
            {"name": name, "ecosystem": eco,
             "project_count": len(paths), "projects": sorted(paths)}
            for (name, eco), paths in by_dep.items()
            if len(paths) >= min_projects
        ]
        shared.sort(key=lambda d: (-d["project_count"], d["name"]))

        # The pool a shared store could dedup: installed deps live in venv / node_modules marks.
        env_bytes = self.con.execute(
            "SELECT COALESCE(SUM(size_bytes), 0) FROM marks "
            "WHERE kind IN ('virtualenv', 'dependencies')"
        ).fetchone()[0]

        by_ecosystem = {
            eco: {"distinct": len(e["names"]), "instances": e["instances"],
                  "projects": len(e["projects"])}
            for eco, e in by_eco.items()
        }
        by_ecosystem = dict(sorted(by_ecosystem.items(),
                                   key=lambda kv: kv[1]["instances"], reverse=True))

        return {
            "shared": shared,
            "distinct_deps": distinct_deps,
            "total_instances": total_instances,
            "duplicate_instances": duplicate_instances,
            "duplication_ratio": ratio,
            "env_bytes": env_bytes,
            "estimated_savings": int(env_bytes * ratio),
            "by_ecosystem": by_ecosystem,
        }

    def storage_report(self, limit=10):
        """
        Workspace-wide storage analysis for the CLI + web -> where the bytes actually live.

        Totals come from the DISTINCT file inventory: a file nested under both a parent and a child project is stored under each, so we de-duplicate by path here rather than double-count it.

        Args:
            limit (int): how many rows to return in each "largest" ranking (default 10).

        Returns:
            dict: {
                total_bytes: int,            # size of every distinct indexed file
                total_files: int,            # count of distinct indexed files
                project_count: int,
                reclaimable_bytes: int,      # regenerable-bloat rollup (see reclaimable_summary)
                largest_projects: [ {path, size_bytes, reclaimable_bytes}, ... ],  # biggest first
                largest_files:    [ {path, size_bytes}, ... ],
                largest_dirs:     [ {path, size_bytes, file_count}, ... ],  # by bytes held directly
            }
        """
        distinct_files = "SELECT path, MAX(size_bytes) AS size FROM files GROUP BY path"

        totals = self.con.execute(
            f"SELECT COUNT(*) AS n, COALESCE(SUM(size), 0) AS b FROM ({distinct_files})"
        ).fetchone()
        project_count = self.con.execute("SELECT COUNT(*) FROM projects").fetchone()[0]
        reclaimable = self.con.execute(
            "SELECT COALESCE(SUM(reclaimable_bytes), 0) FROM projects"
        ).fetchone()[0]

        largest_projects = [dict(r) for r in self.con.execute(
            "SELECT path, size_bytes, reclaimable_bytes FROM projects "
            "ORDER BY size_bytes DESC LIMIT ?", (limit,))]
        largest_files = [dict(r) for r in self.con.execute(
            f"SELECT path, size AS size_bytes FROM ({distinct_files}) "
            "ORDER BY size DESC LIMIT ?", (limit,))]

        # Roll the distinct files up by their immediate parent directory (Python-side -> portable SQLite has no dirname()).
        dir_bytes, dir_count = {}, {}
        for r in self.con.execute(distinct_files):
            d = os.path.dirname(r["path"])
            dir_bytes[d] = dir_bytes.get(d, 0) + (r["size"] or 0)
            dir_count[d] = dir_count.get(d, 0) + 1
        largest_dirs = [
            {"path": d, "size_bytes": b, "file_count": dir_count[d]}
            for d, b in sorted(dir_bytes.items(), key=lambda kv: kv[1], reverse=True)[:limit]
        ]

        return {
            "total_bytes": totals["b"],
            "total_files": totals["n"],
            "project_count": project_count,
            "reclaimable_bytes": reclaimable,
            "largest_projects": largest_projects,
            "largest_files": largest_files,
            "largest_dirs": largest_dirs,
        }

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
