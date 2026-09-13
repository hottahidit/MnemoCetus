-- ===========================================================================
-- MnemoCetus metadata schema  (v0.4 - the "MnemoIndex" store)
--
-- This is the single source of truth for the database shape.
-- db_manager.py just loads and runs this; it doesn't define tables itself.
-- Everything uses "IF NOT EXISTS" so re-running it on an existing DB is a no-op (idempotent).
--
-- Five tables:
--   scans         -> one row per scan run (the "when")
--   projects      -> one row per discovered project (the "what")
--   dependencies  -> declared deps, many-per-project
--   files         -> file inventory, many-per-project
--   marks         -> regenerable/reclaimable bloat dirs, many-per-project (v0.5 Stage B)
-- ===========================================================================

-- A single sweep of the workspace.
-- Lets us answer "what did the last scan find" and keep a history of scans over time.
CREATE TABLE IF NOT EXISTS scans (
    id            INTEGER PRIMARY KEY AUTOINCREMENT,
    root_path     TEXT    NOT NULL,        -- the directory we were asked to scan
    started_at    TEXT    NOT NULL,        -- ISO-8601 timestamp
    finished_at   TEXT,                    -- NULL until the scan is closed off
    project_count INTEGER DEFAULT 0,
    file_count    INTEGER DEFAULT 0,
    total_bytes   INTEGER DEFAULT 0
);

-- One row per project directory we recognised.
-- 'path' is unique, so re-scanning the same project updates its row in place rather than piling up duplicates.
CREATE TABLE IF NOT EXISTS projects (
    id               INTEGER PRIMARY KEY AUTOINCREMENT,
    path             TEXT    NOT NULL UNIQUE,   -- absolute, normalised project path
    language         TEXT,                      -- python / javascript / rust / go / ...
    category         TEXT,                      -- backend / frontend / full stack / ...
    confidence       REAL    DEFAULT 0,         -- 0.0 - 1.0 from the classifier
    frameworks       TEXT,                      -- JSON array of framework names
    markers          TEXT,                      -- JSON array of marker filenames found
    file_count       INTEGER DEFAULT 0,         -- from the classifier's metrics
    size_bytes       INTEGER DEFAULT 0,
    dependency_count INTEGER DEFAULT 0,
    -- relationship info (from resolve_directory_relationships)
    parent_path      TEXT,                      -- nearest project ancestor, or NULL if root
    role             TEXT,                      -- root / child / merged / independent
    is_symlink       INTEGER DEFAULT 0,         -- 0/1 (SQLite has no real bool)
    symlink_target   TEXT,
    -- recognition + user override (v0.5; added to existing DBs by the v2 migration)
    breakdown           TEXT,                   -- JSON {languages:{}, categories:{}} composition
    override_language   TEXT,                   -- user-set language (NULL -> use the auto-detected one)
    override_category   TEXT,                   -- user-set category
    override_frameworks TEXT,                   -- JSON array of user-set frameworks
    override_note       TEXT,                   -- freeform, e.g. "backend done, frontend still to build"
    user_confirmed      INTEGER DEFAULT 0,      -- 1 = user signed off / overrode (locked at full confidence)
    -- reclaimable "marks" rollup (v0.5 Stage B; added to existing DBs by the v3 migration)
    reclaimable_bytes   INTEGER DEFAULT 0,      -- total size of regenerable bloat (node_modules, venv, ...) under this project
    -- bookkeeping
    first_seen       TEXT,                      -- when we first indexed this project
    updated_at       TEXT,                      -- last time this row changed
    last_scan_id     INTEGER REFERENCES scans(id) ON DELETE SET NULL
);

-- Declared dependencies, one row each.
-- Cascade-deletes with the project so we never leave orphans.
-- UNIQUE keeps a re-scan from double-inserting the same dep.
CREATE TABLE IF NOT EXISTS dependencies (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    name         TEXT    NOT NULL,
    ecosystem    TEXT,                           -- python / javascript / rust / go
    version_spec TEXT,                           -- declared constraint (==2.0, ^1.3, >=4,<5; NULL/'' = unpinned) - v0.5 dependency intelligence
    UNIQUE(project_id, name)
);

-- File inventory for a project (path + size + extension).
-- Optional to populate; handy later for storage analysis (v0.5: "largest files").
CREATE TABLE IF NOT EXISTS files (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    path        TEXT    NOT NULL,
    extension   TEXT,
    size_bytes  INTEGER DEFAULT 0,
    UNIQUE(project_id, path)
);

-- Reclaimable "marks": regenerable/bloat directories (node_modules, venv, target, __pycache__, dist, build, ...) that the scan filters out of a project but that we still size up so the user knows how much disk they could get back.
-- Many-per-project, cascade-deletes with the project.
CREATE TABLE IF NOT EXISTS marks (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind        TEXT,                            -- dependencies / virtualenv / build / cache
    name        TEXT,                            -- node_modules / target / __pycache__ / ...
    path        TEXT    NOT NULL,                -- absolute path of the reclaimable directory
    size_bytes  INTEGER DEFAULT 0,               -- how much it weighs
    file_count  INTEGER DEFAULT 0,
    reason      TEXT,                            -- how it's regenerated (e.g. "npm install")
    UNIQUE(project_id, path)
);

-- Security findings from "MnemoScan": hard-coded secrets (regex scan) and optional dependency vulnerabilities (pip-audit / npm audit).
-- Many-per-project, cascade-deletes with the project.
-- The 'detail' for a secret is MASKED, never the raw value. - v0.5
CREATE TABLE IF NOT EXISTS security_findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    project_id  INTEGER NOT NULL REFERENCES projects(id) ON DELETE CASCADE,
    kind        TEXT,                            -- secret / vuln
    rule        TEXT,                            -- rule name (secret) or package + advisory id (vuln)
    severity    TEXT,                            -- high / medium / low
    path        TEXT,                            -- file the finding is in
    line        INTEGER DEFAULT 0,               -- line number (0 for whole-project findings)
    detail      TEXT,                            -- masked secret preview, or a short vuln description
    UNIQUE(project_id, kind, rule, path, line)
);

-- Indexes for the lookups we expect to do a lot of (search by language/category, "which projects use X", and joining files/deps back to their project).
CREATE INDEX IF NOT EXISTS idx_projects_language   ON projects(language);
CREATE INDEX IF NOT EXISTS idx_projects_category   ON projects(category);
CREATE INDEX IF NOT EXISTS idx_dependencies_name   ON dependencies(name);
CREATE INDEX IF NOT EXISTS idx_dependencies_project ON dependencies(project_id);
CREATE INDEX IF NOT EXISTS idx_files_project       ON files(project_id);
-- The storage rollup groups the whole inventory by path (SELECT path, MAX(size_bytes) ... GROUP BY path).
-- A COVERING (path, size_bytes) index serves that from the index alone -> no table lookups, no sort.
CREATE INDEX IF NOT EXISTS idx_files_path           ON files(path, size_bytes);
CREATE INDEX IF NOT EXISTS idx_marks_project       ON marks(project_id);
CREATE INDEX IF NOT EXISTS idx_security_project    ON security_findings(project_id);
