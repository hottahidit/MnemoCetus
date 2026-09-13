# Read-only analytics / reporting queries for MnemoCetus (v0.7.x split out of db_manager).
#
# These are the heavy "what does the workspace look like" rollups -> security, reclaimable space,
# cleanup advice, dependency overlap / conflicts, and storage. They only ever READ (self.con),
# so they live apart from the CRUD/migration core. Database mixes this in, so db.security_summary(),
# db.storage_report() etc. still work exactly as before -> no call site changes.

import os
import re


_RANGE_TOKENS = ("^", "~", ">", "<", "*", "||", " - ")

def _pinned_version(spec):
    """
    The exact version a spec pins, or None when it's a range / wildcard / unconstrained.

    Recognises pip '==1.2.3' / '===1.2.3', a bare '1.2.3', and npm/go 'v1.2.3'. Anything carrying a range operator (^ ~ > < * || or a comma-separated list) is treated as NOT an exact pin -> we only ever flag a conflict on two DIFFERENT exact pins, never on ranges we can't fully solve.
    """
    if not spec:
        return None
    s = spec.strip()
    if "," in s or any(tok in s for tok in _RANGE_TOKENS):
        return None
    m = re.match(r"^={0,3}\s*v?([0-9][0-9A-Za-z.\-+]*)$", s)
    return m.group(1) if m else None


class AnalyticsMixin:
    """The read-only reporting queries, mixed into Database (they use self.con / self._SEVERITY_ORDER)."""

    def security_summary(self, limit=100):
        """
        Workspace-wide MnemoScan rollup for the CLI + web.

        Returns:
            dict: {
                total: int,                       # every finding
                by_severity: {severity: count},   # high / medium / low (high first)
                by_kind: {kind: count},           # secret / vuln
                findings: [ {project_path, kind, rule, severity, path, line, detail}, ... ],  # most severe first
            }
        """
        by_severity, by_kind, total = {}, {}, 0
        for r in self.con.execute(
            "SELECT severity, COUNT(*) AS n FROM security_findings "
            f"GROUP BY severity ORDER BY {self._SEVERITY_ORDER}"
        ):
            by_severity[r["severity"] or "unknown"] = r["n"]
            total += r["n"]
        for r in self.con.execute("SELECT kind, COUNT(*) AS n FROM security_findings GROUP BY kind"):
            by_kind[r["kind"] or "other"] = r["n"]
        findings = [dict(r) for r in self.con.execute(
            "SELECT s.kind, s.rule, s.severity, s.path, s.line, s.detail, p.path AS project_path "
            "FROM security_findings s JOIN projects p ON p.id = s.project_id "
            f"ORDER BY {self._SEVERITY_ORDER}, s.path, s.line LIMIT ?", (limit,))]
        return {"total": total, "by_severity": by_severity, "by_kind": by_kind, "findings": findings}

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

    def dependency_intel(self, min_projects=2):
        """
        Version-aware dependency analysis -> which projects could safely SHARE one environment (venv / node_modules), and which CONFLICT because they pin different exact versions of the same package.

        Heuristic and deliberately conservative: a conflict is only flagged when two projects pin DIFFERENT EXACT versions of a shared dependency (e.g. flask==2.0 vs flask==3.0) -> those genuinely cannot coexist in one environment. Range / unpinned specs are treated as optimistically compatible (a full PEP 440 / semver solver is out of scope), so "shareable" means "no hard version conflict", not a cast-iron guarantee.

        Sharing an environment is really a Python (venv) / JavaScript (node_modules) concern; Rust and Go already share a global module cache, so their rows are informational.

        Args:
            min_projects (int): only report ecosystems spanning at least this many projects (default 2).

        Returns:
            dict: {
                ecosystems: {
                    eco: {
                        project_count: int,
                        projects: [path, ...],
                        conflicts: [ {name, pins: {version: [paths]}}, ... ],  # deps with >1 exact pin, worst first
                        conflicting_projects: [path, ...],   # projects touched by any conflict
                        shareable_projects: [path, ...],     # the conflict-free remainder
                        shareable: bool,                     # True -> the whole ecosystem could share one environment
                    }, ...
                },  # most projects first
            }
        """
        rows = self.con.execute(
            "SELECT d.name, COALESCE(d.ecosystem, 'other') AS eco, d.version_spec AS spec, p.path "
            "FROM dependencies d JOIN projects p ON p.id = d.project_id"
        ).fetchall()

        ecos = {}   # eco -> {projects:set, deps:{name: {path: spec}}}
        for r in rows:
            e = ecos.setdefault(r["eco"], {"projects": set(), "deps": {}})
            e["projects"].add(r["path"])
            e["deps"].setdefault(r["name"], {})[r["path"]] = r["spec"]

        out = {}
        for eco, data in ecos.items():
            projects = sorted(data["projects"])
            if len(projects) < min_projects:
                continue
            conflicts, conflicting = [], set()
            for name, per_project in data["deps"].items():
                pins = {}   # exact version -> [projects pinning it]
                for path, spec in per_project.items():
                    v = _pinned_version(spec)
                    if v is not None:
                        pins.setdefault(v, []).append(path)
                if len(pins) >= 2:  # two projects pin different exact versions -> hard conflict
                    conflicts.append({"name": name,
                                      "pins": {v: sorted(paths) for v, paths in sorted(pins.items())}})
                    for paths in pins.values():
                        conflicting.update(paths)
            conflicts.sort(key=lambda c: (-len(c["pins"]), c["name"]))
            out[eco] = {
                "project_count": len(projects),
                "projects": projects,
                "conflicts": conflicts,
                "conflicting_projects": sorted(conflicting),
                "shareable_projects": [p for p in projects if p not in conflicting],
                "shareable": not conflicts,
            }
        ecosystems = dict(sorted(out.items(), key=lambda kv: kv[1]["project_count"], reverse=True))
        return {"ecosystems": ecosystems}

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
