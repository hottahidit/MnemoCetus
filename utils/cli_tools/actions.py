# Self-contained CLI actions for MnemoCetus (v0.7.x split out of cli.py).
#
# The menu actions that don't touch the live scan session -> browse/query the database, review
# low-confidence projects, and run a dependency audit. Each takes only a db path (or nothing), so
# they live apart from cli.py's session/rt-bound flows. cli.py imports and dispatches to them.

import os
import stat

import questionary
from rich import print, box
from rich.panel import Panel
from rich.table import Table

from db_tools import manager as db_manager
import report
import gitinfo
import insight
from scanner import _human_size
from cli_tools.ui import _menu, ask_dir, _pause, _qstyle


def do_browse(db_path):

    if not os.path.exists(db_path):
        print("Nothing to browse there yet -> scan a directory first (or pick a saved database).")
        return

    def show_projects(projects):
        if not projects:
            print("No matching projects.")
            return
        table = Table(title=f"{len(projects)} project(s)", box=box.ROUNDED, header_style="bold cyan")
        for col in ("path", "language", "category", "conf", "files", "deps", "git"):
            table.add_column(col, overflow="fold")
        for p in projects:
            table.add_row(
                p["path"], str(p["language"]), str(p["category"]),
                f"{p['confidence']:.2f}", str(p["file_count"]), str(len(p["dependencies"])),
                gitinfo.badge_from_row(p),
            )
        print(table)

    db = db_manager.Database(db_path)
    try:
        while True:
            action = _menu(
                "Explore:",
                choices=[
                    "List all projects",
                    "Search (language / category / framework)",
                    "View a project (details + deps)",
                    "Latest scan",
                    "Reclaimable space (regenerable bloat)",
                    "Cleanup recommendations",
                    "Dependency overlap (shared deps / env savings)",
                    "Dependency conflicts (shareable-venv check)",
                    "Storage analysis (largest projects / files / dirs)",
                    "Security findings (secrets)",
                    "Git: at-risk projects (uncommitted / unpushed / stale)",
                    "Git: repositories worth `git gc` (reclaim .git bloat)",
                    "Export report (Markdown / JSON)",
                    "Delete a project",
                    "Back",
                ],
            )
            if action in (None, "Back"):
                return

            if action == "List all projects":
                show_projects(db.all_projects())

            elif action == "Search (language / category / framework)":
                language = questionary.text("language (blank to skip):").ask() or None
                category = questionary.text("category (blank to skip):").ask() or None
                framework = questionary.text("framework (blank to skip):").ask() or None
                show_projects(db.find_projects(language=language, category=category, framework=framework))

            elif action == "View a project (details + deps)":
                directory = ask_dir("Project path:")
                if directory:
                    p = db.get_project(directory)
                    if p is None:
                        print("That path isn't in the database.")
                    else:
                        frameworks = ", ".join(p["frameworks"]) or "(none)"
                        deps = ", ".join(p["dependencies"]) or "(none)"
                        marks = db.get_marks(p["id"])
                        reclaim = f"{_human_size(p['reclaimable_bytes'] or 0)}"
                        if marks:
                            reclaim += " -> " + ", ".join(
                                f"{m['name']} ({_human_size(m['size_bytes'])})" for m in marks)
                        print(Panel(
                            f"language:   {p['language']}\n"
                            f"category:   {p['category']}\n"
                            f"confidence: {p['confidence']:.2f}\n"
                            f"frameworks: {frameworks}\n"
                            f"role:       {p['role']}\n"
                            f"parent:     {p['parent_path']}\n"
                            f"files:      {p['file_count']}  ({_human_size(p['size_bytes'])})\n"
                            f"reclaimable: {reclaim}\n"
                            f"deps ({p['dependency_count']}): {deps}\n"
                            f"first seen: {p['first_seen']}\n"
                            f"updated:    {p['updated_at']}",
                            title=p["path"], style="cyan"))

            elif action == "Latest scan":
                scan = db.latest_scan()
                if scan is None:
                    print("No scans recorded yet.")
                else:
                    print(Panel(
                        f"root:     {scan['root_path']}\n"
                        f"started:  {scan['started_at']}\n"
                        f"finished: {scan['finished_at']}\n"
                        f"projects: {scan['project_count']}\n"
                        f"files:    {scan['file_count']}\n"
                        f"bytes:    {_human_size(scan['total_bytes'] or 0)}",
                        title=f"Scan #{scan['id']}", style="cyan"))

            elif action == "Reclaimable space (regenerable bloat)":
                summary = db.reclaimable_summary()
                if not summary["total_bytes"]:
                    print("No reclaimable bloat recorded -> scan a workspace with node_modules/venv/... first.")
                else:
                    by_kind = "\n".join(
                        f"  {kind:14} {_human_size(v['bytes'])}  ({v['count']} dir(s))"
                        for kind, v in summary["by_kind"].items())
                    top = "\n".join(
                        f"  {_human_size(p['reclaimable_bytes']):>10}  {p['path']}"
                        for p in summary["top_projects"])
                    print(Panel(
                        f"Total reclaimable: [bold]{_human_size(summary['total_bytes'])}[/]\n\n"
                        f"by kind:\n{by_kind}\n\n"
                        f"heaviest projects:\n{top}",
                        title="Reclaimable space", style="yellow"))

            elif action == "Cleanup recommendations":
                recs = db.cleanup_recommendations()
                if not recs["item_count"]:
                    print("Nothing to recommend -> no reclaimable bloat recorded yet.")
                else:
                    print(Panel(
                        f"You could reclaim [bold]{_human_size(recs['total_savings'])}[/] "
                        f"across {recs['item_count']} director(y/ies).\n"
                        f"[dim]Suggestions only -> MnemoCetus never deletes anything.[/]",
                        title="Cleanup recommendations", style="yellow"))
                    table = Table(show_lines=False, box=box.ROUNDED, header_style="bold cyan")
                    for col in ("directory", "kind", "savings", "command"):
                        table.add_column(col, overflow="fold")
                    for it in recs["items"]:
                        table.add_row(it["path"], str(it["kind"]),
                                      _human_size(it["size_bytes"]), it["command"])
                    print(table)

            elif action == "Dependency overlap (shared deps / env savings)":
                overlap = db.dependency_overlap()
                if not overlap["total_instances"]:
                    print("No dependencies recorded yet -> scan some projects with a manifest first.")
                else:
                    pct = overlap["duplication_ratio"] * 100
                    eco = "\n".join(
                        f"  {name:12} {v['distinct']} distinct across {v['projects']} project(s)"
                        for name, v in overlap["by_ecosystem"].items())
                    print(Panel(
                        f"{overlap['total_instances']} installed package(s) across your projects, "
                        f"but only [bold]{overlap['distinct_deps']}[/] are distinct -> "
                        f"{overlap['duplicate_instances']} are duplicate copies ({pct:.0f}%).\n\n"
                        f"Installed-env bloat (venv + node_modules): "
                        f"[bold]{_human_size(overlap['env_bytes'])}[/]\n"
                        f"Rough reclaim with a shared/hardlinked store (uv, pnpm, a common venv): "
                        f"[bold]~{_human_size(overlap['estimated_savings'])}[/]\n"
                        f"[dim]Estimate from dependency names only -> real dedup depends on versions matching.[/]\n\n"
                        f"by ecosystem:\n{eco}",
                        title="Dependency overlap", style="yellow"))
                    top = overlap["shared"][:15]
                    if top:
                        table = Table(title="most-shared dependencies", box=box.ROUNDED, header_style="bold cyan")
                        for col in ("dependency", "ecosystem", "projects"):
                            table.add_column(col, overflow="fold")
                        for d in top:
                            table.add_row(d["name"], str(d["ecosystem"]), str(d["project_count"]))
                        print(table)

            elif action == "Dependency conflicts (shareable-venv check)":
                intel = db.dependency_intel()
                ecos = intel["ecosystems"]
                if not ecos:
                    print("No ecosystem spans 2+ projects yet -> scan more projects with manifests first.")
                else:
                    for eco, d in ecos.items():
                        if d["shareable"]:
                            print(Panel(
                                f"[bold]All {d['project_count']} {eco} project(s) could share one "
                                f"environment[/] -> no conflicting exact version pins found.",
                                title=f"{eco}: shareable", style="green"))
                            continue
                        print(Panel(
                            f"{len(d['conflicting_projects'])} of {d['project_count']} {eco} "
                            f"project(s) [bold]conflict[/] on exact version pins; the other "
                            f"{len(d['shareable_projects'])} could share an environment.\n"
                            f"[dim]Heuristic -> only differing exact pins count; ranges are assumed compatible.[/]",
                            title=f"{eco}: conflicts", style="yellow"))
                        t = Table(title=f"{eco} version conflicts", box=box.ROUNDED, header_style="bold cyan")
                        for col in ("dependency", "version", "projects"):
                            t.add_column(col, overflow="fold")
                        for cf in d["conflicts"]:
                            first = True
                            for ver, paths in cf["pins"].items():
                                t.add_row(cf["name"] if first else "", ver, ", ".join(paths))
                                first = False
                        print(t)

            elif action == "Storage analysis (largest projects / files / dirs)":
                storage = db.storage_report()
                if not storage["total_files"]:
                    print("No file inventory recorded yet -> scan a directory first.")
                else:
                    print(Panel(
                        f"Workspace: [bold]{_human_size(storage['total_bytes'])}[/] across "
                        f"{storage['total_files']} files in {storage['project_count']} project(s).\n"
                        f"Reclaimable (regenerable bloat): {_human_size(storage['reclaimable_bytes'])}",
                        title="Storage analysis", style="yellow"))
                    proj = Table(title="largest projects", box=box.ROUNDED, header_style="bold cyan")
                    for c in ("project", "size", "reclaimable"):
                        proj.add_column(c, overflow="fold")
                    for p in storage["largest_projects"]:
                        proj.add_row(p["path"], _human_size(p["size_bytes"] or 0),
                                     _human_size(p["reclaimable_bytes"] or 0))
                    print(proj)
                    files_t = Table(title="largest files", box=box.ROUNDED, header_style="bold cyan")
                    for c in ("file", "size"):
                        files_t.add_column(c, overflow="fold")
                    for f in storage["largest_files"]:
                        files_t.add_row(f["path"], _human_size(f["size_bytes"] or 0))
                    print(files_t)
                    dirs_t = Table(title="largest directories (bytes held directly)", box=box.ROUNDED, header_style="bold cyan")
                    for c in ("directory", "size", "files"):
                        dirs_t.add_column(c, overflow="fold")
                    for d in storage["largest_dirs"]:
                        dirs_t.add_row(d["path"], _human_size(d["size_bytes"] or 0), str(d["file_count"]))
                    print(dirs_t)

            elif action == "Security findings (secrets)":
                summary = db.security_summary()
                if not summary["total"]:
                    print("No security findings recorded -> secrets are scanned when you scan a directory.")
                else:
                    sev = ", ".join(f"{k}: {v}" for k, v in summary["by_severity"].items())
                    print(Panel(
                        f"[bold]{summary['total']}[/] finding(s) -> {sev}\n"
                        f"[dim]Secret values are masked; MnemoCetus only reports them, never stores the raw value.[/]",
                        title="Security findings", style="red"))
                    t = Table(box=box.ROUNDED, header_style="bold cyan")
                    for col in ("severity", "kind", "rule", "location", "detail"):
                        t.add_column(col, overflow="fold")
                    for f in summary["findings"]:
                        loc = f"{f['path']}:{f['line']}" if f["line"] else f["path"]
                        t.add_row(str(f["severity"]), str(f["kind"]), str(f["rule"]), loc, str(f["detail"]))
                    print(t)

            elif action.startswith("Git: at-risk"):
                risky = insight.at_risk_projects(db)
                if not risky:
                    print("No at-risk repositories -> everything committed, pushed, and recently touched.")
                else:
                    t = Table(title=f"{len(risky)} at-risk repositor(y/ies)", box=box.ROUNDED, header_style="bold cyan")
                    for col in ("path", "language", "risks"):
                        t.add_column(col, overflow="fold")
                    for r in risky:
                        t.add_row(r["path"], str(r["language"]), ", ".join(r["risks"]))
                    print(t)

            elif action.startswith("Git: repositories worth"):
                recs = insight.git_gc_recommendations(db)
                if not recs["items"]:
                    print("No repositories carry enough git bloat to bother with `git gc`.")
                else:
                    t = Table(title=f"{len(recs['items'])} repo(s) - ~{_human_size(recs['total_reclaimable'])} reclaimable via git gc",
                              box=box.ROUNDED, header_style="bold cyan")
                    for col in ("repository", "reclaimable (est.)", ".git total"):
                        t.add_column(col, overflow="fold")
                    for it in recs["items"][:30]:
                        t.add_row(it["path"], _human_size(it["reclaimable"]), _human_size(it["total"]))
                    print(t)
                    if questionary.confirm(
                            f"Run `git gc` on these {len(recs['items'])} repo(s) now? (safe - it never touches your commits/branches)",
                            default=False, style=_qstyle).ask():
                        from reclaimer import run_git_gc
                        res = run_git_gc([it["path"] for it in recs["items"]])
                        msg = (f"Ran git gc on [bold]{len(res['ran'])}[/] repo(s), "
                               f"freed [bold]{_human_size(res['freed_bytes'])}[/].")
                        if res["failed"]:
                            msg += f"\n[yellow]{len(res['failed'])} failed.[/]"
                        print(Panel(msg, title="git gc", style="green"))

            elif action == "Export report (Markdown / JSON)":
                fmt_choice = _menu("Format:", choices=["Markdown", "JSON", "Back"])
                if fmt_choice in (None, "Back"):
                    continue
                fmt = "json" if fmt_choice == "JSON" else "md"
                default_name = report.suggested_filename(fmt)
                out_path = questionary.path("Save to:", default=default_name, style=_qstyle).ask()
                if not out_path:
                    continue
                body = report.render(report.build_report(db_path), fmt)
                try:
                    with open(out_path, "w", encoding="utf-8") as fh:
                        fh.write(body)
                except OSError as exc:
                    print(f"Could not write the report -> {exc}")
                else:
                    print(Panel(f"Report written to [bold]{out_path}[/] ({len(body):,} bytes).",
                                title="Export report", style="green"))

            elif action == "Delete a project":
                directory = ask_dir("Project path to delete:")
                if directory and questionary.confirm(f"Delete '{directory}' from the DB?", default=False).ask():
                    ok = db.delete_project(directory)
                    print("Deleted." if ok else "Nothing matched that path.")

            _pause()  # let the user read the result before the browse menu redraws
    finally:
        db.close()


def do_review(db_path, suggestions=None):
    # suggestions: optional {path: {language, category, frameworks, confidence, rationale}} from the AI arbiter.
    suggestions = suggestions or {}
    if not os.path.exists(db_path):
        print("Nothing to review yet -> scan a directory first.")
        return
    raw = questionary.text("Confidence threshold (default 0.6):", default="0.6").ask()
    try:
        threshold = float(raw)
    except (TypeError, ValueError):
        threshold = 0.6

    db = db_manager.Database(db_path)
    try:
        pending = db.low_confidence_projects(threshold)
        if not pending:
            print("Nothing to review -> every project is above the threshold or already confirmed.")
            return
        print(f"{len(pending)} low-confidence project(s) to review.\n")
        yes_to_all = False
        for p in pending:
            if yes_to_all:
                db.approve(p["path"])
                continue
            auto = p["auto"]
            sug = suggestions.get(p["path"])
            body = (
                f"auto guess: {auto['language']} / {auto['category']}  (confidence {auto['confidence']:.2f})\n"
                f"frameworks: {', '.join(auto['frameworks']) or '(none)'}\n"
                f"breakdown:  {p['breakdown']['categories']}"
            )
            if sug:
                conf = f"{sug['confidence']:.2f}" if sug.get("confidence") is not None else "?"
                body += (f"\n[bold cyan]AI arbiter:[/] {sug.get('language') or '?'} / "
                         f"{sug.get('category') or '?'}  (confidence {conf})")
                if sug.get("rationale"):
                    body += f"\n[dim]{sug['rationale']}[/]"
            print(Panel(body, title=p["path"], style="yellow"))
            choices = (["Accept AI suggestion"] if sug else []) + [
                "Accept this guess",
                "Set the real type",
                "Delete the project",
                "Yes to all (accept the rest)",
                "Skip",
                "Stop",
            ]
            choice = _menu("What is this project?", choices=choices)
            if choice in (None, "Stop"):
                break
            if choice == "Skip":
                continue
            if choice == "Accept AI suggestion":
                db.set_override(p["path"], language=sug.get("language"), category=sug.get("category"),
                                frameworks=sug.get("frameworks") or None,
                                note=(f"AI arbiter: {sug.get('rationale', '')}").strip())
            elif choice == "Accept this guess":
                db.approve(p["path"])
            elif choice == "Yes to all (accept the rest)":
                db.approve(p["path"])
                yes_to_all = True
            elif choice == "Delete the project":
                if questionary.confirm(f"Delete '{p['path']}'?", default=False).ask():
                    db.delete_project(p["path"])
            elif choice == "Set the real type":
                category = _menu(
                    "Category:",
                    choices=["backend", "frontend", "full stack", "automation", "library",
                             "cli", "desktop", "application", "data/ml", "other"],
                )
                language = questionary.text("Language (blank = keep auto):").ask() or None
                note = questionary.text("Note (optional, e.g. 'frontend still to build'):").ask() or None
                db.set_override(p["path"], language=language, category=category, note=note)
        print("Review complete.")
    finally:
        db.close()


def do_audit():
    directory = ask_dir("Directory to audit (pip-audit / npm audit):")
    if not directory:
        return
    from security import audit_dependencies  # lazy: the audit shells out to optional external tools
    findings = audit_dependencies(directory)
    if not findings:
        print("No vulnerabilities reported (or pip-audit / npm audit isn't installed -> the audit is optional).")
        return
    table = Table(title=f"Dependency audit -> {directory}", box=box.ROUNDED, header_style="bold cyan")
    for col in ("severity", "package / advisory", "detail"):
        table.add_column(col, overflow="fold")
    for f in findings:
        table.add_row(str(f["severity"]), str(f["rule"]), str(f["detail"]))
    print(table)


def do_history_scan():
    directory = ask_dir("Repository to scan (full git history):")
    if not directory:
        return
    if not gitinfo.status(directory).get("is_repo"):
        print("Not a git repository -> the history scan needs one (the plain scan already covers the files).")
        return
    from security import scan_git_history  # lazy: shells out to git, walks every commit
    print("[dim]Walking every commit in history -> this can take a moment on a large repo...[/]")
    findings = scan_git_history(directory)
    if not findings:
        print("No secrets found anywhere in this repo's history. ✓")
        return
    table = Table(title=f"Secrets in git history -> {directory}", box=box.ROUNDED, header_style="bold cyan")
    for col in ("severity", "rule", "detail"):
        table.add_column(col, overflow="fold")
    for f in findings:
        table.add_row(str(f["severity"]), str(f["rule"]), str(f["detail"]))
    print(table)
    print(Panel(
        f"[bold]{len(findings)}[/] secret(s) are present in the git history (not just the working tree).\n"
        "[dim]Removing a file in a later commit does NOT remove it from history. To purge, rewrite history\n"
        "with git-filter-repo (or BFG), then rotate the exposed credentials.[/]",
        title="Git history", style="yellow"))


# --- Scan scope: cherry-pick what to scan inside a directory ------------- #
# "Scan a directory" can mean the whole tree (a normal project scan) or a hand-picked set of files.
# A loose file set isn't a "project" (no classification / marks / deps make sense), so the file path
# runs the per-file passes only -> MnemoScan secrets + a size inventory -> and is DISPLAY-ONLY.

def _enumerate_scannable(directory, cap=400):
    """
    Walk 'directory' honouring the scan's excludes, skipping hidden DIRS and non-regular files (sockets /
    FIFOs / devices), but KEEPING hidden files like .env (that's where secrets hide). Returns a sorted
    list of paths relative to 'directory', or None if there are more than 'cap' (too many for a tree).
    """
    from scanner import _default, _is_excluded
    sc = _default()
    nr, pr = sc._name_rules, sc._path_rules
    files = []
    for root, dirs, fs in os.walk(directory):
        dirs[:] = [d for d in dirs
                   if not d.startswith('.') and not _is_excluded(os.path.join(root, d), nr, pr)]
        for f in fs:
            p = os.path.normpath(os.path.join(root, f))
            if _is_excluded(p, nr, pr):
                continue
            try:
                if not stat.S_ISREG(os.stat(p).st_mode):
                    continue
            except OSError:
                continue
            files.append(os.path.relpath(p, directory))
            if len(files) > cap:
                return None
    return sorted(files)


def _pick_tree(directory):
    """Flattened, indented checkbox of the directory: tick individual files, or a whole folder (its subtree)."""
    files = _enumerate_scannable(directory)
    if files is None:
        print("Too many files to list as a tree -> use the glob or manual-path option instead.")
        return None
    if not files:
        print("No scannable files found under there.")
        return None
    from collections import defaultdict
    by_dir = defaultdict(list)
    for rel in files:
        by_dir[os.path.dirname(rel)].append(rel)
    choices = []
    for d in sorted(by_dir):
        if d not in ("", "."):
            depth = d.count(os.sep) + 1
            choices.append(questionary.Choice(
                f"{'  ' * (depth - 1)}[dir] {os.path.basename(d) or d}/  (all {len(by_dir[d])})",
                value=("dir", d)))
        else:
            depth = 0
        for rel in sorted(by_dir[d]):
            choices.append(questionary.Choice(f"{'  ' * depth}- {os.path.basename(rel)}", value=("file", rel)))
    picked = questionary.checkbox("Tick files to scan (or a whole folder):", choices=choices, style=_qstyle).ask()
    if not picked:
        return None
    sel = set()
    for kind, v in picked:
        if kind == "file":
            sel.add(v)
        else:  # a folder -> everything in its subtree
            sel.update(rel for rel in files if rel == v or rel.startswith(v + os.sep))
    return [os.path.normpath(os.path.join(directory, rel)) for rel in sorted(sel)]


def _pick_glob(directory):
    """Match files by one or more glob patterns (relative to the dir) -> preview then confirm."""
    import pathlib
    base = pathlib.Path(directory)
    patterns = []
    while True:
        pat = questionary.text("Glob pattern (e.g. **/*.env or src/*/config.py; blank when done):",
                               style=_qstyle).ask()
        if pat is None:
            return None
        pat = pat.strip()
        if not pat:
            break
        patterns.append(pat)
    if not patterns:
        return None
    matched = set()
    for pat in patterns:
        try:
            for p in base.glob(pat):
                if p.is_file():  # follows symlinks; True only for regular files -> skips sockets/FIFOs/dirs
                    matched.add(os.path.normpath(str(p)))
        except (ValueError, OSError):
            print(f"  [yellow]bad pattern skipped: {pat}[/]")
    matched = sorted(matched)
    if not matched:
        print("No files matched.")
        return None
    print(f"[cyan]{len(matched)} file(s) matched:[/]")
    for m in matched[:50]:
        print(f"  {os.path.relpath(m, directory)}")
    if len(matched) > 50:
        print(f"  ... and {len(matched) - 50} more")
    ok = questionary.confirm(f"Scan these {len(matched)} file(s)?", default=True).ask()
    return matched if ok else None


def _pick_paths(directory):
    """Enter explicit file paths, one per line (relative to the dir or absolute)."""
    print("Enter file paths one per line (relative to the dir or absolute). Blank line when done.")
    paths = []
    while True:
        line = questionary.text("path:", style=_qstyle).ask()
        if line is None:
            return None
        line = line.strip()
        if not line:
            break
        p = line if os.path.isabs(line) else os.path.join(directory, line)
        p = os.path.normpath(p)
        if os.path.isfile(p):
            paths.append(p)
        else:
            print(f"  [yellow]skipped (not a file): {line}[/]")
    return paths or None


def ask_scan_scope(directory):
    """
    Pick WHAT to scan inside 'directory'. Returns one of:
        ('all',)              -> the whole directory (a normal project scan)
        ('files', [abspaths]) -> a hand-picked set of files (targeted secret + inventory scan)
        None                  -> cancelled / nothing picked
    """
    choice = _menu(
        f"What in {directory} do you want to scan?",
        choices=[
            questionary.Choice("Everything in this directory (normal scan)", value="all"),
            questionary.Choice("Pick files / folders (tree)", value="tree"),
            questionary.Choice("Match files by glob pattern", value="glob"),
            questionary.Choice("Enter file paths manually", value="paths"),
            questionary.Choice("Back (cancel)", value="__back__"),
        ],
    )
    if choice in (None, "__back__"):
        return None
    if choice == "all":
        return ("all",)
    files = {"tree": _pick_tree, "glob": _pick_glob, "paths": _pick_paths}[choice](directory)
    return ("files", files) if files else None


def do_file_scan(directory, files):
    """
    Targeted scan over a hand-picked set of files -> MnemoScan secrets + a size inventory. On-demand and
    DISPLAY-ONLY: a loose file set isn't a project, so nothing is written to the database.
    """
    from security import _scan_file, BINARY_EXTS, MAX_FILE_BYTES
    findings, total_bytes, scanned = [], 0, 0
    for p in files:
        try:
            st = os.stat(p)
        except OSError:
            continue
        if not stat.S_ISREG(st.st_mode):
            continue
        total_bytes += st.st_size
        scanned += 1
        if os.path.splitext(p)[1].lower() in BINARY_EXTS or st.st_size > MAX_FILE_BYTES:
            continue  # sized in the inventory, but not read for secrets
        findings.extend(_scan_file(p))
    print(Panel(f"Scanned [bold]{scanned}[/] file(s) - [bold]{_human_size(total_bytes)}[/] total.\n"
                "[dim]Targeted file scan: secrets + inventory only, nothing saved to the database.[/]",
                title="Targeted file scan", style="green"))
    if not findings:
        print("No hard-coded secrets found in the selected files. ✓")
        return
    table = Table(title="Secrets found", box=box.ROUNDED, header_style="bold cyan")
    for col in ("severity", "rule", "location", "detail"):
        table.add_column(col, overflow="fold")
    for f in findings:
        loc = f"{os.path.relpath(f['path'], directory)}:{f['line']}"
        table.add_row(str(f["severity"]), str(f["rule"]), loc, str(f["detail"]))
    print(table)
