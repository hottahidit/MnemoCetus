# Interactive CLI for MnemoCetus (the questionary menu + debug tools).
#
# This is the human-facing front-end; the engines live in scanner / classifier / cleaner / db_manager.
# Launch it with 'python utils/scanner.py' (which delegates here) or 'python utils/cli.py' directly.

# IMPORTS
from rich import print, box
from rich.panel import Panel
from rich.rule import Rule
import os

from scanner import (
    scan_directory, classify_directory, resolve_directory_relationships,
    persist_scan, describe, _is_recognised,
    _is_excluded, _default, _human_size,
)


# --- debug / CLI helpers ------------------------------------------------- #
def _is_child(child, parent):
    """
    Checks whether 'child' lives inside 'parent' (i.e. parent is an ancestor of child).

    Args:
        child (str): the path we think is nested.
        parent (str): the path we think is the ancestor.

    Returns:
        bool: True if child sits under parent (and isn't parent itself), else False.
    """
    child_abs = os.path.abspath(child)
    parent_abs = os.path.abspath(parent)
    if child_abs == parent_abs:
        return False
    try:
        return os.path.commonpath([child_abs, parent_abs]) == parent_abs
    except ValueError:  # e.g. different drives on Windows -> not related
        return False

def _nearest_project_ancestor(directory):
    """Walk up from 'directory' and hand back the closest parent that looks like a project (or None)."""
    path = os.path.abspath(directory)
    parent = os.path.dirname(path)
    while parent and parent != path:
        if _is_recognised(classify_directory(parent)):
            return parent
        path, parent = parent, os.path.dirname(parent)
    return None

def _directory_facts(directory):
    """Dumps a bunch of low-level facts about a path, handy when something looks off."""
    facts = {
        "input": directory,
        "abspath": os.path.abspath(directory),
        "exists": os.path.exists(directory),
        "is_dir": os.path.isdir(directory),
        "is_file": os.path.isfile(directory),
        "readable": os.access(directory, os.R_OK) if os.path.exists(directory) else False,
        "is_symlink": os.path.islink(directory),
        "realpath": os.path.realpath(directory),
    }
    try:
        facts["size_bytes"] = os.path.getsize(directory)
        facts["mtime"] = os.path.getmtime(directory)
    except OSError:
        facts["size_bytes"] = facts["mtime"] = None
    return facts


def _cli():
    """The interactive questionary menu shown when this file is run directly."""
    import sys
    import tempfile
    import questionary
    import db_manager
    import settings

    if not sys.stdin.isatty():
        print("The interactive CLI needs a real terminal. Run: python utils/scanner.py")
        return

    # The current scan is held in a TEMPORARY database (overwritten on each new scan) -> "save long-term" copies it to the permanent database.
    # Every other feature runs against whatever db path is passed in.
    session = {
        "db": os.path.join(tempfile.gettempdir(), "mnemocetus_session.db"),
        "root": None, "mode": "CLASSIFY", "security": True, "count": 0, "saved": False,
    }
    # Runtime state that isn't scan-specific: the loaded user settings and the web dashboard's URL once it's up.
    rt = {"cfg": settings.load(), "web_url": None}

    # One cohesive theme for every prompt: cyan accents, a distinctive pointer, and hotkeys for power users.
    _qstyle = questionary.Style([
        ("qmark",       "fg:#00d7ff bold"),
        ("question",    "bold"),
        ("pointer",     "fg:#00d7ff bold"),
        ("highlighted", "fg:#00d7ff bold"),
        ("selected",    "fg:#5fff87"),
        ("answer",      "fg:#5fff87 bold"),
        ("instruction", "fg:#7f7f7f"),
    ])

    def ask_dir(msg="Enter a directory:"):
        return questionary.path(msg, style=_qstyle).ask()

    def _menu(message, choices, **kwargs):
        """Every menu routes through here -> the shared theme, a '▸' pointer, and number/letter hotkeys."""
        return questionary.select(
            message, choices=choices, style=_qstyle, pointer="▸",
            use_shortcuts=True, **kwargs,
        ).ask()

    def ask_mode():
        """Relationship-mode picker: shows a description on highlight, with the recommended default marked."""
        return _menu(
            "How should nested projects be handled?",
            choices=[
                questionary.Choice("CLASSIFY (recommended)", value="CLASSIFY",
                    description="Map out AND classify every nested project -> the full picture. Best for a normal scan."),
                questionary.Choice("SKIP", value="SKIP",
                    description="Keep only the top-level project; ignore anything nested inside it."),
                questionary.Choice("MERGE", value="MERGE",
                    description="Show nested projects, but treat the whole tree as one merged project."),
                questionary.Choice("SPLIT", value="SPLIT",
                    description="Treat every nested project as its own fully independent project."),
                questionary.Choice("↩ Back (cancel)", value="__back__",
                    description="Picked scan by accident? Go back to the menu without scanning."),
            ],
            default="CLASSIFY",
            show_description=True,
        )

    def _pause():
        """Wait for a keypress so the user can read the output before the menu redraws."""
        questionary.press_any_key_to_continue("Press any key to continue...").ask()

    def _start_web(db_path, port=5000):
        """
        Start the Flask dashboard in a background daemon thread so it's usable alongside the CLI.

        Best-effort: if flask isn't installed or the port is already taken, the CLI just carries on without it.
        The dashboard is pointed at the CLI's current database, so it mirrors whatever you scan.
        """
        try:
            from web.app import create_app
            from werkzeug.serving import run_simple  # serve directly -> avoids Flask's app.run() startup banner
        except ImportError:
            print("[dim]Web dashboard not started (flask isn't installed).[/]")
            return None
        import threading
        import logging
        logging.getLogger("werkzeug").setLevel(logging.ERROR)  # silence the request log + "Running on" banner
        host = "127.0.0.1"
        app = create_app(db_path=db_path)
        def _serve():
            try:
                run_simple(host, port, app, use_reloader=False, use_debugger=False, threaded=True)
            except OSError:
                pass  # port already in use (e.g. the dashboard is already running) -> skip it, the CLI is unaffected
        threading.Thread(target=_serve, daemon=True).start()
        url = f"http://{host}:{port}"
        print(Panel(
            f"Web dashboard live at [bold]{url}[/]\n"
            f"[dim]It mirrors the scan you're working on - refresh the page after each scan.[/]",
            title="Web + CLI", style="cyan"))
        return url

    # --- main actions ---------------------------------------------------- #
    def do_scan():
        directory = ask_dir("Directory to scan (blank to go back):")
        if not directory:
            return
        if not os.path.isdir(directory):
            print(f"'{directory}' isn't a directory.")
            return
        mode = ask_mode()
        if not mode or mode == "__back__":  # "Back" (or cancel) -> no scan, return to the menu
            return
        apply_filters = questionary.confirm("Apply exclude filters (skip node_modules, venv, ...)?", default=True).ask()
        secrets = questionary.confirm("Scan for hard-coded secrets?", default=True).ask()
        # Fresh temporary store -> each scan replaces the last, so it's only held until the next scan.
        if os.path.exists(session["db"]):
            os.remove(session["db"])
        from rich.console import Console
        with Console().status("[cyan]Scanning + classifying...[/]", spinner="dots"):
            _scan_id, count = persist_scan(directory, db_path=session["db"], mode=mode,
                                           confirm_filters=apply_filters, security=secrets)
        session.update(root=directory, mode=mode, security=secrets, count=count, saved=False)
        print(Panel(
            f"Scanned + held in temporary memory: [bold]{count}[/] project(s) under {directory}.\n"
            f"[dim]This lasts until your next scan. Choose 'Save this scan long-term' to keep it; "
            f"all the other features now work on this scan.[/]",
            title="Scan complete", style="green"))
        _pause()

    def do_classify():
        directory = ask_dir("Directory to classify:")
        if not directory:
            return
        info = classify_directory(directory)
        print(Panel(describe(info), title="Best guess", style="cyan"))
        print(info)  # rich pretty-prints the structured dict

    def do_relationships():
        directory = ask_dir("Directory to scan + map:")
        if not directory:
            return
        mode = ask_mode()
        if not mode:
            return
        rels = resolve_directory_relationships(scan_directory(directory), mode=mode)
        if not rels:
            print("No recognised project directories in there.")
            return
        for proj, info in rels.items():
            print(Panel(
                f"type:     {info['type']}\n"
                f"role:     {info['role']}\n"
                f"parent:   {info['parent']}\n"
                f"children: {len(info['children'])}\n"
                f"symlink:  {info['is_symlink']}",
                title=proj, style="cyan"))

    def do_save_longterm():
        if session["root"] is None:
            print("Nothing to save yet -> scan a directory first.")
            return
        dest = os.path.normpath(db_manager.DEFAULT_DB_PATH)

        # Let the user CHECK which scanned projects to keep, then MERGE them in -> the long-term
        # database accumulates across scans (upsert by path), rather than being replaced each time.
        sdb = db_manager.Database(session["db"])
        try:
            projects = sdb.all_projects()
        finally:
            sdb.close()
        if not projects:
            print("Nothing to save -> this scan has no recognised projects.")
            return
        existing = 0
        if os.path.exists(dest):
            edb = db_manager.Database(dest)
            try:
                existing = len(edb.all_projects())
            finally:
                edb.close()
        choices = [questionary.Choice(f"{p['path']}  [{p['language'] or '?'} / {p['category'] or '?'}]",
                                      value=p["path"], checked=True) for p in projects]
        picked = questionary.checkbox(
            f"Which projects to save long-term? (the database already holds {existing})",
            choices=choices, style=_qstyle).ask()
        if not picked:
            print("Nothing checked -> not saved.")
            return

        parent = os.path.dirname(dest)
        if parent:
            os.makedirs(parent, exist_ok=True)
        db = db_manager.Database(dest)
        try:
            n = db.merge_from(session["db"], only_paths=set(picked))
            total = len(db.all_projects())
        finally:
            db.close()
        session["saved"] = True
        print(Panel(f"Merged [bold]{n}[/] project(s) into the long-term database.\n"
                    f"It now holds [bold]{total}[/] project(s) in total.\n[dim]{dest}[/]",
                    title="Saved long-term", style="green"))

    def do_browse(db_path):
        from rich.table import Table

        if not os.path.exists(db_path):
            print("Nothing to browse there yet -> scan a directory first (or pick a saved database).")
            return

        def show_projects(projects):
            if not projects:
                print("No matching projects.")
                return
            table = Table(title=f"{len(projects)} project(s)", box=box.ROUNDED, header_style="bold cyan")
            for col in ("path", "language", "category", "conf", "files", "deps"):
                table.add_column(col, overflow="fold")
            for p in projects:
                table.add_row(
                    p["path"], str(p["language"]), str(p["category"]),
                    f"{p['confidence']:.2f}", str(p["file_count"]), str(len(p["dependencies"])),
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
                        from rich.table import Table
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
                        from rich.table import Table
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
                        from rich.table import Table
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
                    report = db.storage_report()
                    if not report["total_files"]:
                        print("No file inventory recorded yet -> scan a directory first.")
                    else:
                        from rich.table import Table
                        print(Panel(
                            f"Workspace: [bold]{_human_size(report['total_bytes'])}[/] across "
                            f"{report['total_files']} files in {report['project_count']} project(s).\n"
                            f"Reclaimable (regenerable bloat): {_human_size(report['reclaimable_bytes'])}",
                            title="Storage analysis", style="yellow"))
                        proj = Table(title="largest projects", box=box.ROUNDED, header_style="bold cyan")
                        for c in ("project", "size", "reclaimable"):
                            proj.add_column(c, overflow="fold")
                        for p in report["largest_projects"]:
                            proj.add_row(p["path"], _human_size(p["size_bytes"] or 0),
                                         _human_size(p["reclaimable_bytes"] or 0))
                        print(proj)
                        files_t = Table(title="largest files", box=box.ROUNDED, header_style="bold cyan")
                        for c in ("file", "size"):
                            files_t.add_column(c, overflow="fold")
                        for f in report["largest_files"]:
                            files_t.add_row(f["path"], _human_size(f["size_bytes"] or 0))
                        print(files_t)
                        dirs_t = Table(title="largest directories (bytes held directly)", box=box.ROUNDED, header_style="bold cyan")
                        for c in ("directory", "size", "files"):
                            dirs_t.add_column(c, overflow="fold")
                        for d in report["largest_dirs"]:
                            dirs_t.add_row(d["path"], _human_size(d["size_bytes"] or 0), str(d["file_count"]))
                        print(dirs_t)

                elif action == "Security findings (secrets)":
                    summary = db.security_summary()
                    if not summary["total"]:
                        print("No security findings recorded -> secrets are scanned when you scan a directory.")
                    else:
                        from rich.table import Table
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

                elif action == "Export report (Markdown / JSON)":
                    import report
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

    def do_review(db_path):
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
                print(Panel(
                    f"auto guess: {auto['language']} / {auto['category']}  (confidence {auto['confidence']:.2f})\n"
                    f"frameworks: {', '.join(auto['frameworks']) or '(none)'}\n"
                    f"breakdown:  {p['breakdown']['categories']}",
                    title=p["path"], style="yellow"))
                choice = _menu(
                    "What is this project?",
                    choices=[
                        "Accept this guess",
                        "Set the real type",
                        "Delete the project",
                        "Yes to all (accept the rest)",
                        "Skip",
                        "Stop",
                    ],
                )
                if choice in (None, "Stop"):
                    break
                if choice == "Skip":
                    continue
                if choice == "Accept this guess":
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

    # --- Debug Submenu --------------------------------------------------- #
    def do_debug():
        while True:
            check = questionary.select(
                "Debug / checks:",
                choices=[
                    "Is X a child of Y?",
                    "Is a path excluded by the filters?",
                    "Show the compiled exclude rules",
                    "Is it a recognised project?",
                    "Nearest project ancestor",
                    "Symlink info",
                    "Directory facts (low-level dump)",
                    "Classify a single directory",
                    "Resolve relationships (preview, no save)",
                    "Back",
                ],
            ).ask()
            if check in (None, "Back"):
                return

            if check == "Is X a child of Y?":
                child = ask_dir("Child path:")
                parent = ask_dir("Parent path:")
                if child and parent:
                    yes = _is_child(child, parent)
                    print(f"{'✅' if yes else '❌'} '{child}' is "
                          f"{'' if yes else 'NOT '}a child of '{parent}'")

            elif check == "Is a path excluded by the filters?":
                path = questionary.path("Path to test:").ask()
                if path:
                    sc = _default()
                    blocked = _is_excluded(path, sc._name_rules, sc._path_rules)
                    print(f"{'🚫 excluded' if blocked else '✅ kept'} -> {os.path.normpath(path)}")

            elif check == "Show the compiled exclude rules":
                sc = _default()
                name_rules, path_rules = sc._name_rules, sc._path_rules
                print(Panel(
                    f"name rules ({len(name_rules)}):\n{sorted(name_rules)}\n\n"
                    f"path rules ({len(path_rules)}):\n{sorted(path_rules)}",
                    title="Compiled exclude rules", style="yellow"))

            elif check == "Is it a recognised project?":
                directory = ask_dir()
                if directory:
                    info = classify_directory(directory)
                    print(f"{'✅ yes' if _is_recognised(info) else '❌ no'} -> {describe(info)}")

            elif check == "Nearest project ancestor":
                directory = ask_dir()
                if directory:
                    anc = _nearest_project_ancestor(directory)
                    print(f"Nearest project ancestor -> {anc or '(none found)'}")

            elif check == "Symlink info":
                directory = ask_dir()
                if directory:
                    if os.path.islink(directory):
                        print(f"🔗 symlink -> {os.path.realpath(directory)}")
                    else:
                        print("Not a symlink.")

            elif check == "Directory facts (low-level dump)":
                directory = ask_dir()
                if directory:
                    print(_directory_facts(directory))

            elif check == "Classify a single directory":
                do_classify()

            elif check == "Resolve relationships (preview, no save)":
                do_relationships()

    def do_audit():
        directory = ask_dir("Directory to audit (pip-audit / npm audit):")
        if not directory:
            return
        from security import audit_dependencies  # lazy: the audit shells out to optional external tools
        findings = audit_dependencies(directory)
        if not findings:
            print("No vulnerabilities reported (or pip-audit / npm audit isn't installed -> the audit is optional).")
            return
        from rich.table import Table
        table = Table(title=f"Dependency audit -> {directory}", box=box.ROUNDED, header_style="bold cyan")
        for col in ("severity", "package / advisory", "detail"):
            table.add_column(col, overflow="fold")
        for f in findings:
            table.add_row(str(f["severity"]), str(f["rule"]), str(f["detail"]))
        print(table)

    def do_reclaim():
        # The one destructive flow: pick bloat to delete + optionally build a uni-venv, confirm, then execute.
        import db_manager
        from reclaimer import execute_reclaim, create_uni_venv
        db = db_manager.Database(session["db"])
        try:
            recs = db.cleanup_recommendations()
            if not recs["item_count"]:
                print("Nothing to reclaim -> this scan found no regenerable bloat.")
                return

            # 1) choose which KINDS of bloat to delete (Ctrl-C here backs out of the Reclaimer entirely).
            kind_choices = [questionary.Choice(f"{k}  ({v['count']} dir(s), {_human_size(v['bytes'])})", value=k)
                            for k, v in recs["by_kind"].items()]
            chosen_kinds = questionary.checkbox(
                "Select what to DELETE (space toggles, enter confirms, Ctrl-C to go back):",
                choices=kind_choices, style=_qstyle).ask()
            if chosen_kinds is None:
                return
            targets = [it for it in recs["items"] if it["kind"] in set(chosen_kinds)]

            # 2) optionally build one shared uni-venv.
            uni = None
            if questionary.confirm("Also build one shared uni-venv for these projects?", default=False, style=_qstyle).ask():
                py = [p for p in db.all_projects()
                      if (p["language"] or "").startswith("python") and p["dependencies"]]
                if not py:
                    print("No Python projects with dependencies in this scan -> skipping the uni-venv.")
                else:
                    proj_choices = [questionary.Choice(f"{p['path']}  ({len(p['dependencies'])} deps)",
                                                       value=p["path"], checked=True) for p in py]
                    chosen = set(questionary.checkbox("Which projects should the uni-venv cover?",
                                                      choices=proj_choices, style=_qstyle).ask() or [])
                    picked = [p for p in py if p["path"] in chosen]
                    if picked:
                        intel = db.dependency_intel().get("ecosystems", {}).get("python", {})
                        clashing = []
                        for c in intel.get("conflicts", []):
                            versions = {v for v, paths in c["pins"].items() if any(pp in chosen for pp in paths)}
                            if len(versions) >= 2:
                                clashing.append(c["name"])
                        if clashing:
                            print(Panel(
                                f"[yellow]Heads up:[/] these packages are pinned to different exact versions across the "
                                f"chosen projects: [bold]{', '.join(clashing[:6])}[/].\n"
                                f"A single venv holds one version of each -> the install may fail or be wrong.",
                                title="Version conflicts", style="yellow"))
                            if not questionary.confirm("Build the uni-venv anyway?", default=False, style=_qstyle).ask():
                                picked = []
                    if picked:
                        name = questionary.text("uni-venv name:", default=".uni-venv", style=_qstyle).ask() or ".uni-venv"
                        loc = questionary.path("uni-venv location:", default=session["root"], style=_qstyle).ask() or session["root"]
                        deps = sorted({d for p in picked for d in p["dependencies"]})
                        uni = {"path": os.path.normpath(os.path.join(loc, name)),
                               "deps": deps, "projects": [p["path"] for p in picked]}

            if not targets and not uni:
                print("Nothing selected -> Reclaimer cancelled.")
                return

            # 3) show the full plan and require a typed confirmation.
            lines = []
            if targets:
                total = sum(it["size_bytes"] for it in targets)
                lines.append(f"[bold]Delete {len(targets)} director(y/ies)[/], freeing ~[bold]{_human_size(total)}[/]:")
                lines += [f"  [red]-[/] {it['path']}  [dim]({_human_size(it['size_bytes'])})[/]" for it in targets[:20]]
                if len(targets) > 20:
                    lines.append(f"  [dim]... and {len(targets) - 20} more[/]")
            if uni:
                lines.append(f"\n[bold]Create uni-venv[/] at {uni['path']}")
                lines.append(f"  covering {len(uni['projects'])} project(s), installing {len(uni['deps'])} package(s)")
            print(Panel("\n".join(lines), title="Reclaimer plan", style="yellow"))
            print("[bold red]The directories above will be permanently deleted.[/]")
            if questionary.text("Type DELETE to proceed (anything else cancels):", style=_qstyle).ask() != "DELETE":
                print("Cancelled -> nothing was changed.")
                return

            # 4) execute.
            if targets:
                r = execute_reclaim(targets, session["root"])
                summary = f"Deleted [bold]{len(r['deleted'])}[/] dir(s), freed [bold]{_human_size(r['freed_bytes'])}[/]."
                if r["skipped"]:
                    summary += f"\n[yellow]Skipped {len(r['skipped'])}[/] (guarded / already gone)."
                print(Panel(summary, title="Reclaimed", style="green"))
                for p, msg in r["errors"]:
                    print(f"  [red]error[/] {p}: {msg}")
            if uni:
                print(f"[dim]Building uni-venv (installing {len(uni['deps'])} packages, this can take a while)...[/]")
                v = create_uni_venv(uni["path"], uni["deps"])
                if not v["created"]:
                    print(Panel(f"[red]Could not create the venv:[/] {v['error']}", title="uni-venv failed", style="red"))
                elif v["failed"]:
                    print(Panel(f"venv created at [bold]{v['path']}[/], but the install didn't finish.\n[dim]{v['error']}[/]",
                                title="uni-venv (deps not installed)", style="yellow"))
                else:
                    print(Panel(f"uni-venv ready at [bold]{v['path']}[/] with [bold]{v['installed']}[/] package(s).\n"
                                f"[dim]Point your projects/editor at this interpreter to share it.[/]",
                                title="uni-venv created", style="green"))
        finally:
            db.close()

    permanent_db = os.path.normpath(db_manager.DEFAULT_DB_PATH)
    # The web dashboard is opt-in (Settings) -> only auto-start it when the user has turned it on.
    if rt["cfg"]["web_enabled"]:
        rt["web_url"] = _start_web(session["db"], rt["cfg"]["web_port"])

    def _header():
        """A live status bar drawn above the menu -> what's scanned, saved-state, and the web link."""
        if session["root"] is None:
            state = "[dim]no scan yet - start by scanning a directory[/]"
        else:
            saved = "[green]saved ✓[/]" if session["saved"] else "[yellow]unsaved[/]"
            state = f"[green]{session['count']} project(s)[/] from [cyan]{session['root']}[/] [dim]·[/] {saved}"
        web = f"[green]web ▲[/] {rt['web_url']}" if rt["web_url"] else "[dim]web off[/]"
        print(Rule(f"[bold cyan]🐳 MnemoCetus[/]   [dim]│[/]   {state}   [dim]│[/]   {web}",
                   style="cyan", align="left"))

    def do_settings():
        """Toggle global preferences -> the opt-in web dashboard and its port. Persisted to ~/.mnemocetus.json."""
        cfg = rt["cfg"]
        while True:
            action = _menu(
                f"Settings  (web dashboard: {'ON' if cfg['web_enabled'] else 'off'}, port {cfg['web_port']}):",
                choices=[
                    "Turn web dashboard OFF" if cfg["web_enabled"] else "Turn web dashboard ON",
                    "Set web port",
                    "↩ Back",
                ],
            )
            if action in (None, "↩ Back"):
                return
            if action.startswith("Turn web"):
                cfg["web_enabled"] = not cfg["web_enabled"]
                settings.save(cfg)
                if cfg["web_enabled"]:
                    if not rt["web_url"]:
                        rt["web_url"] = _start_web(session["db"], cfg["web_port"])
                    else:
                        print(f"Web dashboard already running at {rt['web_url']}.")
                else:
                    print("Web dashboard disabled -> it won't auto-start next launch (a running server stops when you quit).")
            elif action == "Set web port":
                raw = questionary.text("Web port:", default=str(cfg["web_port"]), style=_qstyle).ask()
                try:
                    cfg["web_port"] = int(raw)
                    settings.save(cfg)
                    print(f"Port set to {cfg['web_port']} (applies the next time the web starts).")
                except (TypeError, ValueError):
                    print("Not a number -> port unchanged.")

    # Step 1 gates everything: you scan first, which auto-holds the result in temporary memory; only then do the analysis features open up (running against that scan until you save it long-term).
    while True:
        _header()
        if session["root"] is None:
            action = _menu(
                "Start here:",
                choices=["Scan a directory", "Open a saved database", "Settings", "Quit"],
            )
            if action in (None, "Quit"):
                print("Bye! 🐳")
                return
            if action == "Scan a directory":
                do_scan()
            elif action == "Open a saved database":
                do_browse(permanent_db)
            elif action == "Settings":
                do_settings()
            continue

        save_label = "Re-save this scan long-term" if session["saved"] else "Save this scan long-term"
        action = _menu(
            "Pick an action:",
            choices=[
                "Explore this scan (browse / search / analyse)",
                save_label,
                "Review low-confidence projects",
                "Dependency vulnerability audit (optional)",
                "Reclaimer (delete bloat / build a uni-venv)",
                "Scan a different directory",
                "Open a saved database",
                "Settings",
                "Debug / checks",
                "Quit",
            ],
        )
        if action in (None, "Quit"):
            print("Bye! 🐳")
            return
        if action.startswith("Explore"):
            do_browse(session["db"])
        elif action.endswith("long-term"):
            do_save_longterm()
            _pause()
        elif action == "Review low-confidence projects":
            do_review(session["db"])
            _pause()
        elif action == "Dependency vulnerability audit (optional)":
            do_audit()
            _pause()
        elif action.startswith("Reclaimer"):
            do_reclaim()
            _pause()
        elif action == "Scan a different directory":
            do_scan()
        elif action == "Open a saved database":
            do_browse(permanent_db)
        elif action == "Settings":
            do_settings()
        elif action == "Debug / checks":
            do_debug()


#👇  Show this in raw format so "\" will print.                          Do you like the ASCII?
BANNER = r"""
                                                                            __________...----..____..-'``-..___
                                                                          ,'.                                  ```--.._
                                                                         :                                             ``._
                                                                        |                           --                    ``.
                                                                        |                <o>   -.-      -.     -   -.        `.
                                                                        : .                   __           --            .     \
                                                                        `._____________     (  `.   -.-      --  -   .   `      \
                                                                          `-----------------\   \_.--------..__..--.._ `. `.    :
ooo        ooooo                                                     .oooooo.                \. /                     `-._ .    |
`88.       .888'                                                    d8P'  `Y8b              .o8                           `.`   |
 888b     d'888  ooo. .oo.    .ooooo.  ooo. .oo.  .oo.    .ooooo.  888           .ooooo.  .o888oo oooo  oooo   .oooo.o      \`  |
 8 Y88. .P  888  `888P"Y88b  d88' `88b `888P"Y88bP"Y88b  d88' `88b 888          d88' `88b   888   `888  `888  d88(  "8       \  |
 8  `888'   888   888   888  888ooo888  888   888   888  888   888 888          888ooo888   888    888   888  `"Y88b.        /  \`
 8    Y     888   888   888  888    .o  888   888   888  888   888 `88b    ooo  888    .o   888 .  888   888  o.  )88b      /   .\
o8o        o888o o888o o888o `Y8bod8P' o888o o888o o888o `Y8bod8P'  `Y8bood8P'  `Y8bod8P'   "888"  `V88V"V8P' 8""888P'     /  __ .\
                                                                                                                          /_,'  \__\
"""

def main():
    """Show the banner, then run the interactive menu. This is the entry point scanner.py hands off to."""
    print(Panel(
        f"[bright_cyan]{BANNER}[/]",
        title="[bold bright_cyan]MnemoCetus[/] [dim]v0.5[/]",
        subtitle="[italic dim]scan · analyse · clean · secure[/]",
        border_style="bright_cyan",
        style="cyan",
    ))
    _cli()


# MAIN
# (run directly, usually for testing)
if __name__ == "__main__":
    main()
