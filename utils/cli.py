# Interactive CLI for MnemoCetus (the interactive questionary menu).
#
# This is the human-facing front-end; the engines live in scanner / classifier / cleaner / db_manager.
# Launch it with 'python utils/scanner.py' (which delegates here) or 'python utils/cli.py' directly.

# IMPORTS
from rich import print
from rich.panel import Panel
import os

from scanner import persist_scan, _human_size


def _cli():
    """The interactive questionary menu shown when this file is run directly."""
    import sys
    import tempfile
    import questionary
    import db_manager

    if not sys.stdin.isatty():
        print("The interactive CLI needs a real terminal. Run: python utils/scanner.py")
        return

    # The current scan is held in a TEMPORARY database (overwritten on each new scan) -> "save long-term" copies it to the permanent database.
    # Every other feature runs against whatever db path is passed in.
    session = {
        "db": os.path.join(tempfile.gettempdir(), "mnemocetus_session.db"),
        "root": None, "mode": "CLASSIFY", "security": True, "count": 0, "saved": False,
    }

    def ask_dir(msg="Enter a directory:"):
        return questionary.path(msg).ask()

    def ask_mode():
        """Relationship-mode picker: shows a description on highlight, with the recommended default marked."""
        return questionary.select(
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
            ],
            default="CLASSIFY",
            show_description=True,
        ).ask()

    # --- main actions ---------------------------------------------------- #
    def do_scan():
        directory = ask_dir("Directory to scan:")
        if not directory:
            return
        if not os.path.isdir(directory):
            print(f"'{directory}' isn't a directory.")
            return
        mode = ask_mode()
        if not mode:
            return
        apply_filters = questionary.confirm("Apply exclude filters (skip node_modules, venv, ...)?", default=True).ask()
        secrets = questionary.confirm("Scan for hard-coded secrets?", default=True).ask()
        # Fresh temporary store -> each scan replaces the last, so it's only held until the next scan.
        if os.path.exists(session["db"]):
            os.remove(session["db"])
        _scan_id, count = persist_scan(directory, db_path=session["db"], mode=mode,
                                       confirm_filters=apply_filters, security=secrets)
        session.update(root=directory, mode=mode, security=secrets, count=count, saved=False)
        print(Panel(
            f"Scanned + held in temporary memory: [bold]{count}[/] project(s) under {directory}.\n"
            f"[dim]This lasts until your next scan. Choose 'Save this scan long-term' to keep it; "
            f"all the other features now work on this scan.[/]",
            title="Scan complete", style="green"))

    def do_save_longterm():
        if session["root"] is None:
            print("Nothing to save yet -> scan a directory first.")
            return
        dest = os.path.normpath(db_manager.DEFAULT_DB_PATH)
        if os.path.exists(dest) and not questionary.confirm(
                f"Save this scan as the long-term database? This replaces the existing {dest}.",
                default=True).ask():
            return
        import shutil
        parent = os.path.dirname(dest)
        if parent:
            os.makedirs(parent, exist_ok=True)
        shutil.copy(session["db"], dest)  # the temp store already holds this scan -> just promote the file
        session["saved"] = True
        print(Panel(f"Saved this scan to the long-term database:\n{dest}",
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
            table = Table(title=f"{len(projects)} project(s)")
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
                action = questionary.select(
                    "Browse the database:",
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
                        "Delete a project",
                        "Back",
                    ],
                ).ask()
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
                        table = Table(show_lines=False)
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
                            table = Table(title="most-shared dependencies")
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
                            t = Table(title=f"{eco} version conflicts")
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
                        proj = Table(title="largest projects")
                        for c in ("project", "size", "reclaimable"):
                            proj.add_column(c, overflow="fold")
                        for p in report["largest_projects"]:
                            proj.add_row(p["path"], _human_size(p["size_bytes"] or 0),
                                         _human_size(p["reclaimable_bytes"] or 0))
                        print(proj)
                        files_t = Table(title="largest files")
                        for c in ("file", "size"):
                            files_t.add_column(c, overflow="fold")
                        for f in report["largest_files"]:
                            files_t.add_row(f["path"], _human_size(f["size_bytes"] or 0))
                        print(files_t)
                        dirs_t = Table(title="largest directories (bytes held directly)")
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
                        t = Table()
                        for col in ("severity", "kind", "rule", "location", "detail"):
                            t.add_column(col, overflow="fold")
                        for f in summary["findings"]:
                            loc = f"{f['path']}:{f['line']}" if f["line"] else f["path"]
                            t.add_row(str(f["severity"]), str(f["kind"]), str(f["rule"]), loc, str(f["detail"]))
                        print(t)

                elif action == "Delete a project":
                    directory = ask_dir("Project path to delete:")
                    if directory and questionary.confirm(f"Delete '{directory}' from the DB?", default=False).ask():
                        ok = db.delete_project(directory)
                        print("Deleted." if ok else "Nothing matched that path.")
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
                choice = questionary.select(
                    "What is this project?",
                    choices=[
                        "Accept this guess",
                        "Set the real type",
                        "Delete the project",
                        "Yes to all (accept the rest)",
                        "Skip",
                        "Stop",
                    ],
                ).ask()
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
                    category = questionary.select(
                        "Category:",
                        choices=["backend", "frontend", "full stack", "automation", "library",
                                 "cli", "desktop", "application", "data/ml", "other"],
                    ).ask()
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
        from rich.table import Table
        table = Table(title=f"Dependency audit -> {directory}")
        for col in ("severity", "package / advisory", "detail"):
            table.add_column(col, overflow="fold")
        for f in findings:
            table.add_row(str(f["severity"]), str(f["rule"]), str(f["detail"]))
        print(table)

    permanent_db = os.path.normpath(db_manager.DEFAULT_DB_PATH)

    # Step 1 gates everything: you scan first, which auto-holds the result in temporary memory; only then do the analysis features open up (running against that scan until you save it long-term).
    while True:
        if session["root"] is None:
            action = questionary.select(
                "MnemoCetus -> start by scanning a directory:",
                choices=["Scan a directory", "Open a saved database", "Quit"],
            ).ask()
            if action in (None, "Quit"):
                print("Bye! 🐳")
                return
            if action == "Scan a directory":
                do_scan()
            elif action == "Open a saved database":
                do_browse(permanent_db)
            continue

        held = "saved long-term ✓" if session["saved"] else "temporary — not saved yet"
        save_label = "Re-save this scan long-term" if session["saved"] else "Save this scan long-term"
        action = questionary.select(
            f"MnemoCetus -> {session['count']} project(s) from {session['root']}  [{held}]",
            choices=[
                "Explore this scan (browse / search / analyse)",
                save_label,
                "Review low-confidence projects",
                "Dependency vulnerability audit (optional)",
                "Scan a different directory",
                "Open a saved database",
                "Quit",
            ],
        ).ask()
        if action in (None, "Quit"):
            print("Bye! 🐳")
            return
        if action.startswith("Explore"):
            do_browse(session["db"])
        elif action.endswith("long-term"):
            do_save_longterm()
        elif action == "Review low-confidence projects":
            do_review(session["db"])
        elif action == "Dependency vulnerability audit (optional)":
            do_audit()
        elif action == "Scan a different directory":
            do_scan()
        elif action == "Open a saved database":
            do_browse(permanent_db)


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
    print(Panel(BANNER, title="v0.5", subtitle="MnemoCetus", style="cyan"))
    _cli()


# MAIN
# (run directly, usually for testing)
if __name__ == "__main__":
    main()
