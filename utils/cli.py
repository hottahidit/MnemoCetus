# Interactive CLI for MnemoCetus (the questionary menu + debug tools).
#
# This is the human-facing front-end; the engines live in scanner / classifier / cleaner / db_manager.
# Launch it with 'python utils/scanner.py' (which delegates here) or 'python utils/cli.py' directly.

# IMPORTS
from rich import print
from rich.columns import Columns
from rich.panel import Panel
import os

from scanner import (
    scan_directory, classify_directory, resolve_directory_relationships,
    identify_directory_type, persist_scan, describe, _is_recognised,
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
    import questionary

    if not sys.stdin.isatty():
        print("The interactive CLI needs a real terminal. Run: python utils/scanner.py")
        return

    def ask_dir(msg="Enter a directory:"):
        return questionary.path(msg).ask()

    # --- main actions ---------------------------------------------------- #
    def do_scan():
        directory = ask_dir("Directory to scan:")
        if not directory:
            return
        apply_filters = questionary.confirm("Apply exclude filters?", default=True).ask()
        files = scan_directory(directory, confirm_filters=apply_filters)
        total_gb = sum(os.path.getsize(f) for f in files) / 1073741824
        print(Panel(
            f"Scanned [bold]{len(files)}[/] files, ~{total_gb:.2f} GB\n"
            f"Type: {identify_directory_type(directory)}\n"
            f"Filters: {'applied' if apply_filters else 'skipped'}",
            title=f"Scan -> {directory}", style="green"))
        if files and questionary.confirm("Show the file list?", default=False).ask():
            print(Columns(files))

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
        mode = questionary.select("Relationship mode:",
                                  choices=["CLASSIFY", "SKIP", "MERGE", "SPLIT"]).ask()
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

    def do_persist():
        import db_manager  # lazy: only needed once you actually save to the DB
        directory = ask_dir("Directory to scan + store:")
        if not directory:
            return
        mode = questionary.select("Relationship mode:",
                                  choices=["CLASSIFY", "SKIP", "MERGE", "SPLIT"]).ask()
        if not mode:
            return
        scan_id, count = persist_scan(directory, mode=mode)
        print(Panel(
            f"Stored [bold]{count}[/] projects\n"
            f"scan id:  {scan_id}\n"
            f"database: {os.path.normpath(db_manager.DEFAULT_DB_PATH)}",
            title="Saved to database", style="green"))

    def do_browse():
        import db_manager  # lazy: the DB layer is only needed for browsing
        from rich.table import Table

        db_path = questionary.path(
            "Database file:", default=os.path.normpath(db_manager.DEFAULT_DB_PATH)
        ).ask()
        if not db_path:
            return
        if not os.path.exists(db_path):
            print(f"No database at '{db_path}' yet. Run 'Scan + save to database' first.")
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

                elif action == "Delete a project":
                    directory = ask_dir("Project path to delete:")
                    if directory and questionary.confirm(f"Delete '{directory}' from the DB?", default=False).ask():
                        ok = db.delete_project(directory)
                        print("Deleted." if ok else "Nothing matched that path.")
        finally:
            db.close()

    def do_review():
        import db_manager  # lazy: only needed when reviewing stored projects
        db_path = questionary.path(
            "Database file:", default=os.path.normpath(db_manager.DEFAULT_DB_PATH)
        ).ask()
        if not db_path:
            return
        if not os.path.exists(db_path):
            print(f"No database at '{db_path}' yet. Run 'Scan + save to database' first.")
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

    actions = {
        "Scan a directory": do_scan,
        "Classify a directory": do_classify,
        "Resolve relationships (scan + map)": do_relationships,
        "Scan + save to database": do_persist,
        "Browse the database": do_browse,
        "Review low-confidence projects": do_review,
        "Debug / checks": do_debug,
    }
    while True:
        action = questionary.select("MnemoCetus -> pick an action:",
                                    choices=list(actions) + ["Quit"]).ask()
        if action in (None, "Quit"):
            print("Bye! 🐳")
            return
        actions[action]()


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
    print(Panel(BANNER, title="v0.4", subtitle="MnemoCetus", style="cyan"))
    _cli()


# MAIN
# (run directly, usually for testing)
if __name__ == "__main__":
    main()
