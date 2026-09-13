# Interactive CLI for MnemoCetus (the interactive questionary menu).
#
# This is the human-facing front-end; the engines live in scanner / classifier / cleaner / db_manager.
# Launch it with 'python utils/scanner.py' (which delegates here) or 'python utils/cli.py' directly.

# IMPORTS
from rich import print
from rich.panel import Panel
from rich.rule import Rule
import os

from scanner import persist_scan, _human_size

from cli_tools.ui import _qstyle, _menu, ask_dir, ask_mode, _pause
from cli_tools.actions import do_browse, do_review, do_audit


def _cli():
    """The interactive questionary menu shown when this file is run directly."""
    import sys
    import tempfile
    import questionary
    from db_tools import manager as db_manager
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

    def do_reclaim():
        # The one destructive flow: pick bloat to delete + optionally build a uni-venv, confirm, then execute.
        from db_tools import manager as db_manager
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
