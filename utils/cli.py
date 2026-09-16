# Interactive CLI for MnemoCetus (the questionary menu + debug tools).
#
# This is the human-facing front-end; the engines live in scanner / classifier / cleaner / db_manager.
# Launch it with 'python utils/scanner.py' (which delegates here) or 'python utils/cli.py' directly.

# IMPORTS
from rich import print
from rich.panel import Panel
from rich.rule import Rule
import os

from scanner import (
    scan_directory, classify_directory, resolve_directory_relationships,
    persist_scan, describe, _is_recognised,
    _is_excluded, _default, _human_size,
)

from cli_tools.ui import _qstyle, _menu, ask_dir, ask_mode, _pause
from cli_tools.actions import do_browse, do_review, do_audit


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
    from db_tools import manager as db_manager
    import settings
    import arbiter

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

    # --- AI arbiter (opt-in; nothing here runs unless the user enabled it) ---- #
    def _configure_arbiter(cfg):
        """Interactive setup for the AI arbiter block -> shared by the first-run wizard and Settings."""
        ac = cfg["arbiter"]
        enabled = questionary.confirm(
            "Enable the AI arbiter? An optional second opinion on low-confidence projects (off by default).",
            default=ac["enabled"], style=_qstyle).ask()
        if enabled is None:
            return
        ac["enabled"] = enabled
        if not enabled:
            settings.save(cfg)
            print("AI arbiter is off.")
            return
        provider = _menu("AI provider:", choices=list(arbiter.PRESETS.keys()) + ["custom"])
        if provider is None:
            return
        ac["provider"] = provider
        preset = arbiter.PRESETS.get(provider, {})
        default_base = ac["base_url"] if provider == "custom" else preset.get("base_url", ac["base_url"])
        ac["base_url"] = questionary.text("Base URL:", default=default_base, style=_qstyle).ask() or default_base
        local = arbiter.is_local(ac["base_url"])
        # Model: for OpenAI-compatible endpoints try to list what's available; otherwise ask by name.
        models = None
        if provider not in ("anthropic", "gemini"):
            key = os.environ.get(preset.get("api_key_env", "")) if preset.get("api_key_env") else None
            models = arbiter.list_models(ac["base_url"], key)
        if models:
            pick = _menu("Model:", choices=models + ["(enter manually)"])
            if pick in (None, "(enter manually)"):
                ac["model"] = questionary.text("Model name:", default=ac["model"] or preset.get("model", ""),
                                               style=_qstyle).ask() or ac["model"]
            else:
                ac["model"] = pick
        else:
            ac["model"] = questionary.text("Model name:", default=ac["model"] or preset.get("model", ""),
                                           style=_qstyle).ask() or ac["model"]
        if local:
            ac["api_key_env"] = ""
        else:
            print(Panel(
                "This is a CLOUD endpoint -> project paths are REDACTED to folder names only (e.g. 'SokaOS'), "
                "never absolute paths. Dependency, marker and language signals are still sent.",
                title="Privacy", style="yellow"))
            default_env = ac["api_key_env"] or preset.get("api_key_env", "")
            ac["api_key_env"] = questionary.text(
                "Name of the env var holding the API key:", default=default_env, style=_qstyle).ask() or default_env
        ac["run_after_scan"] = bool(questionary.confirm(
            "Run the arbiter automatically after a scan (on low-confidence projects, before you review them)?",
            default=ac["run_after_scan"], style=_qstyle).ask())
        settings.save(cfg)
        if questionary.confirm("Test the connection now?", default=True, style=_qstyle).ask():
            ok, msg = arbiter.get_provider(ac).ping()
            print(Panel(f"{'✅' if ok else '❌'} {msg}", title="Arbiter connection",
                        style="green" if ok else "red"))

    def _setup_wizard(cfg):
        """One-time first-run setup (web dashboard + AI arbiter). Records 'configured' so it never repeats."""
        print(Panel(
            "Welcome to MnemoCetus 🐳\nA quick one-time setup -> you can change any of this later in Settings.",
            title="First-run setup", style="cyan"))
        cfg["web_enabled"] = bool(questionary.confirm(
            "Auto-start the web dashboard alongside the CLI?", default=cfg["web_enabled"], style=_qstyle).ask())
        _configure_arbiter(cfg)
        cfg["configured"] = True
        settings.save(cfg)
        print("[green]Setup complete.[/]\n")

    def _arbitrate(db_path, ask=True):
        """Run the arbiter over the current scan's low-confidence projects -> {path: suggestion}."""
        ac = rt["cfg"]["arbiter"]
        if not ac["enabled"]:
            print("AI arbiter is off -> turn it on in Settings first.")
            return {}
        if not os.path.exists(db_path):
            print("Nothing to arbitrate -> scan a directory first.")
            return {}
        db = db_manager.Database(db_path)
        try:
            pending = db.low_confidence_projects()
        finally:
            db.close()
        if not pending:
            print("No low-confidence projects -> nothing for the arbiter to weigh in on.")
            return {}
        if ask and not questionary.confirm(
                f"Ask the arbiter about {len(pending)} low-confidence project(s)?",
                default=True, style=_qstyle).ask():
            return {}
        from rich.console import Console
        suggestions = {}
        with Console().status("[cyan]Consulting the arbiter...[/]", spinner="dots"):
            for p in pending:
                s = arbiter.classify_project(p, ac, workspace_root=session["root"])
                if s:
                    suggestions[p["path"]] = s
        print(f"Arbiter offered {len(suggestions)} suggestion(s) across {len(pending)} project(s).")
        return suggestions

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
        from rich.progress import (Progress, SpinnerColumn, TextColumn, BarColumn,
                                    MofNCompleteColumn, TimeElapsedColumn, TimeRemainingColumn)
        # Indeterminate spinner during the walk (total unknown), then a real bar as projects are stored.
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}[/]"), BarColumn(),
                      MofNCompleteColumn(), TimeElapsedColumn(), TimeRemainingColumn(),
                      transient=True) as _prog:
            _task = _prog.add_task("Scanning workspace...", total=None)
            def _on_progress(done, total):
                _prog.update(_task, total=total, completed=done, description="Classifying + storing")
            _scan_id, count = persist_scan(directory, db_path=session["db"], mode=mode,
                                           confirm_filters=apply_filters, security=secrets,
                                           workers=rt["cfg"].get("scan_workers") or None,
                                           progress=_on_progress)
        session.update(root=directory, mode=mode, security=secrets, count=count, saved=False)
        print(Panel(
            f"Scanned + held in temporary memory: [bold]{count}[/] project(s) under {directory}.\n"
            f"[dim]This lasts until your next scan. Choose 'Save this scan long-term' to keep it; "
            f"all the other features now work on this scan.[/]",
            title="Scan complete", style="green"))
        # Opt-in: weigh in on the uncertain ones with the arbiter, then drop into review, before the user moves on.
        if rt["cfg"]["arbiter"]["enabled"] and rt["cfg"]["arbiter"]["run_after_scan"]:
            sug = _arbitrate(session["db"], ask=False)
            if sug:
                do_review(session["db"], sug)
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

    # First-run setup wizard -> runs once, then records 'configured' so it never nags again.
    if not rt["cfg"].get("configured"):
        _setup_wizard(rt["cfg"])

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

    def _autotune():
        """Benchmark a throwaway workspace across worker counts and save the fastest for this machine."""
        import tuning
        from rich.table import Table
        from rich import box
        from rich.progress import (Progress, SpinnerColumn, TextColumn, BarColumn,
                                    MofNCompleteColumn, TimeElapsedColumn)
        if not questionary.confirm(
                "Build a small test workspace and time a few scans to find this machine's best worker "
                "count? (~15-40s; nothing is kept)", default=True, style=_qstyle).ask():
            return
        with Progress(SpinnerColumn(), TextColumn("[cyan]Auto-tuning scan workers[/]"), BarColumn(),
                      MofNCompleteColumn(), TimeElapsedColumn(), transient=True) as prog:
            task = prog.add_task("tuning", total=None)
            best, results = tuning.autotune(
                progress=lambda done, total: prog.update(task, total=total, completed=done))
        table = Table(title="Auto-tune results", box=box.ROUNDED, header_style="bold cyan")
        table.add_column("workers")
        table.add_column("time (s)")
        for w, sec in results:
            table.add_row(f"{w}  ⭐" if w == best else str(w), f"{sec:.3f}")
        print(table)
        rt["cfg"]["scan_workers"] = best
        settings.save(rt["cfg"])
        print(Panel(f"Saved -> scans on this machine will use [bold]{best}[/] worker(s).\n"
                    f"[dim]Reset to automatic by re-tuning or editing ~/.mnemocetus.json (scan_workers: 0).[/]",
                    title="Auto-tune complete", style="green"))

    def do_settings():
        """Toggle global preferences -> web dashboard, AI arbiter, and scan auto-tuning. Persisted to ~/.mnemocetus.json."""
        cfg = rt["cfg"]
        while True:
            action = _menu(
                f"Settings  (web: {'ON' if cfg['web_enabled'] else 'off'} · "
                f"AI arbiter: {'ON' if cfg['arbiter']['enabled'] else 'off'} · "
                f"scan workers: {cfg['scan_workers'] or 'auto'}):",
                choices=[
                    "Turn web dashboard OFF" if cfg["web_enabled"] else "Turn web dashboard ON",
                    "Set web port",
                    "Configure AI arbiter",
                    "Auto-tune scan performance",
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
            elif action == "Configure AI arbiter":
                _configure_arbiter(cfg)
            elif action == "Auto-tune scan performance":
                _autotune()

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
                "AI: re-classify uncertain projects",
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
        elif action.startswith("AI:"):
            sug = _arbitrate(session["db"])
            if sug:
                do_review(session["db"], sug)
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
