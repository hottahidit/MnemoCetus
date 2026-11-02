# The `nemc` subcommands -> argparse wiring + terminal rendering over mnemocetus.ops.
#
#   nemc                      interactive menu
#   nemc scan [DIR]           scan (incremental) + show what changed + save to the long-term DB
#   nemc rescan [PATH]        re-scan every saved folder (or the one containing PATH)
#   nemc changes [DIR]        scan WITHOUT saving -> just "what changed since last save"
#   nemc status [PATH]        clean / changed / security / unscanned for the project at PATH
#   nemc projects             list / filter saved projects
#   nemc secrets [DIR]        stored security findings (or --history: scan a repo's whole git history)
#   nemc audit [DIR]          optional dependency vulnerability audit (pip-audit / npm audit)
#   nemc reclaim              plan (default) or --execute the deletion of regenerable bloat
#   nemc serve                run the web dashboard
#   nemc db                   database path / stats / --report export
#   nemc init <shell>         prompt status light + tab-completion: eval "$(nemc init zsh)"
#
# Every read command takes --json for scripting. The long-term DB can be pointed elsewhere with the
# global --db (or $MNEMOCETUS_DB).

import argparse
import json
import os
import sys

from mnemocetus import __version__, ops

EXIT_OK, EXIT_ERROR, EXIT_FINDINGS = 0, 1, 3
STATUS_EXIT = {ops.CLEAN: 0, ops.CHANGED: 1, ops.SECURITY: 2, ops.UNSCANNED: 3, ops.UNKNOWN: 4}


# --------------------------------------------------------------------------- #
# Output helpers
# --------------------------------------------------------------------------- #
def _console(stderr=False):
    from rich.console import Console
    return Console(stderr=stderr, highlight=False)


def _out(*objs):
    from mnemocetus.utils import safe_print
    safe_print(*objs)


def _json(data):
    print(json.dumps(data, indent=2, default=str))


def _esc(text):
    from rich.markup import escape
    return escape(str(text))


def _size(n):
    from mnemocetus.utils import human_size
    return human_size(n or 0)


def _table(title, columns, rows, style="bold cyan"):
    from rich import box
    from rich.table import Table
    t = Table(title=title, box=box.ROUNDED, header_style=style)
    for c in columns:
        t.add_column(c, overflow="fold")
    for r in rows:
        t.add_row(*[_esc(x) for x in r])
    return t


def _need_db(args):
    path = ops.long_term_db(args.db)
    if not os.path.exists(path):
        print(f"No saved database yet at {path}. Run `nemc scan <dir>` first.", file=sys.stderr)
        return None
    return path


# --------------------------------------------------------------------------- #
# scan / rescan / changes
# --------------------------------------------------------------------------- #
def _progress_cb(enabled):
    """A rich progress bar on stderr for an interactive terminal, else None (pipes / --json stay clean)."""
    if not enabled or not sys.stderr.isatty():
        return None, None
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn, TimeElapsedColumn
    prog = Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}[/]"), BarColumn(),
                    MofNCompleteColumn(), TimeElapsedColumn(), transient=True, console=_console(stderr=True))
    task = prog.add_task("Scanning", total=None)

    def cb(done, total):
        prog.update(task, total=total, completed=done, description="Classifying + storing")
    return prog, cb


def _render_scan(res, show_changes=True):
    from rich.panel import Panel
    from mnemocetus import insight
    saved = (f"saved {res['saved']} project(s) to {_esc(res['db'])}" if res["saved"] is not None
             else "[yellow]not saved[/] (--no-save)")
    body = (f"[bold]{res['project_count']}[/] project(s), {res['file_count']} file(s), "
            f"{_size(res['total_bytes'])} under [bold]{_esc(res['root'])}[/]\n{saved}")
    if res["pruned"]:
        body += f"\n[dim]removed {len(res['pruned'])} project(s) whose folder no longer exists[/]"
    _out(Panel(body, title="Scan", style="green"))
    ch = res["changes"]
    if not show_changes:
        return
    if ch is None:
        _out("[dim]First save -> nothing to compare against yet; the next scan will show what changed.[/]")
        return
    if not insight.has_changes(ch):
        _out("[green]No changes since the last save.[/]")
        return
    from mnemocetus.cli.actions import show_changes
    show_changes(ch)


def _scan_kwargs(args):
    return dict(mode=args.mode, filters=not args.no_filters, secrets=not args.no_secrets,
                workers=args.workers)


def _scan_exit(results, args):
    if getattr(args, "fail_on_findings", False) and any(
            (r["changes"] or {}).get("new_findings") for r in results):
        return EXIT_FINDINGS
    return EXIT_OK


def cmd_scan(args, save=True):
    prog, cb = _progress_cb(not args.json)
    try:
        if prog:
            prog.start()
        res = ops.scan(args.directory, db_path=args.db, save=save and not args.no_save,
                       progress=cb, **_scan_kwargs(args))
    except NotADirectoryError as e:
        print(f"nemc: {e}", file=sys.stderr)
        return EXIT_ERROR
    finally:
        if prog:
            prog.stop()
    if args.json:
        _json(res)
    else:
        _render_scan(res)
    return _scan_exit([res], args)


def cmd_changes(args):
    args.no_save = True
    return cmd_scan(args, save=False)


def cmd_rescan(args):
    roots = ops.saved_roots(args.db)
    if not roots and not args.path:
        print("Nothing saved to re-scan yet. Run `nemc scan <dir>` first.", file=sys.stderr)
        return EXIT_ERROR
    prog, cb = _progress_cb(not args.json)
    try:
        if prog:
            prog.start()
        results = ops.rescan(args.path, db_path=args.db, save=not args.no_save, progress=cb, **_scan_kwargs(args))
    finally:
        if prog:
            prog.stop()
    if args.json:
        _json(results)
    else:
        for res in results:
            _render_scan(res)
    return _scan_exit(results, args)


# --------------------------------------------------------------------------- #
# status
# --------------------------------------------------------------------------- #
_LIGHT = {  # state -> (glyph, ANSI colour code, zsh colour name, label)
    ops.CLEAN: ("●", "32", "green", "up to date"),
    ops.CHANGED: ("●", "33", "yellow", "changed since last scan"),
    ops.SECURITY: ("●", "31", "red", "security findings"),
    ops.UNKNOWN: ("◌", "90", "8", "unknown"),
}


def prompt_segment(state, shell="plain"):
    """The coloured status-light glyph for a shell prompt ('' when unscanned -> no light at all)."""
    if state not in _LIGHT:
        return ""
    glyph, ansi, zsh_colour, _ = _LIGHT[state]
    if shell == "zsh":
        return f"%F{{{zsh_colour}}}{glyph}%f"
    if shell == "bash":  # \001 / \002 tell readline the escape codes take no width (no line-wrap glitches)
        return f"\001\033[{ansi}m\002{glyph}\001\033[0m\002"
    if shell == "none":
        return glyph
    return f"\033[{ansi}m{glyph}\033[0m"  # plain ANSI: fish, or anything that just prints


def cmd_status(args):
    if args.prompt:
        # Inside a prompt: never print errors, never hang -> a short budget and a silent failure.
        try:
            st = ops.status(args.path, db_path=args.db, budget=args.budget or 0.25)
        except Exception:  # noqa: BLE001 -> a broken DB must not break the user's shell prompt
            return EXIT_OK
        sys.stdout.write(prompt_segment(st["state"], args.shell))
        return EXIT_OK
    st = ops.status(args.path, db_path=args.db, budget=args.budget)
    if args.json:
        _json(st)
    else:
        glyph, ansi, _, label = _LIGHT.get(st["state"], ("○", "2", "", "not scanned"))
        colour = {"32": "green", "33": "yellow", "31": "red", "90": "bright_black"}.get(ansi, "dim")
        where = (f"{_esc(st['project'])}  [dim]({_esc(st['language'] or '?')} / {_esc(st['category'] or '?')})[/]"
                 if st["project"] else _esc(st["path"]))
        _out(f"[{colour}]{glyph} {label}[/]  {where}")
        _out(f"  [dim]{_esc(st['reason'])}" + (f" · last saved {_esc(st['scanned_at'])}" if st["scanned_at"] else "") + "[/]")
    return STATUS_EXIT.get(st["state"], 0) if args.exit_code else EXIT_OK


# --------------------------------------------------------------------------- #
# projects / secrets / audit
# --------------------------------------------------------------------------- #
def cmd_projects(args):
    path = _need_db(args)
    if not path:
        return EXIT_ERROR
    from mnemocetus.db import manager as db_manager
    with db_manager.Database(path) as db:
        projects = db.find_projects(language=args.language, category=args.category, framework=args.framework)
    if args.under:
        u = os.path.abspath(os.path.expanduser(args.under))
        projects = [p for p in projects if ops._under(p["path"], u)]
    if args.uncertain:
        projects = [p for p in projects if not p["user_confirmed"] and (p["confidence"] or 0) < 0.6]
    if args.json:
        _json([{k: p.get(k) for k in ("path", "language", "category", "frameworks", "confidence", "user_confirmed",
                                      "file_count", "size_bytes", "reclaimable_bytes", "dependencies",
                                      "git_branch", "git_dirty", "git_ahead")} for p in projects])
        return EXIT_OK
    from mnemocetus import gitinfo
    _out(_table(f"{len(projects)} project(s)", ("path", "language", "category", "conf", "size", "reclaimable", "git"),
                [(p["path"], p["language"] or "?", p["category"] or "?", f"{p['confidence']:.2f}",
                  _size(p["size_bytes"]), _size(p["reclaimable_bytes"]) if p["reclaimable_bytes"] else "-",
                  gitinfo.badge_from_row(p)) for p in projects]))
    return EXIT_OK


def cmd_secrets(args):
    if args.history:
        from mnemocetus import gitinfo
        from mnemocetus.security import scan_git_history, HistoryScanError
        target = os.path.abspath(os.path.expanduser(args.directory or "."))
        if not gitinfo.status(target).get("is_repo"):
            print(f"nemc: {target} is not a git repository", file=sys.stderr)
            return EXIT_ERROR
        try:
            findings = scan_git_history(target)
        except HistoryScanError as e:
            print(f"nemc: git history scan incomplete ({e}) -> the result is unknown, NOT clean", file=sys.stderr)
            return EXIT_ERROR
        title = f"Secrets in git history -> {target}"
    else:
        path = _need_db(args)
        if not path:
            return EXIT_ERROR
        from mnemocetus.db import manager as db_manager
        with db_manager.Database(path) as db:
            findings = db.security_summary(limit=100000)["findings"]
        if args.directory:
            u = os.path.abspath(os.path.expanduser(args.directory))
            findings = [f for f in findings if ops._under(f.get("project_path") or f["path"], u)]
        title = "Stored security findings (values masked)"
    if args.json:
        _json(findings)
    elif not findings:
        _out("[green]No security findings.[/]")
    else:
        _out(_table(f"{title} ({len(findings)})", ("severity", "kind", "rule", "location", "detail"),
                    [(f["severity"], f["kind"], f["rule"], f"{f['path']}:{f['line']}" if f["line"] else f["path"],
                      f["detail"]) for f in findings], style="bold red"))
    return EXIT_FINDINGS if (findings and args.fail_on_findings) else EXIT_OK


def cmd_audit(args):
    from mnemocetus.security import audit_dependencies
    target = os.path.abspath(os.path.expanduser(args.directory or "."))
    findings = audit_dependencies(target)
    if args.json:
        _json(findings)
    elif not findings:
        _out("No vulnerabilities reported [dim](or pip-audit / npm audit isn't installed -> the audit is optional)[/]")
    else:
        _out(_table(f"Dependency audit -> {target}", ("severity", "package / advisory", "detail"),
                    [(f["severity"], f["rule"], f["detail"]) for f in findings], style="bold red"))
    return EXIT_FINDINGS if (findings and args.fail_on_findings) else EXIT_OK


# --------------------------------------------------------------------------- #
# reclaim
# --------------------------------------------------------------------------- #
def cmd_reclaim(args):
    if not _need_db(args):
        return EXIT_ERROR
    plan = ops.reclaim_plan(args.db, kinds=set(args.kind) if args.kind else None,
                            min_bytes=int(args.min_mb * 1024 * 1024), under=args.under)
    items = plan["items"]
    if args.json and not args.execute:
        _json(plan)
        return EXIT_OK
    if not items:
        _out("Nothing to reclaim with those filters.")
        return EXIT_OK
    from mnemocetus.reclaimer import _safe_to_delete
    checked = [(it, _safe_to_delete(it["path"], it["root"]) if it["root"] else (False, "not inside a saved scan folder"))
               for it in items]
    ok_items = [it for it, (ok, _) in checked if ok]
    refused = [(it, why) for it, (ok, why) in checked if not ok]
    if not args.json:
        _out(_table(f"Reclaim plan: {len(ok_items)} director(y/ies), ~{_size(sum(i['size_bytes'] or 0 for i in ok_items))}",
                    ("directory", "kind", "size", "regenerate with"),
                    [(i["path"], i["kind"], _size(i["size_bytes"]), i["reason"] or "") for i in ok_items]))
        if refused:
            _out(_table(f"Kept by the safety guard ({len(refused)})", ("directory", "why"),
                        [(i["path"], why) for i, why in refused], style="bold yellow"))
    if not args.execute:
        if not args.json:
            _out("[dim]Dry run -> nothing deleted. Add --execute to delete the planned directories.[/]")
        return EXIT_OK
    if not ok_items:
        return EXIT_OK
    if not args.yes:
        if not sys.stdin.isatty():
            print("nemc: refusing to delete without confirmation (use --yes in scripts)", file=sys.stderr)
            return EXIT_ERROR
        if input("Type DELETE to permanently delete the directories above: ").strip() != "DELETE":
            print("Cancelled -> nothing deleted.")
            return EXIT_OK
    from mnemocetus.reclaimer import execute_reclaim
    by_root = {}
    for it in ok_items:
        by_root.setdefault(it["root"], []).append(it)
    deleted, skipped, errors, freed = [], [], [], 0
    for root, group in by_root.items():
        r = execute_reclaim(group, root)  # re-checks every path with the guard at delete time
        deleted += r["deleted"]
        skipped += r["skipped"]
        errors += r["errors"]
        freed += r["freed_bytes"]
    if args.json:
        _json({"deleted": deleted, "freed_bytes": freed, "skipped": skipped, "errors": errors})
    else:
        _out(f"[green]Deleted {len(deleted)} director(y/ies), freed ~{_size(freed)}.[/]"
             + (f" [yellow]{len(skipped)} skipped, {len(errors)} error(s).[/]" if skipped or errors else ""))
        _out("[dim]Run `nemc rescan` to refresh the stored sizes.[/]")
    return EXIT_ERROR if errors else EXIT_OK


# --------------------------------------------------------------------------- #
# serve / db
# --------------------------------------------------------------------------- #
def _host_names(host):
    """Hostnames a browser may use to reach a non-loopback bind (the web app rejects any other Host header)."""
    import socket
    names = {host}
    if host in ("0.0.0.0", "::"):
        try:
            hn = socket.gethostname()
            names |= {hn, socket.getfqdn()}
            names |= {ai[4][0] for ai in socket.getaddrinfo(hn, None)}
        except OSError:
            pass
    return {n.lower() for n in names if n}


def cmd_serve(args):
    try:
        from mnemocetus.web.app import create_app, LOCAL_HOSTS
    except ImportError:
        print("nemc: the web dashboard needs flask (pip install flask)", file=sys.stderr)
        return EXIT_ERROR
    db = ops.long_term_db(args.db)
    app = create_app(db_path=db)
    allowed = set(LOCAL_HOSTS) | {h.lower() for h in args.allow_host}
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        allowed |= _host_names(args.host)
        print(f"WARNING: serving on {args.host} exposes your project paths, git state and masked secret "
              f"previews to the network. There is no login. Allowed Host names: {', '.join(sorted(allowed))}",
              file=sys.stderr)
    app.config["ALLOWED_HOSTS"] = allowed
    shown = "127.0.0.1" if args.host in ("0.0.0.0", "::") else args.host
    print(f"MnemoCetus dashboard -> http://{shown}:{args.port}  (database: {db})  Ctrl-C to stop")
    from werkzeug.serving import run_simple
    try:
        run_simple(args.host, args.port, app, use_reloader=False, use_debugger=False, threaded=True)
    except OSError as e:
        print(f"nemc: could not bind {args.host}:{args.port} ({e})", file=sys.stderr)
        return EXIT_ERROR
    return EXIT_OK


def cmd_db(args):
    path = ops.long_term_db(args.db)
    if args.path:
        print(path)
        return EXIT_OK
    if not _need_db(args):
        return EXIT_ERROR
    from mnemocetus import report
    if args.report:
        body = report.render(report.build_report(path), args.format)
        if args.output:
            with open(args.output, "w", encoding="utf-8") as fh:
                fh.write(body)
            print(f"Report written to {args.output} ({len(body):,} bytes)", file=sys.stderr)
        else:
            sys.stdout.write(body)
        return EXIT_OK
    from mnemocetus.db import manager as db_manager
    with db_manager.Database(path) as db:
        projects = db.all_projects()
        sec = db.security_summary(limit=0)
        rec = db.reclaimable_summary()
        n_scans = db.con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    stats = {"database": path, "projects": len(projects), "total_bytes": sum(p["size_bytes"] or 0 for p in projects),
             "reclaimable_bytes": rec["total_bytes"], "security_findings": sec["total"], "scans": n_scans,
             "saved_roots": ops.saved_roots(args.db)}
    if args.json:
        _json(stats)
    else:
        _out(f"[bold]{stats['projects']}[/] project(s), {_size(stats['total_bytes'])}, "
             f"{_size(stats['reclaimable_bytes'])} reclaimable, {stats['security_findings']} security finding(s), "
             f"{stats['scans']} saved scan(s)\n[dim]{_esc(path)}[/]")
        for r in stats["saved_roots"]:
            _out(f"  [cyan]{_esc(r)}[/]")
    return EXIT_OK


def cmd_init(args):
    from mnemocetus import shell
    sys.stdout.write(shell.init_script(args.shell, build_parser(), prompt=not args.no_prompt,
                                       completion=not args.no_completion))
    return EXIT_OK


# --------------------------------------------------------------------------- #
# Parser
# --------------------------------------------------------------------------- #
def _add_scan_options(p):
    p.add_argument("--mode", default="CLASSIFY", choices=["CLASSIFY", "SKIP", "MERGE", "SPLIT"],
                   type=str.upper, help="how nested projects are handled (default: CLASSIFY)")
    p.add_argument("--no-filters", action="store_true", help="don't apply the exclude list (node_modules, venv, ...)")
    p.add_argument("--no-secrets", action="store_true", help="skip the hard-coded secret scan")
    p.add_argument("--workers", type=int, default=None, help="scan threads (default: auto)")
    p.add_argument("--fail-on-findings", action="store_true",
                   help=f"exit {EXIT_FINDINGS} when the scan found NEW security findings (for CI / hooks)")
    p.add_argument("--json", action="store_true", help="machine-readable output")


def build_parser():
    parser = argparse.ArgumentParser(
        prog="nemc",
        description="MnemoCetus - scan, classify, analyse, clean and secure your developer workspace.\n"
                    "Run with no command for the interactive menu.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("-V", "--version", action="version", version=f"MnemoCetus {__version__}")
    parser.add_argument("--db", metavar="PATH", help="long-term database to use (default: $MNEMOCETUS_DB or "
                                                     "~/.local/share/mnemocetus/mnemocetus.db)")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("scan", help="scan a folder, show what changed, and save it")
    p.add_argument("directory", nargs="?", default=".", help="folder to scan (default: current directory)")
    p.add_argument("--no-save", action="store_true", help="don't save to the long-term database")
    _add_scan_options(p)
    p.set_defaults(func=cmd_scan)

    p = sub.add_parser("rescan", help="re-scan every saved folder (or the one containing PATH)")
    p.add_argument("path", nargs="?", help="only re-scan the saved folder containing this path")
    p.add_argument("--no-save", action="store_true", help="don't save the results")
    _add_scan_options(p)
    p.set_defaults(func=cmd_rescan)

    p = sub.add_parser("changes", help="scan without saving -> what changed since the last save")
    p.add_argument("directory", nargs="?", default=".", help="folder to check (default: current directory)")
    _add_scan_options(p)
    p.set_defaults(func=cmd_changes)

    p = sub.add_parser("status", help="is the project here up to date / changed / has security findings?")
    p.add_argument("path", nargs="?", default=".", help="path inside a project (default: current directory)")
    p.add_argument("--prompt", action="store_true", help="print only a coloured light for a shell prompt")
    p.add_argument("--shell", default="plain", choices=["bash", "zsh", "fish", "plain", "none"],
                   help="escape style for --prompt (default: plain ANSI)")
    p.add_argument("--budget", type=float, default=None, metavar="SECONDS",
                   help="max time for the change check (default: unlimited; 0.25s with --prompt)")
    p.add_argument("--exit-code", action="store_true",
                   help="exit 0 clean / 1 changed / 2 security / 3 unscanned / 4 unknown")
    p.add_argument("--json", action="store_true", help="machine-readable output")
    p.set_defaults(func=cmd_status)

    p = sub.add_parser("projects", help="list saved projects")
    p.add_argument("--language")
    p.add_argument("--category")
    p.add_argument("--framework")
    p.add_argument("--under", metavar="DIR", help="only projects inside this folder")
    p.add_argument("--uncertain", action="store_true", help="only unconfirmed low-confidence projects")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_projects)

    p = sub.add_parser("secrets", help="stored security findings, or --history for a repo's whole git history")
    p.add_argument("directory", nargs="?", help="limit to this folder (with --history: the repo, default .)")
    p.add_argument("--history", action="store_true", help="scan every commit of the repo for secrets")
    p.add_argument("--fail-on-findings", action="store_true", help=f"exit {EXIT_FINDINGS} if anything is found")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_secrets)

    p = sub.add_parser("audit", help="dependency vulnerability audit (needs pip-audit / npm audit)")
    p.add_argument("directory", nargs="?", default=".")
    p.add_argument("--fail-on-findings", action="store_true", help=f"exit {EXIT_FINDINGS} if anything is found")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_audit)

    p = sub.add_parser("reclaim", help="plan (default) or --execute deleting regenerable bloat")
    p.add_argument("--kind", action="append", metavar="KIND",
                   help="only this kind (dependencies / virtualenv / cache / build); repeatable")
    p.add_argument("--min-mb", type=float, default=0, help="skip directories smaller than this")
    p.add_argument("--under", metavar="DIR", help="only inside this folder")
    p.add_argument("--execute", action="store_true", help="actually delete (asks you to type DELETE)")
    p.add_argument("--yes", action="store_true", help="with --execute: skip the confirmation (scripts)")
    p.add_argument("--json", action="store_true")
    p.set_defaults(func=cmd_reclaim)

    p = sub.add_parser("serve", help="run the web dashboard")
    p.add_argument("-p", "--port", type=int, default=5000)
    p.add_argument("--host", default="127.0.0.1", help="bind address (default 127.0.0.1; 0.0.0.0 = whole network)")
    p.add_argument("--allow-host", action="append", default=[], metavar="NAME",
                   help="extra Host name the dashboard may be reached by (e.g. a LAN hostname); repeatable")
    p.set_defaults(func=cmd_serve)

    p = sub.add_parser("db", help="the long-term database: stats, path, or --report export")
    p.add_argument("--path", action="store_true", help="print the database path")
    p.add_argument("--report", action="store_true", help="export the full workspace report")
    p.add_argument("--format", default="md", choices=["md", "json"], help="report format (default md)")
    p.add_argument("-o", "--output", metavar="FILE", help="write the report here instead of stdout")
    p.add_argument("--json", action="store_true", help="stats as JSON")
    p.set_defaults(func=cmd_db)

    p = sub.add_parser("init", help="shell setup: status light + tab-completion (eval \"$(nemc init zsh)\")",
                       description='Print shell setup code. Add ONE line to your shell config:\n'
                                   '  bash  (~/.bashrc):                 eval "$(nemc init bash)"\n'
                                   '  zsh   (~/.zshrc):                  eval "$(nemc init zsh)"\n'
                                   '  fish  (~/.config/fish/config.fish): nemc init fish | source',
                       formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("shell", choices=["bash", "zsh", "fish"])
    p.add_argument("--no-prompt", action="store_true", help="only tab-completion, leave the prompt alone")
    p.add_argument("--no-completion", action="store_true", help="only the status light")
    p.set_defaults(func=cmd_init)
    return parser


def main(argv=None):
    """Parse and dispatch. No command -> the interactive menu. Returns the process exit code."""
    args = build_parser().parse_args(argv)
    if not getattr(args, "func", None):
        if args.db:
            os.environ["MNEMOCETUS_DB"] = os.path.abspath(os.path.expanduser(args.db))
            from mnemocetus.db import manager as db_manager
            db_manager.DEFAULT_DB_PATH = os.environ["MNEMOCETUS_DB"]
        from mnemocetus.cli.menu import main as interactive  # lazy: questionary only for the menu
        interactive()
        return EXIT_OK
    try:
        return args.func(args)
    except KeyboardInterrupt:
        print("\nInterrupted.", file=sys.stderr)
        return 130
    except BrokenPipeError:  # e.g. `nemc projects | head`
        return EXIT_OK
