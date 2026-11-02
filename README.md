```text
                                                                            __________...----..____..-'``-..___
                                                                          ,'.                                  ```--.._
                                                                         :                                             ``._
                                                                        |                           --                    ``.
                                                                        |                <o>   -.-      -.     -   -.        `.
                                                                        :                     __           --            .     \
                                                                        `._____________     (  `.   -.-      --  -   .   `     \
                                                                          `-----------------\   \_.--------..__..--.._ `. `.   :
ooo        ooooo                                                     .oooooo.                \. ,                     `-._ .   |
`88.       .888'                                                    d8P'  `Y8b              .o8                           `.`  |
 888b     d'888  ooo. .oo.    .ooooo.  ooo. .oo.  .oo.    .ooooo.  888           .ooooo.  .o888oo oooo  oooo   .oooo.o      \` |
 8 Y88. .P  888  `888P"Y88b  d88' `88b `888P"Y88bP"Y88b  d88' `88b 888          d88' `88b   888   `888  `888  d88(  "8       \ |
 8  `888'   888   888   888  888ooo888  888   888   888  888   888 888          888ooo888   888    888   888  `"Y88b.        / \`
 8    Y     888   888   888  888    .o  888   888   888  888   888 `88b    ooo  888    .o   888 .  888   888  o.  )88b      /  .\
o8o        o888o o888o o888o `Y8bod8P' o888o o888o o888o `Y8bod8P'  `Y8bood8P'  `Y8bod8P'   "888"  `V88V"V8P' 8""888P'     /  __.\
                                                                                                                          /_,'  \_\
```

# MnemoCetus

MnemoCetus is a developer workspace power tool designed to scan, analyse, and organise local coding projects. It helps developers understand what exists in their workspace, identify unused files, and gain insights into project structure and storage usage.

## What's in the name?

MnemoCetus is a portmanteau of the name of the Greek Goddess Mnemosyne (for memory) and the Greek God Anicetus (the Unconquerable One, and son of Heracles). It simultaneously plays on mnēmē (greek for memory) and Cetus, a legendary beast that roamed the deep oceans. Together, MnemoCetus represents an unconquerable leviathian that roams the deep sea of files on your system, ensuring it is protected, clean and secure.

---

## Features

**Find and understand your projects**

* Recursively scans a workspace for projects - Python, JavaScript/TypeScript, Rust and Go - via marker
  files and declared dependencies, filtering out junk (node_modules, venv, build output, ...)
* Detects language, frameworks and type (backend / frontend / full stack / cli / library / ...) with a
  weighted **confidence score** and a composition **breakdown**, so a mostly-HTML repo with one small
  Flask file isn't mislabelled "backend"
* **Low-confidence review** with **user overrides** that survive re-scans, plus an optional local-first
  **AI arbiter** (Ollama by default; OpenAI-compatible, Anthropic and Gemini supported) for a second
  opinion on borderline projects - cloud endpoints only ever see redacted, workspace-relative paths
* **Git awareness** - branch, uncommitted / unpushed / stale work, repos worth a `git gc`

**Keep it clean**

* **Reclaimable space** - sizes regenerable bloat (node_modules, venvs, caches, build output) honestly:
  symlinks are never followed and pnpm-style hard links aren't counted as freeable
* **Cleanup recommendations** and the opt-in **Reclaimer**, the one feature that deletes: a dry-run plan,
  a typed confirmation, and a guard that refuses anything outside the scanned workspace, anything git
  tracks, anything containing a nested repo, and ambiguous folders (`dist/`, `build/`, `target/`,
  `vendor/`) without a matching build file beside them
* **Storage analysis** (largest projects / files / folders) and **dependency intelligence** (shared
  packages, version conflicts, which projects could share one virtualenv)

**Keep it secure** ("MnemoScan")

* Hard-coded secrets (API keys, tokens, private keys) found during every scan - **masked**, never stored raw
* Optional **full git-history** secret scan, `.env` exposure and un-ignored-bloat hygiene checks, and an
  optional dependency-vulnerability audit via `pip-audit` / `npm audit` when installed

**Know what changed**

* **Incremental scans** - unchanged projects reuse their stored results
* **"What changed since last save"** - new / removed / changed projects, **new security findings** and new
  bloat, in the terminal, the web dashboard and the export report
* A **shell-prompt status light**: a coloured dot when you're inside a scanned project

**Three ways in**

* `nemc` - scriptable subcommands (every read command speaks `--json`) plus an interactive menu
* A local **web dashboard** - statistics, a filterable project database with in-page recategorisation,
  cleanup, overlap, storage, security, git and changes views
* **Markdown / JSON report export** of the whole workspace

---

## Installation

Requires Python 3.9+ (3.11+ for `pyproject.toml` / `Cargo.toml` parsing).

```bash
git clone https://github.com/hottahidit/mnemocetus.git
cd mnemocetus
pipx install .          # recommended: puts the `nemc` command on your PATH, isolated
# or, to hack on it (edits take effect immediately):
pip install -e .
```

On a system Python that refuses `pip install` ("externally-managed-environment", PEP 668) use `pipx` or a
virtualenv. To run from a checkout without installing: `pip install -r requirements.txt`, then
`python cli.py` (same as `nemc`).

Then add the status light + tab-completion to your shell (one line, see [Shell integration](#shell-integration)):

```bash
echo 'eval "$(nemc init zsh)"' >> ~/.zshrc      # or bash / fish
```

---

## Quick start

```bash
nemc scan ~/Projects          # scan, classify, check for secrets, save
nemc status                   # is the project I'm in up to date / changed / leaking a secret?
nemc projects --language python
nemc changes ~/Projects       # what changed since the last save (doesn't save)
nemc reclaim                  # what could be deleted to free space (dry run)
nemc serve                    # web dashboard on http://127.0.0.1:5000
nemc                          # the interactive menu
```

---

## Commands

| Command | What it does |
|---|---|
| `nemc` | Interactive menu: scan, explore, review, AI re-classify, audit, Reclaimer, settings |
| `nemc scan [DIR]` | Scan (incremental), show what changed, save. `--no-save`, `--no-secrets`, `--no-filters`, `--mode`, `--workers` |
| `nemc rescan [PATH]` | Re-scan every saved folder, or only the one containing PATH |
| `nemc changes [DIR]` | Scan **without** saving: what changed since the last save |
| `nemc status [PATH]` | `up to date` / `changed` / `security findings` / not scanned, for the project at PATH |
| `nemc projects` | List saved projects: `--language`, `--category`, `--framework`, `--under DIR`, `--uncertain` |
| `nemc secrets [DIR]` | Stored security findings; `--history` scans a repo's entire git history |
| `nemc audit [DIR]` | Dependency vulnerabilities via `pip-audit` / `npm audit` (if installed) |
| `nemc reclaim` | Cleanup plan (dry run). `--execute` deletes after you type `DELETE`; `--yes` for scripts. `--kind`, `--min-mb`, `--under` |
| `nemc serve` | Web dashboard. `-p PORT`, `--host` (see [Security notes](#security-notes)), `--allow-host` |
| `nemc db` | Database stats; `--path`; `--report [--format md\|json] [-o FILE]` |
| `nemc init SHELL` | Print the status-light + completion setup for `bash`, `zsh` or `fish` |

**Scripting.** Read commands take `--json` (diagnostics go to stderr, so stdout is clean JSON).
`--fail-on-findings` on `scan` / `changes` / `secrets` / `audit` exits `3` when something is found - handy
in CI or a git pre-push hook. `nemc status --exit-code` exits `0` up to date, `1` changed, `2` security
findings, `3` not scanned, `4` unknown. The global `--db PATH` (or `$MNEMOCETUS_DB`) points any command
at a different database.

Saving a scan also records the folder and time (so `rescan` knows what to refresh) and drops saved
projects whose folder no longer exists.

---

## Shell integration

One line in your shell config adds the **status light** and **tab-completion**:

| Shell | Add to | Line |
|---|---|---|
| bash | `~/.bashrc` | `eval "$(nemc init bash)"` |
| zsh | `~/.zshrc` | `eval "$(nemc init zsh)"` |
| fish | `~/.config/fish/config.fish` | `nemc init fish \| source` |

Inside a scanned project your prompt gains a dot: **green** - up to date with the last scan; **amber** -
new commits or edited / added / deleted files since then; **red** - the project has stored security
findings; grey - the check ran out of time; nothing - not a scanned project. The check never scans and
never prints errors: it compares the commit and file timestamps against the last scan and stops at the
first change (typically ~35 ms, capped at 0.25 s).

Only want one half? `nemc init zsh --no-prompt` (completion only) or `--no-completion` (light only).
Using a prompt framework (starship, powerlevel10k, oh-my-posh)? Call
`nemc status --prompt --shell plain` from a custom segment instead.

---

## Web dashboard

`nemc serve` (or Settings -> web dashboard in the menu, which starts it alongside the CLI). Views:
**Dashboard** (totals, languages, categories, confidence, reclaimable space), **Projects** (filter +
recategorise, git badges), **Changes** (what changed since the last save), **Cleanup**, **Overlap**
(shared dependencies + shareable-venv check), **Storage**, **Security** and **Git** (at-risk work, repos
worth `git gc`), plus Markdown / JSON export. The dashboard never deletes files.

---

## Configuration

| What | Where |
|---|---|
| Long-term database | `~/.local/share/mnemocetus/mnemocetus.db` (`$XDG_DATA_HOME`), or `$MNEMOCETUS_DB`, or `--db`. A `mnemocetus.db` already in a pre-v1 checkout keeps being used |
| Temporary session scan (menu) | `$XDG_RUNTIME_DIR/mnemocetus-<uid>/session.db` - private (0700), replaced on each menu scan |
| Settings | `~/.mnemocetus.json` - web dashboard on/off + port, AI arbiter, scan workers (edit via the menu's **Settings**) |
| Exclude list | Shipped default in `mnemocetus/exclude_list/default_exclude_list.txt`; your own in `~/.config/mnemocetus/exclude_list.txt` (`$XDG_CONFIG_HOME`) replaces it |

**Exclude list format:** one entry per line - a bare name like `node_modules` matches anywhere in the
tree; an entry containing a slash matches that exact path or anything under it.

**AI arbiter** (off by default): Settings -> Configure AI arbiter. Pick a provider (Ollama, OpenAI,
DeepSeek, Groq, OpenRouter, Anthropic, Gemini or any OpenAI-compatible URL) and a model. Only the *name*
of the environment variable holding your API key is stored, never the key. Cloud endpoints receive
workspace-relative paths, never absolute ones.

**Scan performance:** Settings -> Auto-tune scan performance benchmarks this machine and stores the best
worker count; `nemc scan --workers N` overrides it for one run.

---

## Security notes

* Secret values are **masked** before they're stored or shown; MnemoCetus never keeps the raw value.
* MnemoCetus runs `git` inside every scanned project with repository-controlled hooks and
  `core.fsmonitor` disabled, so a hostile `.git/config` in a downloaded project can't execute commands.
* The web dashboard binds to `127.0.0.1` and only answers requests addressed to localhost, rejects
  cross-site form posts, and never runs the Werkzeug debugger. `nemc serve --host 0.0.0.0` exposes your
  project paths, git state and masked secret previews to the network **with no login** - it warns, and
  only accepts the host names it was bound to (add more with `--allow-host`).
* Dependency names from scanned manifests are validated before reaching `pip install` (uni-venv), so a
  crafted `requirements.txt` can't inject pip options.

---

## Development

```bash
pip install -e .
python -m unittest discover -s mnemocetus/tests     # on the nightly branch
```

Layout: `mnemocetus/` is the package - `scanner` / `classifier` (discovery + recognition), `cleaner` /
`reclaimer` (bloat sizing + deletion), `security`, `gitinfo`, `insight` (diffs, at-risk work), `report`,
`arbiter`, `db/` (SQLite store + analytics), `web/` (Flask), `cli/` (interactive menu), `ops.py` +
`commands.py` (the `nemc` subcommands) and `shell.py` (prompt + completion).

### Branches

* **`main`** - the stable, public branch. Its interactive menu has no developer debug/checks submenu,
  and the test suite is not tracked.
* **`nightly`** - the development branch. It tracks the full test suite under `mnemocetus/tests/`
  (340+ tests across the scanner, database, web, git, security, CLI and shell layers) and keeps the
  debug/checks submenu.

---

## Roadmap

* v0.1: Basic directory scanner
* v0.2: Project detection and filtering improvements
* v0.3: Metadata storage system (SQLite) + database viewer (+ the OOP scanner refactor folded in)
* v0.4: Smarter recognition (weighted confidence, composition breakdown, review/override, web
  dashboard) + reclaimable-space marks, safe cleanup recommendations, and cross-project
  dependency-overlap analysis (+ the storage analyser)
* v0.5: Dependency intelligence (version-aware conflict / shareable-venv checks) + the MnemoScan
  security layer (masked secret detection, optional pip-audit / npm audit)
* v0.6 - v0.8: UI overhaul and report export, hardening, the opt-in AI arbiter, a parallel scanner
  with auto-tuning
* v0.9: The git-aware workspace - git state, incremental scans, git-history secret scan, security
  hardening, and the "what changed since last save" diff
* **v1.0: The shell companion** - an installable `mnemocetus` package, the `nemc` command,
  the shell-prompt status light, tab-completion, and much faster scans on large workspaces

Next ideas: `nemc watch` (re-scan on change), archive-and-reclaim for stale repositories (push to a
private remote, then remove locally once everything is backed up), and more secret detectors.

---

## Goals

MnemoCetus aims to be a developer workspace assistant that:

* Organises projects automatically
* Reduces storage clutter
* Helps developers understand their codebase ecosystem
* Provides intelligent insights about local development environments

---

## LICENSE

I am an (self-proclaimed) intermediate student developer looking to further their skills with this project. Feel free to use my code however you would like!
However, please link back to this repository or credit me.
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
