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

Working today:

* Scan directories recursively for programming projects, filtering out junk (node_modules, venv, ...)
* Detect project language, frameworks and type (backend / frontend / full stack / cli / library / ...)
  for Python, JavaScript/TypeScript, Rust and Go via marker files + declared dependencies
* Weighted **confidence score** and a composition **breakdown** per project, so a mostly-HTML repo
  with one small Flask file isn't mislabelled "backend" (it's promoted to "full stack")
* Store everything in a local SQLite database (scans, projects, dependencies, files, marks)
* **Review low-confidence projects** and set a **user override** for what a project really is;
  overrides survive re-scans
* Flag **reclaimable space** ("marks") - regenerable bloat like node_modules / venv / build output -
  and generate **safe, non-destructive cleanup recommendations** with potential savings
* **Storage analysis** - workspace size rollup plus the largest projects / files / directories,
  backed by a persisted per-project file inventory
* **Cross-project dependency intelligence** - the shared packages across your projects, a rough
  estimate of the space a shared/hardlinked package store (uv, pnpm) could reclaim, and a
  version-conflict check flagging which projects could share one virtualenv vs. which clash on pins
* **Security scan** ("MnemoScan") - flag hard-coded secrets (API keys, tokens, private keys; values
  are masked, never stored raw) during a scan, plus an optional dependency-vulnerability audit that
  shells out to pip-audit / npm audit when they're installed
* A **web dashboard** (Flask): workspace statistics, a filterable database viewer with in-page
  recategorisation, cleanup recommendations, dependency overlap, storage analysis, and security findings

Planned:

* Deeper security scanning (more secret detectors, richer audit integration)
* Automated organisation suggestions

---

## Current Status

DISCLAIMER: I may forget to update this information with each update, so double-check it if needed.

Active development, currently at **v0.5**. On top of the v0.4 line (recognition, review/override,
reclaimable-space + cleanup, dependency overlap, storage analysis), v0.5 adds **dependency
intelligence** (version-aware conflict / shareable-venv checks) and the **MnemoScan** security layer
(masked secret detection + an optional pip-audit / npm audit). See the roadmap.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/hottahidit/mnemocetus.git
cd mnemocetus
```

Install the dependencies (the CLI uses `rich` + `questionary`; the optional web dashboard adds `flask`):

```bash
pip install -r requirements.txt
```

The core scanning + database layer is pure-stdlib Python; only the interactive CLI and the web
dashboard need the packages above.

---

## Usage

### CLI

Run the interactive tool:

```bash
python utils/scanner.py
```

You **scan a directory first** - choosing how nested projects are handled (CLASSIFY / SKIP / MERGE /
SPLIT, each with an inline description on highlight and a recommended default). The scan (which also
flags secrets) is **auto-held in a temporary database** until your next scan; you can then **save it
long-term** to keep it. Once scanned, the rest opens up: **explore this scan** (list/search projects,
latest scan, reclaimable space, cleanup recommendations, dependency overlap, dependency conflicts,
storage analysis, security findings), **review low-confidence projects** (set the real type / delete /
"yes to all"), an optional **dependency vulnerability audit** (pip-audit / npm audit), or **open a
saved database**.

### Web dashboard (optional)

```bash
python utils/web/app.py        # -> http://127.0.0.1:5000
```

Six views: the **Dashboard** (totals, by-language / by-category, confidence spread, reclaimable
space), **Projects** (filter + in-page recategorise), **Cleanup** (ranked cleanup suggestions),
**Overlap** (shared dependencies + the space a shared/hardlinked package store could reclaim + a
version-conflict / shareable-venv check), **Storage** (largest projects / files / directories), and
**Security** (masked secret findings + dependency vulnerabilities). MnemoCetus never deletes anything
itself - cleanup is advisory, secrets are masked, and the commands are shown for you to run.

---

## Roadmap

* v0.1: Basic directory scanner
* v0.2: Project detection and filtering improvements
* v0.3: Metadata storage system (SQLite) + database viewer (+ the OOP scanner refactor folded in)
* v0.4: Smarter recognition (weighted confidence, composition breakdown, review/override, web
  dashboard) + reclaimable-space marks, safe cleanup recommendations, and cross-project
  dependency-overlap analysis (+ the scanner split into classifier / cleaner / cli modules;
  v0.4.x adds the storage analyser)
* v0.5: Dependency intelligence (version-aware conflict / shareable-venv checks) + the MnemoScan
  security layer (masked secret detection, optional pip-audit / npm audit)
* v1.0: Full workspace intelligence platform

Note: the roadmap numbers are actual release versions. `PLAN.md` uses finer-grained planning
milestones (its "v0.5" and "v0.6" feature buckets both ship inside release v0.4).

---

## Goals

MnemoCetus aims to become a developer workspace assistant that:

* Organises projects automatically
* Reduces storage clutter
* Helps developers understand their codebase ecosystem
* Provides intelligent insights about local development environments

---

## LICENSE

I am an (self-proclaimed) intermediate student developer looking to further their skills with this project. Feel free to use my code however you would like!
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
