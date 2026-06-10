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

MnemoCetus is a developer workspace power tool designed to scan, analyze, and organize local coding projects. It helps developers understand what exists in their workspace, identify unused files, and gain insights into project structure and storage usage.

## What's in the name?

MnemoCetus is a portmanteau of the name of the Greek Goddess Mnemosyne (for memory) and the Greek God Anicetus (the Unconquerable One, and son of Heracles). It simultaneously plays on mnēmē (latin for memory) and Cetus, a legendary beast that roamed the deep oceans. Together, MnemoCetus represents an unconquerable leviathian that roams the deep sea of files on your system, ensuring it is protected, clean and secure.

---

## Features (Planned / In Progress)

* Scan directories for programming projects
* Detect project roots and project types using marker files
* Track file sizes and storage usage
* Filter out unnecessary folders (e.g. node_modules, venv)
* Generate workspace summaries
* Identify large or unused files
* Future: security scanning and dependency checks

---

## Current Status

DISCLAIMER: I may forget to update this information with each update, so double-check it if needed.

This project is in active development and currently progressing through the v0.2 scanner stage.
The scanner now supports recursive scanning, filtering, and basic project detection (WIP) for Python, JavaScript/TypeScript, Rust, and Go using marker files.

---

## Installation

Clone the repository:

```bash
git clone https://github.com/your-username/mnemoguardian.git
cd mnemoguardian
```

No dependencies are required yet (pure Python).

---

## Usage

DISCLAIMER: As of v0.2, these are all the available features, and how to use them.

Run the scanner:

```bash
python utils/scanner.py
```

You will be prompted to enter a directory to scan.

Example:

```text
Enter the directory to scan: /your/projects
```

---

## Roadmap

* v0.1: Basic directory scanner
* v0.2: Project detection and filtering improvements
* v0.3: Metadata storage system
* v1.0: Full workspace intelligence platform

---

## Goals

MnemoCetus aims to become a developer workspace assistant that:

* Organizes projects automatically
* Reduces storage clutter
* Helps developers understand their codebase ecosystem
* Provides intelligent insights about local development environments

---

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
