# File Scanner for the project, this will probably get called upon a lot
#IMPORTS
from rich import print
from rich.columns import Columns
from rich.panel import Panel
import os

#SETUP
try:
    with open('utils/exclude_list/custom_exclude_list.txt', 'r') as f:
        exclude_list = f.read().splitlines()
except FileNotFoundError:
    print("Custom exclude list not found, proceeding without it. (If it exists, name your custom list 'custom_exclude_list.txt' and place it in the 'exclude_list' folder to use it.)")
    with open('utils/exclude_list/default_exclude_list.txt', 'r') as f:
        exclude_list = f.read().splitlines()

#FUNCTIONS
def compile_exclude_rules(exclude_list):
    """
    Splits a raw exclude list into two rule sets, gitignore-style.

    Args:
        exclude_list (list): Raw lines from an exclude list file.

    Returns:
        (name_rules, path_rules): name_rules is a set of basenames to match anywhere
        in the tree (e.g. 'node_modules'); path_rules is a set of normalised absolute/
        relative paths to match exactly or as a parent prefix (e.g. '/home/me/proj/build').
    """
    name_rules = set()
    path_rules = set()
    for entry in exclude_list:
        entry = entry.strip()
        if not entry or entry.startswith('#'):  # Skip blank lines and comments
            continue
        entry = entry.rstrip('/\\')  # Trailing slashes are cosmetic ('node_modules/' == 'node_modules')
        if os.sep in entry or (os.altsep and os.altsep in entry):
            path_rules.add(os.path.normpath(entry))  # Has a separator -> treat as a path
        else:
            name_rules.add(entry)  # Bare name -> match this basename anywhere
    return name_rules, path_rules

def is_excluded(path, name_rules, path_rules):
    """Return True if 'path' is matched by a name rule or a path rule."""
    norm = os.path.normpath(path)
    if os.path.basename(norm) in name_rules:  # e.g. any '.../node_modules'
        return True
    if norm in path_rules:  # exact path match
        return True
    return any(norm.startswith(p + os.sep) for p in path_rules)  # anything under an excluded path

# IMPORTANT: This code is not complete, in the future it will change to include arguments, and other features.
def scan_directory(directory, exclude_list=exclude_list, confirm_filters=True):
    """
    Scans the given directory and returns a list of file paths.

    Args:
        directory (str): The path to the directory to scan.
        exclude_list (list): A list of file paths to exclude from the scan.
        confirm_filters (bool): Whether to apply filters during scanning.
    """

    files_scanned = 0
    bytes_scanned = 0
    file_paths = []

    # Check if the directory exists and is accessible (error handling)
    if directory is None or not os.path.exists(directory):
        print(f"Directory '{directory}' does not exist.")
        return []
    if not os.path.isdir(directory):
        print(f"'{directory}' is not a directory.")
        return []
    if not os.access(directory, os.R_OK):
        print(f"Directory '{directory}' is not readable. (Permission denied)")
        return []

    # Recursively scan the directory and its subdirectories, as well as counting the number of files and bytes scanned
    if confirm_filters:
        # Compile the exclude list once up front rather than re-parsing it on every path.
        name_rules, path_rules = compile_exclude_rules(exclude_list)
        for root, dirs, files in os.walk(directory):
            # Prune excluded/hidden dirs in place so os.walk never even descends into them.
            dirs[:] = [d for d in dirs if not d.startswith('.') and not is_excluded(os.path.join(root, d), name_rules, path_rules)]
            for file in files:

                if file.startswith('.'):  # Skip hidden files
                    continue

                file_path = os.path.normpath(os.path.join(root, file))
                if is_excluded(file_path, name_rules, path_rules):  # Exclude files by name or under an excluded path
                    continue

                try:
                    file_paths.append(file_path)
                    files_scanned += 1
                    bytes_scanned += os.path.getsize(file_path)
                except (OSError, PermissionError):
                    print(f"Error accessing file: {file_path}, skipping... (Permission denied or file not found)")
    else:
        for root, dirs, files in os.walk(directory):
            for file in files:
                file_path = os.path.normpath(os.path.join(root, file))
                try:
                    file_paths.append(file_path)
                    files_scanned += 1
                    bytes_scanned += os.path.getsize(file_path)
                except (OSError, PermissionError):
                    print(f"Error accessing file: {file_path}, skipping... (Permission denied or file not found)")

    return file_paths

def resolve_directory_relationships(file_paths, mode):
    """
    Resolves relationships between directories (e.g., parent-child relationships, symbolic links).

    Args:
        file_paths (list): A list of file paths to resolve relationships for.
        mode (str): The mode to use for resolving relationships.

    Modes:
     - SKIP : Skips nested directories, and only scans the top-level directory
     - MERGE : Shows the relationships between directories, but treats them as one project (it will scan the top directory and show the relationships but won't scan the child directories)
     - CLASSIFY : Classifies the relationships between directories (e.g., parent-child, symbolic links) AND investigates them. (DEFAULT)
     - SPLIT : Treats every nested directory as a separate project
    """

    relationships = {}

    # Validate the mode, defaulting to CLASSIFY
    if mode is None or mode not in ["SKIP", "MERGE", "CLASSIFY", "SPLIT"]:
        print(f"Invalid mode: '{mode}', defaulting to 'CLASSIFY'.")
        mode = "CLASSIFY"

    # Validate the incoming list
    if file_paths is None or not isinstance(file_paths, list):
        print(f"The list of file paths were invalid. Expected: A list of file paths. Recieved: {file_paths}")
        return {}

    # Collapse the *file* list into a directory list, then filter it out
    directories = set()
    for path in file_paths:
        if path is None or not isinstance(path, str):  # In case a file/folder was deleted mid-scan
            print(f"Skipping invalid file path: '{path}'. Expected a string representing a file path.")
            continue
        directories.add(os.path.dirname(os.path.normpath(path)))

    # Keep only the directories that actually look like projects (reuse the type detector)
    project_dirs = sorted(d for d in directories if not identify_directory_type(d).startswith("Unknown"))
    if not project_dirs:
        print("No recognisable project directories were found in the scanned files.")
        return {}
    project_set = set(project_dirs)

    # Helper: walk up the tree to find the closest progenitor that is also a project.
    def nearest_project_ancestor(path):
        parent = os.path.dirname(path)
        while parent and parent != path:
            if parent in project_set:
                return parent
            path, parent = parent, os.path.dirname(parent)
        return None

    # Build the base relationship map. This is the full, classified tree used by CLASSIFY.
    for project in project_dirs:
        parent = nearest_project_ancestor(project)
        is_symlink = os.path.islink(project)
        relationships[project] = {
            "type": identify_directory_type(project),
            "parent": parent,
            "children": [],
            "is_symlink": is_symlink,
            "symlink_target": os.path.realpath(project) if is_symlink else None,
            "role": "root" if parent is None else "child",
        }

    # Now that every node exists, fill in each parent's children list.
    for project, info in relationships.items():
        if info["parent"] is not None:
            relationships[info["parent"]]["children"].append(project)

    # Re-shape the map according to the chosen mode.
    if mode == "SKIP":
        # Only the primogenitor
        relationships = {p: info for p, info in relationships.items() if info["parent"] is None}
        for info in relationships.values():
            info["children"] = []  # children were skipped, so don't advertise them

    elif mode == "MERGE":
        # Keep the relationships visible, but fold children into their root project; the root stays the scannable unit while children remain listed but flagged as merged.
        for info in relationships.values():
            if info["parent"] is not None:
                info["role"] = "merged"

    # CLASSIFY mode is the default, so we don't need to do anything special

    elif mode == "SPLIT":
        # Every project directory becomes its own independent project; cut the links.
        for info in relationships.values():
            info["parent"] = None
            info["children"] = []
            info["role"] = "independent"

    return relationships

def identify_directory_type(directory):
    """
    Identifies the type of the given directory (e.g., project, user data, system files).

    Caching wrapper around detect_directory_type(): identification fires a lot of
    os.path.exists() syscalls, so results are memoised in the global "cache", keyed by
    absolute path and guarded by the directory's mtime. If the directory changes (a marker
    file is added/removed) its mtime moves and the entry is recomputed automatically.

    Args:
        directory (str): The path to the directory to identify.
    """
    cache = identify_directory_type.cache

    # Without a valid path/mtime we can't safely key or invalidate, so skip the cache entirely.
    if directory is None:
        return detect_directory_type(directory)
    abs_dir = os.path.abspath(directory)
    try:
        mtime = os.path.getmtime(directory)
    except OSError:
        return detect_directory_type(directory)

    cached = cache.get(abs_dir)
    if cached is not None and cached[0] == mtime:  # Cache hit: directory unchanged since last time
        return cached[1]

    result = detect_directory_type(directory)
    cache[abs_dir] = (mtime, result)
    return result

# Initialise the memoisation store the wrapper reads from (path -> (mtime, result)).
identify_directory_type.cache = {}

def detect_directory_type(directory):
    """
    The actual detection logic for identify_directory_type(). Call the cached wrapper instead.

    Args:
        directory (str): The path to the directory to identify.
    """
    # Currently only for detecting the language and framework, will be expanded on (this is very basic) -> NOTE: Maybe use confidence trackers instead of hard rules?
    if os.path.exists(os.path.join(directory, 'pyproject.toml')) or os.path.exists(os.path.join(directory, 'requirements.txt')) or os.path.exists(os.path.join(directory, 'Pipfile')) or os.path.exists(os.path.join(directory, 'setup.py')):
        if os.path.exists(os.path.join(directory, 'manage.py')) or os.path.exists(os.path.join(directory, 'settings.py')):
            return 'Python Project, Django Framework'
        elif ((os.path.exists(os.path.join(directory, 'app.py')) or os.path.exists(os.path.join(directory, 'main.py'))) and os.path.exists(os.path.join(directory, 'templates'))) or os.path.exists(os.path.join(directory, 'static')):
            # ^ app.py or main.py, then if it also has templates, or static folder asw
            return 'Python Project, Flask Framework'
        return 'Python Project, unknown'

    elif os.path.exists(os.path.join(directory, 'package.json')) or os.path.exists(os.path.join(directory, 'package-lock.json')) or os.path.exists(os.path.join(directory, 'yarn.lock')) or os.path.exists(os.path.join(directory, 'pnpm-lock.yaml')):
        if os.path.exists(os.path.join(directory, 'next.config.js')) or os.path.exists(os.path.join(directory, 'next.config.mjs')):
            return 'JS/Typescript Project, Next.js Framework'
        elif os.path.exists(os.path.join(directory, 'nuxt.config.js')) or os.path.exists(os.path.join(directory, 'nuxt.config.mjs')):
            return 'JS/Typescript Project, Nuxt.js Framework'
        return 'JS/Typescript Project, unknown'
    
    elif os.path.exists(os.path.join(directory, 'Cargo.toml')) or os.path.exists(os.path.join(directory, 'Cargo.lock')):
        if os.path.exists(os.path.join(directory, 'src', 'main.rs')):
            return 'Rust Project, binary application'
        elif os.path.exists(os.path.join(directory, 'src', 'lib.rs')):
            return 'Rust Project, library' 
        return 'Rust Project, unknown'
    
    elif os.path.exists(os.path.join(directory, 'go.mod')) or os.path.exists(os.path.join(directory, 'go.sum')):
        if os.path.exists(os.path.join(directory, 'main.go')):
            return 'Go Project, binary application'
        elif os.path.exists(os.path.join(directory, 'lib.go')):
            return 'Go Project, library'
        elif os.path.exists(os.path.join(directory, 'cmd')) and os.path.isdir(os.path.join(directory, 'cmd')):
            return 'Go Project, multi-module application'
        return 'Go Project, unknown'
    return "Unknown Directory Type -> There aren't a lot of languages implemented yet, so this is highly likely, don't worrry"

#MAIN
# (if the file is run directly, usually for testing)
if __name__ == "__main__":
    print(Panel("""
                                                                            __________...----..____..-'``-..___
                                                                          ,'.                                  ```--.._
                                                                         :                                             ``._
                                                                        |                           --                    ``.
                                                                        |                <o>   -.-      -.     -   -.        `.
                                                                        :                     __           --            .     |
                                                                        `._____________     (  `.   -.-      --  -   .   `     |
                                                                          `-----------------\   \_.--------..__..--.._ `. `.   :
ooo        ooooo                                                     .oooooo.                \. ,                     `-._ .   |
`88.       .888'                                                    d8P'  `Y8b              .o8                           `.`  |
 888b     d'888  ooo. .oo.    .ooooo.  ooo. .oo.  .oo.    .ooooo.  888           .ooooo.  .o888oo oooo  oooo   .oooo.o      \` |
 8 Y88. .P  888  `888P"Y88b  d88' `88b `888P"Y88bP"Y88b  d88' `88b 888          d88' `88b   888   `888  `888  d88(  "8       \ |
 8  `888'   888   888   888  888ooo888  888   888   888  888   888 888          888ooo888   888    888   888  `"Y88b.        / \`
 8    Y     888   888   888  888    .o  888   888   888  888   888 `88b    ooo  888    .o   888 .  888   888  o.  )88b      /  .$
o8o        o888o o888o o888o `Y8bod8P' o888o o888o o888o `Y8bod8P'  `Y8bood8P'  `Y8bod8P'   "888"  `V88V"V8P' 8""888P'     /  __.$
                                                                                                                          /_,'  \_\                                                                                                                                                                                                      
""", title="v0.2", subtitle="MnemoCetus", style="cyan"))
    directory = input("Enter the directory to scan: ")
    skip_filters = input("Do you want to remove filters and scan all files? (y/n): ")
    scanned_files = scan_directory(directory, confirm_filters=(skip_filters.lower() != 'y'))
    identified_type = identify_directory_type(directory)
    relationships = resolve_directory_relationships(scanned_files, mode="CLASSIFY")
    print(
    f"""Scanned {len(scanned_files)} files,
        Totaling {sum(os.path.getsize(f) for f in scanned_files)/1073741824:.2f} GB in {directory}, including subdirectories. 
        #                                                           ^ Convert bytes to gigabytes (lowered pressure on the CPU by having the precalculated num instead of 1024**3)
        Detected directory type: {identified_type}. {"Filters skipped." if skip_filters.lower() == 'y' else "Filters applied."}
           """)
    if input("Do you want to see the list of scanned files? (y/n): ").lower() == 'y':
        print(Columns(scanned_files))
        print("")
        if input("Do you also want to see the resolved directory relationships? (y/n): ").lower() == 'y':
            print(relationships)