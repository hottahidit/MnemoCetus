# File Scanner for the project, this will probably get called upon a lot
#IMPORTS
import os

#SETUP
file_paths = []
try:
    with open('./exclude_list/custom_exclude_list.txt', 'r') as f:
        exclude_list = f.read().splitlines()
except FileNotFoundError:
    print("Custom exclude list not found, proceeding without it. (If it exists, name your custom list 'custom_exclude_list.txt' and place it in the 'exclude_list' folder to use it.)")
    with open('./exclude_list/default_exclude_list.txt', 'r') as f:
        exclude_list = f.read().splitlines()

files_scanned = 0
bytes_scanned = 0

#FUNCTIONS
# IMPORTANT: This code is not complete, in the future it will change to include arguments, and other features.
def scan_directory(directory):
    """
    Scans the given directory and returns a list of file paths.

    Args:
        directory (str): The path to the directory to scan.
    """

    global files_scanned, bytes_scanned

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
    global file_paths
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if os.path.normpath(os.path.join(root, d)) not in exclude_list and not d.startswith('.')]  # Exclude hidden directories or directories (even nested ones) in the exclude list
        for file in files:

            if file.startswith('.'):  # Skip hidden files
                continue

            file_path = os.path.normpath(os.path.join(root, file))
            if file_path in exclude_list or any(file_path.startswith(ex + os.sep) for ex in exclude_list): # Exclude exact files in the exclude list, and any files in excluded directories
                continue

            try:
                file_path = os.path.join(root, file)
                file_paths.append(file_path)
                files_scanned += 1
                bytes_scanned += os.path.getsize(file_path)
            except (OSError, PermissionError):
                print(f"Error accessing file: {file_path}, skipping... (Permission denied or file not found)")

    return file_paths

def identify_directory_type(directory):
    """
    Identifies the type of the given directory (e.g., project, user data, system files).

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
    directory = input("Enter the directory to scan: ")
    scanned_files = scan_directory(directory)
    identified_type = identify_directory_type(directory)
    print(f"Scanned {files_scanned} files, totaling {bytes_scanned/(1024**3):.2f} GB in {directory}, including subdirectories. Detected directory type: {identified_type}.")
    if input("Do you want to see the list of scanned files? (y/n): ").lower() == 'y':
        print(f"OVERRIDE: \n{scanned_files}")