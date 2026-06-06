# File Scanner for the project, this will probably get called upon a lot
#IMPORTS
import os

#SETUP
file_paths = []
with open('exclude_list.txt', 'r') as f:
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
    file_paths = []
    for root, dirs, files in os.walk(directory):
        dirs[:] = [d for d in dirs if os.path.normpath(os.path.join(root, d)) not in exclude_list or d.startswith('.')]  # Exclude hidden directories or directories (even nested ones) in the exclude list
        for file in files:

            if file.startswith('.'):  # Skip hidden files
                continue

            file_path = os.path.normpath(os.path.join(root, file))
            if file_path in exclude_list or any(file_path.startswith(ex + os.sep) for ex in exclude_list): # Exclude exact files in the exclude list, and any files in excluded directories
                continue

            file_path = os.path.join(root, file)
            file_paths.append(file_path)
            files_scanned += 1
            bytes_scanned += os.path.getsize(file_path)

    return file_paths

#MAIN
# (if the file is run directly, usually for testing)
if __name__ == "__main__":
    directory = input("Enter the directory to scan: ")
    scanned_files = scan_directory(directory)
    print(f"Scanned {files_scanned} files, totaling {bytes_scanned/1073741824:.2f} GB in {directory}, including subdirectories.")
    #                                                              ^ bytes_scanned/1024/1024/1024 to convert bytes into GB
    if input("Do you want to see the list of scanned files? (y/n): ").lower() == 'y':
        print(f"OVERRIDE: \n{scanned_files}")