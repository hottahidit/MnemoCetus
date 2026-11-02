# Entry point for `nemc` (the installed console script) and `python -m mnemocetus`.
# No arguments -> the interactive menu; otherwise a subcommand (see mnemocetus/commands.py).

import sys


def main(argv=None):
    """Console-script entry point -> returns a process exit code."""
    from mnemocetus.commands import main as run
    return run(sys.argv[1:] if argv is None else argv)


if __name__ == "__main__":
    sys.exit(main())
