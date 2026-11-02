# Repo-root launcher kept for muscle memory: `python cli.py` == `nemc` == `python -m mnemocetus`.
# The real code lives in the mnemocetus/ package (install it with `pip install .` to get `nemc` on PATH).

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))  # run from a checkout without installing

from mnemocetus.__main__ import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
