# User settings for MnemoCetus (a small JSON config in the user's home directory).
#
# Global, cross-session preferences that don't belong in a scan database -> e.g. whether the web dashboard auto-starts with the CLI.
# It lives at ~/.mnemocetus.json so it's per-user and outside the repo (nothing to gitignore).

import os
import json

SETTINGS_PATH = os.path.join(os.path.expanduser("~"), ".mnemocetus.json")

# Every supported setting + its default.
# The web dashboard is OFF by default -> the user opts in.
DEFAULTS = {
    "web_enabled": False,
    "web_port": 5000,
}


def load():
    """Return the settings dict: the defaults, overlaid with whatever valid keys are on disk."""
    data = dict(DEFAULTS)
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            saved = json.load(f)
    except (OSError, ValueError):
        return data
    if isinstance(saved, dict):
        for key in DEFAULTS:
            if key in saved and isinstance(saved[key], type(DEFAULTS[key])):
                data[key] = saved[key]
    return data


def save(settings):
    """Persist the known settings to disk. Returns True on success, False if the write failed."""
    data = {key: settings.get(key, DEFAULTS[key]) for key in DEFAULTS}
    try:
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except OSError:
        return False
