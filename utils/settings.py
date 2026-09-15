# User settings for MnemoCetus (a small JSON config in the user's home directory).
#
# Global, cross-session preferences that don't belong in a scan database -> whether the web dashboard auto-starts, and (v0.8) the opt-in AI arbiter.
# It lives at ~/.mnemocetus.json so it's per-user and outside the repo (nothing to gitignore).

import os
import json

SETTINGS_PATH = os.path.join(os.path.expanduser("~"), ".mnemocetus.json")

# Every supported setting + its default. Nested dicts (e.g. "arbiter") are merged key-by-key on load,
# so adding a new sub-key here fills in for configs written by an older version.
# The web dashboard and the AI arbiter are both OFF by default -> the user opts in.
DEFAULTS = {
    "web_enabled": False,
    "web_port": 5000,
    "configured": False,               # flipped True once the first-run setup wizard has run
    "arbiter": {
        "enabled": False,              # opt-in second opinion on low-confidence projects
        "provider": "ollama",          # preset name (ollama / openai / deepseek / groq / openrouter / anthropic / gemini / custom)
        "model": "",                   # chosen at setup (Ollama: from the installed list; cloud: user-set)
        "base_url": "http://localhost:11434/v1",
        "api_key_env": "",             # NAME of the env var holding the key (cloud); empty for a local endpoint
        "run_after_scan": False,       # run on low-confidence projects right after a scan, before the review step
    },
}


def _overlay(defaults, saved):
    """Build a fresh settings tree: every default, replaced by a same-typed value from 'saved' where present (recursing into nested dicts)."""
    out = {}
    saved = saved if isinstance(saved, dict) else {}
    for key, dval in defaults.items():
        if isinstance(dval, dict):
            out[key] = _overlay(dval, saved.get(key, {}))
        elif key in saved and isinstance(saved[key], type(dval)):
            out[key] = saved[key]
        else:
            out[key] = dval
    return out


def _project(defaults, settings):
    """Reduce a settings tree down to just the known keys (the mirror of _overlay), ready to write."""
    out = {}
    settings = settings if isinstance(settings, dict) else {}
    for key, dval in defaults.items():
        if isinstance(dval, dict):
            out[key] = _project(dval, settings.get(key, {}))
        else:
            out[key] = settings.get(key, dval)
    return out


def load():
    """Return the settings tree: the defaults, overlaid with whatever valid keys are on disk."""
    try:
        with open(SETTINGS_PATH, "r", encoding="utf-8") as f:
            saved = json.load(f)
    except (OSError, ValueError):
        saved = {}
    return _overlay(DEFAULTS, saved)


def save(settings):
    """Persist the known settings to disk. Returns True on success, False if the write failed."""
    data = _project(DEFAULTS, settings)
    try:
        with open(SETTINGS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return True
    except OSError:
        return False
