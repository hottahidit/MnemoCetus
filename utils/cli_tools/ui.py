# Shared CLI prompt helpers for MnemoCetus (v0.7.x split out of cli.py).
#
# The one questionary theme plus the small wrappers every menu goes through -> ask_dir / _menu /
# ask_mode / _pause. They depend only on questionary, so both cli.py and cli_actions.py import them
# from here (no shared state, nothing to thread through).

import questionary


# One cohesive theme for every prompt: cyan accents, a distinctive pointer, and hotkeys for power users.
_qstyle = questionary.Style([
    ("qmark",       "fg:#00d7ff bold"),
    ("question",    "bold"),
    ("pointer",     "fg:#00d7ff bold"),
    ("highlighted", "fg:#00d7ff bold"),
    ("selected",    "fg:#5fff87"),
    ("answer",      "fg:#5fff87 bold"),
    ("instruction", "fg:#7f7f7f"),
])

def ask_dir(msg="Enter a directory:"):
    return questionary.path(msg, style=_qstyle).ask()

def _menu(message, choices, **kwargs):
    """Every menu routes through here -> the shared theme, a '▸' pointer, and number/letter hotkeys."""
    return questionary.select(
        message, choices=choices, style=_qstyle, pointer="▸",
        use_shortcuts=True, **kwargs,
    ).ask()

def ask_mode():
    """Relationship-mode picker: shows a description on highlight, with the recommended default marked."""
    return _menu(
        "How should nested projects be handled?",
        choices=[
            questionary.Choice("CLASSIFY (recommended)", value="CLASSIFY",
                description="Map out AND classify every nested project -> the full picture. Best for a normal scan."),
            questionary.Choice("SKIP", value="SKIP",
                description="Keep only the top-level project; ignore anything nested inside it."),
            questionary.Choice("MERGE", value="MERGE",
                description="Show nested projects, but treat the whole tree as one merged project."),
            questionary.Choice("SPLIT", value="SPLIT",
                description="Treat every nested project as its own fully independent project."),
            questionary.Choice("↩ Back (cancel)", value="__back__",
                description="Picked scan by accident? Go back to the menu without scanning."),
        ],
        default="CLASSIFY",
        show_description=True,
    )

def _pause():
    """Wait for a keypress so the user can read the output before the menu redraws."""
    questionary.press_any_key_to_continue("Press any key to continue...").ask()
