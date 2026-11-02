"""
Tests for `nemc init <shell>` (mnemocetus.shell): generated completion matches the real parser, the
scripts are valid shell, real bash completion works, and the prompt hooks are idempotent.
"""

import os
import sys
import shutil
import subprocess
import tempfile
import unittest

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, REPO_ROOT)

from mnemocetus import commands, shell  # noqa: E402

HAS_BASH = shutil.which("bash") is not None
HAS_ZSH = shutil.which("zsh") is not None
HAS_FISH = shutil.which("fish") is not None


def _init(sh, **kw):
    return shell.init_script(sh, commands.build_parser(), **kw)


class TestSpec(unittest.TestCase):
    def test_every_command_is_completed(self):
        names = set(shell._spec(commands.build_parser())["commands"])
        self.assertTrue({"scan", "rescan", "changes", "status", "projects", "secrets", "audit",
                         "reclaim", "serve", "db", "init"} <= names)
        for sh in shell.SHELLS:
            script = _init(sh, prompt=False)
            for n in names:
                self.assertIn(n, script, (sh, n))

    def test_option_values_come_from_the_parser(self):
        script = _init("bash", prompt=False)
        self.assertIn('--mode) COMPREPLY=($(compgen -W "CLASSIFY SKIP MERGE SPLIT"', script)
        self.assertIn('--shell) COMPREPLY=($(compgen -W "bash zsh fish plain none"', script)

    def test_flags_toggle_parts(self):
        self.assertNotIn("__nemc_light", _init("bash", prompt=False))
        self.assertNotIn("_nemc_complete", _init("bash", completion=False))
        with self.assertRaises(ValueError):
            shell.init_script("tcsh", commands.build_parser())


class TestScriptsAreValid(unittest.TestCase):
    def _check(self, exe, flag, text):
        with tempfile.NamedTemporaryFile("w", suffix=".sh", delete=False) as fh:
            fh.write(text)
        try:
            r = subprocess.run([exe, flag, fh.name], capture_output=True, text=True)
            self.assertEqual(r.returncode, 0, r.stderr)
        finally:
            os.unlink(fh.name)

    @unittest.skipUnless(HAS_BASH, "bash not installed")
    def test_bash_syntax(self):
        self._check("bash", "-n", _init("bash"))

    @unittest.skipUnless(HAS_ZSH, "zsh not installed")
    def test_zsh_syntax(self):
        self._check("zsh", "-n", _init("zsh"))

    @unittest.skipUnless(HAS_FISH, "fish not installed")
    def test_fish_syntax(self):
        self._check("fish", "--no-execute", _init("fish"))

    def test_fish_structure(self):
        script = _init("fish")
        self.assertIn("complete -c nemc -n '__fish_use_subcommand' -a scan", script)
        self.assertIn("functions -c fish_prompt __nemc_orig_fish_prompt", script)
        self.assertIn("-l mode -r -a 'CLASSIFY SKIP MERGE SPLIT'", script)


@unittest.skipUnless(HAS_BASH, "bash not installed")
class TestBashBehaviour(unittest.TestCase):
    def run_bash(self, body):
        script = _init("bash") + "\n" + body
        r = subprocess.run(["bash", "--norc", "--noprofile", "-c", script], capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return r.stdout

    def complete(self, *words):
        body = ("COMP_WORDS=(" + " ".join(f"'{w}'" for w in words) + "); COMP_CWORD=$((${#COMP_WORDS[@]}-1)); "
                "COMPREPLY=(); _nemc_complete; echo \"${COMPREPLY[*]}\"")
        return self.run_bash(body).split()

    def test_completion(self):
        self.assertEqual(self.complete("nemc", "re"), ["rescan", "reclaim"])
        self.assertEqual(self.complete("nemc", "scan", "--mode", ""), ["CLASSIFY", "SKIP", "MERGE", "SPLIT"])
        self.assertEqual(self.complete("nemc", "--db", "x.db", "sta"), ["status"])  # --db value is skipped
        self.assertIn("--execute", self.complete("nemc", "reclaim", "--"))

    def test_prompt_hook_is_idempotent(self):
        out = self.run_bash('PS1="$ "; eval "$(declare -f __nemc_light >/dev/null && echo :)"; '
                            + _init("bash", completion=False).replace("\n", "\n") + '\necho "$PS1"')
        self.assertEqual(out.strip().count("__nemc_light"), 1)


if __name__ == "__main__":
    unittest.main()
