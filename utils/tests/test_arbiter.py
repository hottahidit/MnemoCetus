"""
Tests for the v0.8 AI arbiter (utils/arbiter.py) and its settings block.

Everything here mocks arbiter._post_json -> no network is ever touched. The focus is the parts that
carry risk: the privacy redaction, the defensive JSON parsing / validation, per-provider request shape,
the fail-soft behaviour, and the settings deep-merge.
"""

import os
import sys
import json
import tempfile
import unittest
from unittest import mock

REPO_ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", ".."))
sys.path.insert(0, os.path.join(REPO_ROOT, "utils"))

import arbiter        # noqa: E402
import settings       # noqa: E402


VALID = {"language": "python", "category": "backend",
         "frameworks": ["flask"], "confidence": 0.9, "rationale": "flask app"}


def _openai_reply(text):
    return {"choices": [{"message": {"content": text}}]}


class TestIsLocal(unittest.TestCase):
    def test_localhost_and_private_are_local(self):
        for url in ("http://localhost:11434/v1", "http://127.0.0.1:11434/v1",
                    "http://192.168.1.5:11434/v1", "http://10.0.0.2/v1", "http://box.local/v1"):
            self.assertTrue(arbiter.is_local(url), url)

    def test_public_hosts_are_not_local(self):
        for url in ("https://api.openai.com/v1", "https://api.deepseek.com/v1",
                    "https://generativelanguage.googleapis.com/v1beta"):
            self.assertFalse(arbiter.is_local(url), url)


class TestRedaction(unittest.TestCase):
    def setUp(self):
        self.project = {"path": "/home/nemesis/Projects/APP/SokaOS", "language": "python",
                        "category": "backend", "confidence": 0.4, "frameworks": ["flask"],
                        "markers": ["requirements.txt"], "dependencies": ["flask", "requests"],
                        "file_count": 12}

    def test_local_keeps_full_path(self):
        facts = arbiter.build_facts(self.project, workspace_root="/home/nemesis/Projects/APP", redact=False)
        self.assertEqual(facts["path"], "/home/nemesis/Projects/APP/SokaOS")

    def test_cloud_redacts_to_workspace_relative_keeping_folder_name(self):
        facts = arbiter.build_facts(self.project, workspace_root="/home/nemesis/Projects/APP", redact=True)
        self.assertEqual(facts["path"], "SokaOS")                 # folder name kept
        self.assertNotIn("/home/nemesis", json.dumps(facts))       # absolute/home prefix gone

    def test_cloud_outside_workspace_falls_back_to_basename(self):
        facts = arbiter.build_facts(self.project, workspace_root="/somewhere/else", redact=True)
        self.assertEqual(facts["path"], "SokaOS")

    def test_dependencies_capped(self):
        p = dict(self.project, dependencies=[f"dep{i}" for i in range(200)])
        self.assertEqual(len(arbiter.build_facts(p)["dependencies"]), 50)


class TestParsing(unittest.TestCase):
    def test_plain_json(self):
        self.assertEqual(arbiter._normalise(json.dumps(VALID))["category"], "backend")

    def test_json_wrapped_in_prose_and_fences(self):
        text = "Sure!\n```json\n" + json.dumps(VALID) + "\n```\nHope that helps."
        out = arbiter._normalise(text)
        self.assertEqual(out["language"], "python")
        self.assertEqual(out["frameworks"], ["flask"])

    def test_invalid_category_is_dropped_not_trusted(self):
        out = arbiter._normalise(json.dumps({"language": "python", "category": "web-thing", "confidence": 0.8}))
        self.assertIsNone(out["category"])       # not in the allowed set -> dropped
        self.assertEqual(out["language"], "python")

    def test_confidence_clamped(self):
        self.assertEqual(arbiter._normalise(json.dumps({"category": "cli", "confidence": 5}))["confidence"], 1.0)

    def test_nothing_actionable_returns_none(self):
        self.assertIsNone(arbiter._normalise(json.dumps({"confidence": 0.5})))
        self.assertIsNone(arbiter._normalise("not json at all"))
        self.assertIsNone(arbiter._normalise(""))


class TestOpenAICompatible(unittest.TestCase):
    def test_success_parses_suggestion(self):
        with mock.patch.object(arbiter, "_post_json", return_value=_openai_reply(json.dumps(VALID))) as m:
            p = arbiter.OpenAICompatibleProvider("http://localhost:11434/v1", "llama3.1")
            out = p.classify({"path": "x"})
        self.assertEqual(out["category"], "backend")
        url, payload = m.call_args.args[0], m.call_args.args[1]
        self.assertTrue(url.endswith("/chat/completions"))
        self.assertEqual(payload["model"], "llama3.1")

    def test_api_key_sets_bearer_header(self):
        with mock.patch.object(arbiter, "_post_json", return_value=_openai_reply(json.dumps(VALID))) as m:
            arbiter.OpenAICompatibleProvider("https://api.deepseek.com/v1", "deepseek-chat", "sk-xyz").classify({"path": "x"})
        headers = m.call_args.args[2]
        self.assertEqual(headers["Authorization"], "Bearer sk-xyz")

    def test_transport_error_fails_soft(self):
        with mock.patch.object(arbiter, "_post_json", side_effect=OSError("boom")):
            self.assertIsNone(arbiter.OpenAICompatibleProvider("http://localhost:11434/v1", "m").classify({"path": "x"}))

    def test_unexpected_shape_fails_soft(self):
        with mock.patch.object(arbiter, "_post_json", return_value={"unexpected": True}):
            self.assertIsNone(arbiter.OpenAICompatibleProvider("http://localhost:11434/v1", "m").classify({"path": "x"}))


class TestAnthropic(unittest.TestCase):
    def test_success(self):
        reply = {"content": [{"text": json.dumps(VALID)}]}
        with mock.patch.object(arbiter, "_post_json", return_value=reply) as m:
            out = arbiter.AnthropicProvider("https://api.anthropic.com/v1", "claude-haiku-4-5", "sk-ant").classify({"path": "x"})
        self.assertEqual(out["category"], "backend")
        self.assertEqual(m.call_args.args[2]["x-api-key"], "sk-ant")

    def test_no_key_returns_none_without_calling(self):
        with mock.patch.object(arbiter, "_post_json") as m:
            self.assertIsNone(arbiter.AnthropicProvider("https://api.anthropic.com/v1", "claude-haiku-4-5", None).classify({"path": "x"}))
        m.assert_not_called()


class TestGemini(unittest.TestCase):
    def test_success_puts_key_in_query(self):
        reply = {"candidates": [{"content": {"parts": [{"text": json.dumps(VALID)}]}}]}
        with mock.patch.object(arbiter, "_post_json", return_value=reply) as m:
            out = arbiter.GeminiProvider("https://generativelanguage.googleapis.com/v1beta", "gemini-1.5-flash", "k123").classify({"path": "x"})
        self.assertEqual(out["language"], "python")
        self.assertIn("key=k123", m.call_args.args[0])


class TestGetProvider(unittest.TestCase):
    def test_disabled_returns_none_provider(self):
        self.assertIsInstance(arbiter.get_provider({"enabled": False}), arbiter.NoneProvider)

    def test_missing_model_returns_none_provider(self):
        cfg = {"enabled": True, "provider": "ollama", "base_url": "http://localhost:11434/v1", "model": ""}
        self.assertIsInstance(arbiter.get_provider(cfg), arbiter.NoneProvider)

    def test_kinds(self):
        base = {"enabled": True, "model": "m"}
        self.assertIsInstance(arbiter.get_provider({**base, "provider": "ollama", "base_url": "http://localhost:11434/v1"}), arbiter.OpenAICompatibleProvider)
        self.assertIsInstance(arbiter.get_provider({**base, "provider": "anthropic", "base_url": "https://api.anthropic.com/v1"}), arbiter.AnthropicProvider)
        self.assertIsInstance(arbiter.get_provider({**base, "provider": "gemini", "base_url": "https://generativelanguage.googleapis.com/v1beta"}), arbiter.GeminiProvider)

    def test_api_key_read_from_named_env(self):
        cfg = {"enabled": True, "provider": "deepseek", "base_url": "https://api.deepseek.com/v1",
               "model": "deepseek-chat", "api_key_env": "MC_TEST_KEY"}
        with mock.patch.dict(os.environ, {"MC_TEST_KEY": "sk-from-env"}):
            self.assertEqual(arbiter.get_provider(cfg).api_key, "sk-from-env")


class TestClassifyProjectRedactionEndToEnd(unittest.TestCase):
    project = {"path": "/home/nemesis/Projects/APP/SokaOS", "language": "python",
               "frameworks": [], "markers": ["package.json"], "dependencies": ["react"], "file_count": 9}

    def _run(self, base_url):
        cfg = {"enabled": True, "provider": "custom", "base_url": base_url,
               "model": "m", "api_key_env": ""}
        captured = {}
        def fake(url, payload, headers=None, timeout=30):
            captured["facts"] = json.loads(payload["messages"][-1]["content"])
            return _openai_reply(json.dumps(VALID))
        with mock.patch.object(arbiter, "_post_json", side_effect=fake):
            arbiter.classify_project(self.project, cfg, workspace_root="/home/nemesis/Projects/APP")
        return captured["facts"]

    def test_cloud_endpoint_redacts_path(self):
        facts = self._run("https://api.example.com/v1")
        self.assertEqual(facts["path"], "SokaOS")

    def test_local_endpoint_sends_full_path(self):
        facts = self._run("http://localhost:11434/v1")
        self.assertEqual(facts["path"], "/home/nemesis/Projects/APP/SokaOS")


class TestSettingsArbiterBlock(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, ".mnemocetus.json")
        self._orig = settings.SETTINGS_PATH
        settings.SETTINGS_PATH = self.path

    def tearDown(self):
        settings.SETTINGS_PATH = self._orig

    def test_defaults_when_no_file(self):
        cfg = settings.load()
        self.assertFalse(cfg["configured"])
        self.assertFalse(cfg["arbiter"]["enabled"])
        self.assertEqual(cfg["arbiter"]["provider"], "ollama")

    def test_old_flat_config_gets_default_arbiter_block(self):
        with open(self.path, "w") as f:
            json.dump({"web_enabled": True, "web_port": 8080}, f)   # a pre-v0.8 config
        cfg = settings.load()
        self.assertTrue(cfg["web_enabled"])
        self.assertIn("arbiter", cfg)
        self.assertFalse(cfg["arbiter"]["enabled"])       # merged in from defaults

    def test_partial_arbiter_block_merges_missing_subkeys(self):
        with open(self.path, "w") as f:
            json.dump({"arbiter": {"enabled": True, "provider": "deepseek"}}, f)
        cfg = settings.load()
        self.assertTrue(cfg["arbiter"]["enabled"])
        self.assertEqual(cfg["arbiter"]["provider"], "deepseek")
        self.assertFalse(cfg["arbiter"]["run_after_scan"])    # default filled in

    def test_round_trip_and_unknown_keys_dropped(self):
        cfg = settings.load()
        cfg["configured"] = True
        cfg["arbiter"]["enabled"] = True
        cfg["arbiter"]["model"] = "llama3.1"
        cfg["arbiter"]["junk"] = "nope"
        self.assertTrue(settings.save(cfg))
        again = settings.load()
        self.assertTrue(again["configured"])
        self.assertEqual(again["arbiter"]["model"], "llama3.1")
        with open(self.path) as f:
            on_disk = json.load(f)
        self.assertNotIn("junk", on_disk["arbiter"])          # unknown sub-key not persisted

    def test_load_returns_independent_copies(self):
        a, b = settings.load(), settings.load()
        a["arbiter"]["model"] = "changed"
        self.assertEqual(b["arbiter"]["model"], "")           # not sharing the defaults dict


if __name__ == "__main__":
    unittest.main()
