# AI arbiter for MnemoCetus (v0.8) -> an OPT-IN second opinion on low-confidence projects.
#
# The base classifier stays non-AI and authoritative; this only ever ARBITRATES the projects the
# recogniser was unsure about, and the user still confirms every suggestion. Nothing here runs unless
# the user has turned it on in settings.
#
# Design notes:
#   - Zero extra dependencies -> every provider is plain JSON-over-HTTP through urllib. Providers are
#     isolated behind the ArbiterProvider interface, so swapping one to its official SDK later (for
#     streaming / awkward auth) touches only that adapter.
#   - Privacy is tiered by endpoint: a LOCAL endpoint (Ollama / localhost) gets full facts; a CLOUD
#     endpoint gets the path redacted to workspace-relative -> the absolute / home prefix is stripped
#     but the folder names are kept (they genuinely help, e.g. "SokaOS").
#   - Every call fails soft: any network / parse / validation problem returns None, never an exception,
#     so the CLI is never blocked by the arbiter.

import json
import os
import ipaddress
import urllib.request
import urllib.error
from urllib.parse import urlparse

# The categories the arbiter is allowed to return -> mirrors the CLI review choices.
CATEGORIES = ["backend", "frontend", "full stack", "automation", "library",
              "cli", "desktop", "application", "data/ml", "other"]

# Provider presets: base_url + the env var a cloud key is read from (None -> local, no key).
# 'model' is a SUGGESTION only -> the setup wizard collects the real one (Ollama lists what's installed;
# cloud model ids drift, so we never hard-depend on these).
PRESETS = {
    "ollama":     {"base_url": "http://localhost:11434/v1",                 "api_key_env": "",                  "model": ""},
    "openai":     {"base_url": "https://api.openai.com/v1",                 "api_key_env": "OPENAI_API_KEY",    "model": "gpt-4o-mini"},
    "deepseek":   {"base_url": "https://api.deepseek.com/v1",               "api_key_env": "DEEPSEEK_API_KEY",  "model": "deepseek-chat"},
    "groq":       {"base_url": "https://api.groq.com/openai/v1",            "api_key_env": "GROQ_API_KEY",      "model": "llama-3.1-8b-instant"},
    "openrouter": {"base_url": "https://openrouter.ai/api/v1",              "api_key_env": "OPENROUTER_API_KEY", "model": ""},
    "anthropic":  {"base_url": "https://api.anthropic.com/v1",              "api_key_env": "ANTHROPIC_API_KEY", "model": "claude-haiku-4-5"},
    "gemini":     {"base_url": "https://generativelanguage.googleapis.com/v1beta", "api_key_env": "GEMINI_API_KEY", "model": "gemini-1.5-flash"},
}

_SYSTEM_PROMPT = (
    "You identify software project types from facts about a directory. "
    "Reply with ONLY a JSON object, no prose, of the form: "
    '{"language": string, "category": string, "frameworks": [string], '
    '"confidence": number between 0 and 1, "rationale": one short sentence}. '
    "The category MUST be exactly one of: " + ", ".join(CATEGORIES) + "."
)

_TIMEOUT = 30  # seconds; the arbiter is a small single call, so a short ceiling is fine


# --------------------------------------------------------------------------- #
# Endpoint classification + fact building (redaction)
# --------------------------------------------------------------------------- #
def is_local(base_url):
    """True if base_url points at this machine / a private network -> such endpoints get un-redacted facts."""
    host = (urlparse(base_url).hostname or "").lower()
    if not host or host in ("localhost", "0.0.0.0") or host.endswith(".local"):
        return True
    try:
        return ipaddress.ip_address(host).is_private or ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def _shown_path(path, workspace_root, redact):
    """The project path as the arbiter should see it -> full when local, workspace-relative (folder names kept) when redacting."""
    if not redact:
        return path
    if workspace_root:
        try:
            rel = os.path.relpath(path, workspace_root)
            if not rel.startswith(".."):
                return rel
        except ValueError:
            pass
    return os.path.basename(os.path.normpath(path))


def build_facts(project, workspace_root=None, redact=False):
    """
    The minimal fact dict handed to the arbiter.

    'project' is an inflated project row (path, language, category, confidence, frameworks, markers, dependencies, file_count).
    When redact is True the path is reduced to workspace-relative / basename; every other field is metadata that carries no absolute location.
    """
    return {
        "path": _shown_path(project.get("path", ""), workspace_root, redact),
        "detected_language": project.get("language"),
        "detected_category": project.get("category"),
        "detected_confidence": round(project.get("confidence") or 0, 2),
        "frameworks": list(project.get("frameworks") or []),
        "markers": list(project.get("markers") or []),
        "dependencies": list(project.get("dependencies") or [])[:50],
        "file_count": project.get("file_count"),
    }


# --------------------------------------------------------------------------- #
# HTTP transport + response parsing (the seam tests mock)
# --------------------------------------------------------------------------- #
def _post_json(url, payload, headers=None, timeout=_TIMEOUT):
    """POST a JSON body and return the parsed JSON response. Raises on any transport/HTTP error."""
    body = json.dumps(payload).encode("utf-8")
    req = urllib.request.Request(
        url, data=body, method="POST",
        headers={"Content-Type": "application/json", **(headers or {})},
    )
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read().decode("utf-8"))


def list_models(base_url, api_key=None, timeout=5):
    """Best-effort GET of an OpenAI-compatible /models list (works for Ollama too) -> [ids] or None if it can't be listed."""
    url = (base_url or "").rstrip("/") + "/models"
    headers = {"Authorization": f"Bearer {api_key}"} if api_key else {}
    try:
        req = urllib.request.Request(url, headers=headers, method="GET")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            data = json.loads(resp.read().decode("utf-8"))
        ids = [m.get("id") for m in data.get("data", []) if isinstance(m, dict) and m.get("id")]
        return ids or None
    except (urllib.error.URLError, OSError, KeyError, TypeError, ValueError):
        return None


def _extract_json(text):
    """Pull the first JSON object out of a model reply, tolerating prose or code fences around it."""
    if not text:
        return None
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except (ValueError, TypeError):
        pass
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end > start:
        try:
            obj = json.loads(text[start:end + 1])
            return obj if isinstance(obj, dict) else None
        except (ValueError, TypeError):
            return None
    return None


def _normalise(text):
    """Turn a raw model reply into a validated suggestion dict, or None if it isn't usable."""
    obj = _extract_json(text)
    if not obj:
        return None
    category = obj.get("category")
    if isinstance(category, str):
        match = next((c for c in CATEGORIES if c.lower() == category.strip().lower()), None)
        category = match  # an out-of-set category is dropped rather than trusted
    else:
        category = None
    language = obj.get("language")
    language = language.strip() if isinstance(language, str) and language.strip() else None
    if not language and not category:
        return None  # nothing actionable
    try:
        confidence = max(0.0, min(1.0, float(obj.get("confidence"))))
    except (TypeError, ValueError):
        confidence = None
    frameworks = [str(f) for f in obj.get("frameworks") or [] if f]
    rationale = obj.get("rationale")
    rationale = rationale.strip() if isinstance(rationale, str) else ""
    return {"language": language, "category": category, "frameworks": frameworks,
            "confidence": confidence, "rationale": rationale}


# --------------------------------------------------------------------------- #
# Providers
# --------------------------------------------------------------------------- #
class ArbiterProvider:
    """Interface: classify(facts) -> a validated suggestion dict, or None on any failure."""

    def classify(self, facts):
        raise NotImplementedError

    def ping(self):
        """Best-effort connection test -> (ok: bool, message: str). Default: try a trivial classify."""
        try:
            out = self.classify({"path": "ping", "detected_language": "python",
                                  "markers": ["pyproject.toml"], "dependencies": ["flask"]})
        except Exception as exc:  # noqa: BLE001 -> ping must never raise
            return False, str(exc)
        return (out is not None), ("reachable" if out is not None else "no usable response")


class NoneProvider(ArbiterProvider):
    """The disabled arbiter -> never suggests anything."""

    def classify(self, facts):
        return None

    def ping(self):
        return False, "arbiter is disabled"


class OpenAICompatibleProvider(ArbiterProvider):
    """Any endpoint speaking the OpenAI /chat/completions shape -> Ollama, OpenAI, DeepSeek, Groq, OpenRouter, xAI, Mistral, ..."""

    def __init__(self, base_url, model, api_key=None):
        self.base_url = (base_url or "").rstrip("/")
        self.model = model
        self.api_key = api_key

    def classify(self, facts):
        headers = {"Authorization": f"Bearer {self.api_key}"} if self.api_key else {}
        payload = {
            "model": self.model,
            "temperature": 0,
            "stream": False,
            "messages": [
                {"role": "system", "content": _SYSTEM_PROMPT},
                {"role": "user", "content": json.dumps(facts)},
            ],
        }
        try:
            data = _post_json(f"{self.base_url}/chat/completions", payload, headers)
            return _normalise(data["choices"][0]["message"]["content"])
        except (urllib.error.URLError, OSError, KeyError, IndexError, TypeError, ValueError):
            return None


class AnthropicProvider(ArbiterProvider):
    """Anthropic Messages API (distinct shape: x-api-key header, system field, content blocks)."""

    def __init__(self, base_url, model, api_key=None):
        self.base_url = (base_url or "https://api.anthropic.com/v1").rstrip("/")
        self.model = model
        self.api_key = api_key

    def classify(self, facts):
        if not self.api_key:
            return None
        headers = {"x-api-key": self.api_key, "anthropic-version": "2023-06-01"}
        payload = {
            "model": self.model,
            "max_tokens": 512,
            "system": _SYSTEM_PROMPT,
            "messages": [{"role": "user", "content": json.dumps(facts)}],
        }
        try:
            data = _post_json(f"{self.base_url}/messages", payload, headers)
            return _normalise(data["content"][0]["text"])
        except (urllib.error.URLError, OSError, KeyError, IndexError, TypeError, ValueError):
            return None


class GeminiProvider(ArbiterProvider):
    """Google Gemini generateContent (key in the query string, contents/parts shape)."""

    def __init__(self, base_url, model, api_key=None):
        self.base_url = (base_url or "https://generativelanguage.googleapis.com/v1beta").rstrip("/")
        self.model = model
        self.api_key = api_key

    def classify(self, facts):
        if not self.api_key:
            return None
        url = f"{self.base_url}/models/{self.model}:generateContent?key={self.api_key}"
        payload = {
            "contents": [{"parts": [{"text": _SYSTEM_PROMPT + "\n\n" + json.dumps(facts)}]}],
            "generationConfig": {"temperature": 0},
        }
        try:
            data = _post_json(url, payload)
            return _normalise(data["candidates"][0]["content"]["parts"][0]["text"])
        except (urllib.error.URLError, OSError, KeyError, IndexError, TypeError, ValueError):
            return None


def get_provider(arbiter_cfg):
    """
    Build the provider described by a settings 'arbiter' block, or NoneProvider when it's off / misconfigured.

    The adapter kind is derived from the preset name: 'anthropic' and 'gemini' have their own APIs; everything
    else (ollama / openai / deepseek / groq / openrouter / custom) speaks the OpenAI-compatible shape.
    """
    if not arbiter_cfg or not arbiter_cfg.get("enabled"):
        return NoneProvider()
    provider = arbiter_cfg.get("provider") or "ollama"
    base_url = arbiter_cfg.get("base_url") or PRESETS.get(provider, {}).get("base_url", "")
    model = arbiter_cfg.get("model") or ""
    key_env = arbiter_cfg.get("api_key_env") or ""
    api_key = os.environ.get(key_env) if key_env else None
    if not model or not base_url:
        return NoneProvider()
    if provider == "anthropic":
        return AnthropicProvider(base_url, model, api_key)
    if provider == "gemini":
        return GeminiProvider(base_url, model, api_key)
    return OpenAICompatibleProvider(base_url, model, api_key)


def classify_project(project, arbiter_cfg, workspace_root=None):
    """
    Ask the configured arbiter about one project, honouring the privacy tier.

    Returns a validated suggestion dict (language / category / frameworks / confidence / rationale) or None.
    """
    provider = get_provider(arbiter_cfg)
    if isinstance(provider, NoneProvider):
        return None
    redact = not is_local(arbiter_cfg.get("base_url") or "")
    return provider.classify(build_facts(project, workspace_root, redact))
