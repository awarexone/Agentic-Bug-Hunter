"""Regression tests for the Groq provider model wiring.

Groq returns HTTP 404 on `/chat/completions` when a model id has been
decommissioned (not when the URL is wrong — the path is fixed). In 2026 the
old default `llama-3.3-70b-versatile` and the whole advertised list
(`mixtral-8x7b-32768`, `gemma2-9b-it`, ...) passed their shutdown dates, which
is what produced the "404 Not Found" the fix addresses. These tests pin the
current defaults so a stale id can't creep back in.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path


def load_brain_module():
    brain_path = Path(__file__).resolve().parents[1] / "bughunter" / "brain.py"
    spec = importlib.util.spec_from_file_location("brain_module", brain_path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader is not None
    spec.loader.exec_module(module)
    return module


# Models Groq has decommissioned — none of these may be a default or advertised.
DECOMMISSIONED = {
    "mixtral-8x7b-32768",
    "gemma2-9b-it",
    "llama3-70b-8192",
    "llama3-8b-8192",
}


def test_groq_default_model_is_current():
    brain = load_brain_module()
    assert brain.LLMClient.DEFAULT_MODELS["groq"] == "openai/gpt-oss-20b"


def test_groq_default_is_not_decommissioned():
    brain = load_brain_module()
    assert brain.LLMClient.DEFAULT_MODELS["groq"] not in DECOMMISSIONED


def test_groq_legacy_ids_remap_to_current():
    brain = load_brain_module()
    aliases = brain.LLMClient.GROQ_LEGACY_ALIASES
    # Every retired id we know about is remapped...
    assert DECOMMISSIONED.issubset(set(aliases))
    # ...and every target is a current gpt-oss model, never another dead id.
    for new_model in aliases.values():
        assert new_model.startswith("openai/gpt-oss-")
        assert new_model not in DECOMMISSIONED


def test_groq_advertised_list_has_no_dead_defaults():
    brain = load_brain_module()
    client = brain.LLMClient.__new__(brain.LLMClient)
    client.provider = "groq"
    client._ollama = None
    models = client.list_models()
    assert "openai/gpt-oss-20b" in models
    # The two hard-decommissioned ids must not be advertised as choices.
    assert "mixtral-8x7b-32768" not in models
    assert "gemma2-9b-it" not in models


def test_groq_base_url_unchanged(monkeypatch):
    """The 404 was a dead model, not a bad path — keep the canonical base."""
    import sys
    import types

    brain = load_brain_module()

    # Stub `requests` so _init_provider doesn't need the real dependency.
    fake = types.ModuleType("requests")
    fake.Session = lambda: types.SimpleNamespace(headers={
        # a real Session.headers is a dict-like with .update(); a plain dict
        # already provides that, which is all _init_provider uses.
    })
    monkeypatch.setitem(sys.modules, "requests", fake)
    monkeypatch.setenv("GROQ_API_KEY", "test-key")

    client = brain.LLMClient("groq")
    assert client._api_base == "https://api.groq.com/openai/v1"
