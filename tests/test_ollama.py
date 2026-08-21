from __future__ import annotations

import httpx
import pytest

from llm_lab.config import Settings
from llm_lab.corpus import load_cases
from llm_lab.ollama import OllamaError, OllamaModel


def _settings() -> Settings:
  return Settings(
    ollama_url="http://ollama.test/api/chat",
    ollama_model="test-model",
    timeout_seconds=5,
    max_tokens=64,
  )


def test_settings_are_loaded_from_environment(monkeypatch) -> None:
  monkeypatch.setenv("OLLAMA_URL", "http://custom.test/api/chat")
  monkeypatch.setenv("OLLAMA_MODEL", "custom-model")
  monkeypatch.setenv("OLLAMA_TIMEOUT", "9")
  monkeypatch.setenv("OLLAMA_MAX_TOKENS", "32")

  settings = Settings.from_environment()

  assert settings.ollama_model == "custom-model"
  assert settings.timeout_seconds == 9
  assert settings.max_tokens == 32


def test_healthcheck_uses_tags_endpoint(monkeypatch) -> None:
  requested: list[str] = []

  class Response:
    is_success = True

  def fake_get(url: str, timeout: int) -> Response:
    requested.append(url)
    assert timeout == 5
    return Response()

  monkeypatch.setattr("llm_lab.ollama.httpx.get", fake_get)

  assert OllamaModel(_settings()).healthcheck()
  assert requested == ["http://ollama.test/api/tags"]


def test_generate_sends_bounded_non_thinking_request(monkeypatch) -> None:
  captured: dict[str, object] = {}

  class Response:
    def raise_for_status(self) -> None:
      return None

    def json(self) -> dict[str, object]:
      return {"message": {"content": "safe response"}}

  def fake_post(url: str, **kwargs: object) -> Response:
    captured["url"] = url
    captured.update(kwargs)
    return Response()

  monkeypatch.setattr("llm_lab.ollama.httpx.post", fake_post)
  case = next(case for case in load_cases() if case.id == "LLM01-INDIRECT-001")
  response = OllamaModel(_settings()).generate(case)
  payload = captured["json"]

  assert response.text == "safe response"
  assert isinstance(payload, dict)
  assert payload["think"] is False
  assert payload["options"]["num_predict"] == 64
  assert "trust=\"untrusted\"" in payload["messages"][1]["content"]


def test_generate_wraps_http_failures(monkeypatch) -> None:
  def fail(*args: object, **kwargs: object) -> None:
    del args, kwargs
    raise httpx.ConnectError("offline")

  monkeypatch.setattr("llm_lab.ollama.httpx.post", fail)
  case = load_cases()[0]

  with pytest.raises(OllamaError, match="Ollama request failed"):
    OllamaModel(_settings()).generate(case)
