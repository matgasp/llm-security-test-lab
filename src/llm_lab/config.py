"""Runtime configuration read from environment variables."""

from __future__ import annotations

from dataclasses import dataclass
import os


@dataclass(frozen=True)
class Settings:
  ollama_url: str
  ollama_model: str
  timeout_seconds: float
  max_tokens: int

  @classmethod
  def from_environment(cls) -> "Settings":
    return cls(
      ollama_url=os.getenv("OLLAMA_URL", "http://localhost:11434/api/chat"),
      ollama_model=os.getenv("OLLAMA_MODEL", "qwen3:8b"),
      timeout_seconds=float(os.getenv("OLLAMA_TIMEOUT", "120")),
      max_tokens=int(os.getenv("OLLAMA_MAX_TOKENS", "256")),
    )
