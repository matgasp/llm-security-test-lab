"""Domain models shared by the laboratory."""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class DefenseLayer(StrEnum):
  INPUT = "input"
  OUTPUT = "output"
  CAPABILITY = "capability"
  EVIDENCE = "evidence"


@dataclass(frozen=True)
class ToolCall:
  """A model-proposed operation. The lab never performs real side effects."""

  name: str
  arguments: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class ModelResponse:
  text: str
  tool_calls: tuple[ToolCall, ...] = ()
  evidence_ids: tuple[str, ...] = ()


@dataclass(frozen=True)
class AttackCase:
  id: str
  title: str
  owasp_id: str | None
  vector: str
  user_prompt: str
  untrusted_content: str | None
  protected_values: tuple[str, ...]
  success_signals: tuple[str, ...]
  success_min_output_chars: int | None
  dangerous_tools: tuple[str, ...]
  compromised_output: str
  compromised_tool_calls: tuple[ToolCall, ...]
  compromised_evidence_ids: tuple[str, ...]
  trusted_evidence_ids: tuple[str, ...]
  authorized_tenant: str | None
  expected_defense: DefenseLayer | None
  is_attack: bool = True


@dataclass(frozen=True)
class GuardDecision:
  allowed: bool
  reasons: tuple[str, ...] = ()


@dataclass(frozen=True)
class RunResult:
  mode: str
  blocked: bool
  layer: DefenseLayer | None
  visible_output: str
  proposed_tools: tuple[ToolCall, ...] = ()
  executed_tools: tuple[ToolCall, ...] = ()
  reasons: tuple[str, ...] = ()
  latency_ms: float | None = None


@dataclass(frozen=True)
class Comparison:
  case: AttackCase
  baseline: RunResult
  protected: RunResult
  baseline_attack_succeeded: bool
  protected_attack_succeeded: bool
