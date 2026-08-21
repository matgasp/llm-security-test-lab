"""Load and validate the versioned OWASP LLM security corpus."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from llm_lab.models import AttackCase, DefenseLayer, ToolCall


CORPUS_PATH = Path(__file__).with_name("data") / "attacks.json"
VECTORS = {"direct", "indirect", "encoded", "invisible-unicode", "output", "tool", "benign"}
OWASP_IDS = {f"LLM{index:02d}" for index in range(1, 11)}


def _required_text(item: dict[str, Any], field: str) -> str:
  value = item.get(field)

  if not isinstance(value, str) or not value.strip():
    raise ValueError(f"{item.get('id', '<unknown>')}: {field} must be non-empty text")

  return value


def load_cases(path: str | Path = CORPUS_PATH) -> list[AttackCase]:
  raw = json.loads(Path(path).read_text(encoding="utf-8"))

  if not isinstance(raw, list) or not raw:
    raise ValueError("The attack corpus must be a non-empty JSON array")

  cases: list[AttackCase] = []
  seen: set[str] = set()

  for item in raw:
    if not isinstance(item, dict):
      raise ValueError("Every corpus entry must be an object")

    case_id = _required_text(item, "id")

    if case_id in seen:
      raise ValueError(f"Duplicate case id: {case_id}")

    seen.add(case_id)

    vector = _required_text(item, "vector")

    if vector not in VECTORS:
      raise ValueError(f"{case_id}: unsupported vector {vector!r}")

    is_attack = bool(item.get("is_attack", True))
    owasp_id = item.get("owasp_id")

    if is_attack and owasp_id not in OWASP_IDS:
      raise ValueError(f"{case_id}: attack cases require a valid owasp_id")

    expected = item.get("expected_defense")
    expected_defense = DefenseLayer(expected) if expected is not None else None

    if is_attack and expected_defense is None:
      raise ValueError(f"{case_id}: attack cases require expected_defense")

    tool_calls = tuple(
      ToolCall(name=_required_text(call, "name"), arguments=dict(call.get("arguments", {})))
      for call in item.get("compromised_tool_calls", [])
    )

    repetitions = item.get("compromised_output_repetitions", 1)

    if not isinstance(repetitions, int) or not 1 <= repetitions <= 100_000:
      raise ValueError(f"{case_id}: compromised_output_repetitions is out of range")

    success_min = item.get("success_min_output_chars")

    if success_min is not None and (not isinstance(success_min, int) or success_min < 1):
      raise ValueError(f"{case_id}: success_min_output_chars must be a positive integer")

    cases.append(
      AttackCase(
        id=case_id,
        title=_required_text(item, "title"),
        owasp_id=owasp_id,
        vector=vector,
        user_prompt=_required_text(item, "user_prompt"),
        untrusted_content=item.get("untrusted_content"),
        protected_values=tuple(item.get("protected_values", [])),
        success_signals=tuple(item.get("success_signals", [])),
        success_min_output_chars=success_min,
        dangerous_tools=tuple(item.get("dangerous_tools", [])),
        compromised_output=str(item.get("compromised_output", "")) * repetitions,
        compromised_tool_calls=tool_calls,
        compromised_evidence_ids=tuple(item.get("compromised_evidence_ids", [])),
        trusted_evidence_ids=tuple(item.get("trusted_evidence_ids", [])),
        authorized_tenant=item.get("authorized_tenant"),
        expected_defense=expected_defense,
        is_attack=is_attack,
      )
    )

  return cases
