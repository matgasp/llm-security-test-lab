"""Deterministic adversarial test double used to prove application controls."""

from llm_lab.models import AttackCase, ModelResponse


class CompromisedModel:
  """Always emits the attacker's desired result from the versioned case.

  Security tests should not depend on a model choosing to refuse. This test
  double represents the worst case: instruction following has already failed.
  """

  def generate(self, case: AttackCase) -> ModelResponse:
    return ModelResponse(
      case.compromised_output,
      case.compromised_tool_calls,
      case.compromised_evidence_ids,
    )
