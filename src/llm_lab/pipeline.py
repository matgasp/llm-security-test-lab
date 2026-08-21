"""Comparable vulnerable and protected application pipelines."""

from __future__ import annotations

import time
from typing import Protocol

from llm_lab.defenses import CapabilityPolicy, EvidencePolicy, InputGuard, OutputGuard
from llm_lab.models import AttackCase, DefenseLayer, ModelResponse, RunResult


BLOCKED_MESSAGE = "Request blocked by application security policy."


class Model(Protocol):
  def generate(self, case: AttackCase) -> ModelResponse: ...


class BaselinePipeline:
  """Intentionally vulnerable reference: trusts output and every tool request."""

  def __init__(self, model: Model) -> None:
    self.model = model

  def run(self, case: AttackCase) -> RunResult:
    started = time.perf_counter()
    response = self.model.generate(case)
    elapsed = (time.perf_counter() - started) * 1000

    return RunResult(
      mode="baseline",
      blocked=False,
      layer=None,
      visible_output=response.text,
      proposed_tools=response.tool_calls,
      # Simulation only: no OS, network, or filesystem action occurs.
      executed_tools=response.tool_calls,
      reasons=("model-output-trusted-without-application-policy",),
      latency_ms=elapsed,
    )


class ProtectedPipeline:
  """Defense-in-depth pipeline that treats the model as untrusted."""

  def __init__(
    self,
    model: Model,
    *,
    input_guard: InputGuard | None = None,
    capability_policy: CapabilityPolicy | None = None,
    evidence_policy: EvidencePolicy | None = None,
  ) -> None:
    self.model = model
    self.input_guard = input_guard or InputGuard()
    self.capability_policy = capability_policy or CapabilityPolicy()
    self.evidence_policy = evidence_policy or EvidencePolicy()

  def run(self, case: AttackCase) -> RunResult:
    input_decision = self.input_guard.check(case.user_prompt, case.untrusted_content)

    if not input_decision.allowed:
      return self._blocked(DefenseLayer.INPUT, input_decision.reasons)

    started = time.perf_counter()
    response = self.model.generate(case)
    elapsed = (time.perf_counter() - started) * 1000

    capability_decision = self.capability_policy.check(
      response.tool_calls,
      authorized_tenant=case.authorized_tenant,
    )

    if not capability_decision.allowed:
      return self._blocked(
        DefenseLayer.CAPABILITY,
        capability_decision.reasons,
        response=response,
        latency_ms=elapsed,
      )

    if case.trusted_evidence_ids:
      evidence_decision = self.evidence_policy.check(
        response.evidence_ids,
        trusted_evidence_ids=case.trusted_evidence_ids,
      )

      if not evidence_decision.allowed:
        return self._blocked(
          DefenseLayer.EVIDENCE,
          evidence_decision.reasons,
          response=response,
          latency_ms=elapsed,
        )

    output_decision = OutputGuard(case.protected_values).check(response.text)

    if not output_decision.allowed:
      return self._blocked(
        DefenseLayer.OUTPUT,
        output_decision.reasons,
        response=response,
        latency_ms=elapsed,
      )

    return RunResult(
      mode="protected",
      blocked=False,
      layer=None,
      visible_output=response.text,
      proposed_tools=response.tool_calls,
      executed_tools=response.tool_calls,
      latency_ms=elapsed,
    )

  @staticmethod
  def _blocked(
    layer: DefenseLayer,
    reasons: tuple[str, ...],
    *,
    response: ModelResponse | None = None,
    latency_ms: float | None = None,
  ) -> RunResult:
    return RunResult(
      mode="protected",
      blocked=True,
      layer=layer,
      visible_output=BLOCKED_MESSAGE,
      proposed_tools=response.tool_calls if response else (),
      executed_tools=(),
      reasons=reasons,
      latency_ms=latency_ms,
    )
