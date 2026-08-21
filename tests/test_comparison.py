from llm_lab.corpus import load_cases
from llm_lab.demo_model import CompromisedModel
from llm_lab.evaluator import attack_succeeded, compare_case
from llm_lab.models import AttackCase, ModelResponse
from llm_lab.pipeline import ProtectedPipeline


def test_every_attack_fails_in_baseline_and_is_contained_when_protected() -> None:
  comparisons = [compare_case(case, CompromisedModel()) for case in load_cases() if case.is_attack]

  assert all(result.baseline_attack_succeeded for result in comparisons)
  assert all(not result.protected_attack_succeeded for result in comparisons)
  assert all(result.protected.layer == result.case.expected_defense for result in comparisons)


def test_protected_output_never_exposes_a_success_signal() -> None:
  comparisons = [compare_case(case, CompromisedModel()) for case in load_cases()]
  for comparison in comparisons:
    assert not attack_succeeded(comparison.case, comparison.protected)
    assert all(
      value.casefold() not in comparison.protected.visible_output.casefold()
      for value in comparison.case.protected_values
    )


def test_denied_tool_is_proposed_but_never_executed() -> None:
  case = next(case for case in load_cases() if case.id == "LLM03-AGENCY-001")
  result = ProtectedPipeline(CompromisedModel()).run(case)

  assert [call.name for call in result.proposed_tools] == ["delete_file"]
  assert result.executed_tools == ()


def test_benign_case_is_not_blocked() -> None:
  case = next(case for case in load_cases() if not case.is_attack)
  comparison = compare_case(case, CompromisedModel())

  assert not comparison.baseline_attack_succeeded
  assert not comparison.protected_attack_succeeded
  assert not comparison.protected.blocked
  assert comparison.baseline.visible_output == comparison.protected.visible_output


def test_input_block_happens_before_model_execution() -> None:
  class MustNotRun:
    def generate(self, case: AttackCase) -> ModelResponse:
      raise AssertionError(f"model ran for blocked case {case.id}")

  case = next(case for case in load_cases() if case.id == "LLM01-DIRECT-001")
  result = ProtectedPipeline(MustNotRun()).run(case)

  assert result.blocked
  assert result.latency_ms is None


def test_paired_comparison_generates_only_once() -> None:
  class CountingModel:
    calls = 0

    def generate(self, case: AttackCase) -> ModelResponse:
      self.calls += 1
      return ModelResponse(
        case.compromised_output,
        case.compromised_tool_calls,
        case.compromised_evidence_ids,
      )

  case = next(case for case in load_cases() if case.id == "LLM02-DISCLOSURE-001")
  model = CountingModel()
  comparison = compare_case(case, model)

  assert model.calls == 1
  assert comparison.baseline.visible_output != comparison.protected.visible_output


def test_cross_tenant_vector_access_is_denied() -> None:
  case = next(case for case in load_cases() if case.id == "LLM09-VECTOR-ACCESS-001")
  comparison = compare_case(case, CompromisedModel())

  assert comparison.baseline_attack_succeeded
  assert comparison.protected.reasons == (
    "tenant-access-denied:retrieve_tenant_records",
  )


def test_unsupported_claim_is_blocked_without_trusted_evidence() -> None:
  case = next(case for case in load_cases() if case.id == "LLM07-MISINFORMATION-001")
  comparison = compare_case(case, CompromisedModel())

  assert comparison.baseline_attack_succeeded
  assert comparison.protected.reasons == ("missing-evidence",)
