from types import SimpleNamespace

import llm_lab.cli as cli
from llm_lab.corpus import load_cases
from llm_lab.demo_model import CompromisedModel
from llm_lab.evaluator import compare_case
from llm_lab.models import ModelResponse


def test_demo_command_proves_failure_then_containment(capsys) -> None:
  assert cli.run_demo(None) == 0
  output = capsys.readouterr().out

  assert "baseline exploited 13/13" in output
  assert "protected exploited 0/13" in output
  assert "benign controls blocked 0/20" in output
  assert "false-positive rate 0.00%" in output


def test_comparison_serialization_contains_evidence() -> None:
  case = next(case for case in load_cases() if case.id == "LLM02-DISCLOSURE-001")
  data = cli._as_dict(compare_case(case, CompromisedModel()))

  assert data["baseline"]["attack_succeeded"] is True
  assert data["protected"]["attack_succeeded"] is False
  assert data["protected"]["layer"] == "output"
  assert data["owasp_id"] == "LLM02"


def test_live_command_applies_controls_to_one_replayed_generation(monkeypatch, capsys) -> None:
  model = CompromisedModel()
  model.settings = SimpleNamespace(ollama_url="http://local.test/api/chat")
  model.healthcheck = lambda: True
  monkeypatch.setattr(cli, "OllamaModel", lambda: model)

  assert cli.run_live(None, strict=True) == 0
  assert "Running LLM01-DIRECT-001" in capsys.readouterr().out


def test_live_command_reports_unavailable_service(monkeypatch, capsys) -> None:
  model = CompromisedModel()
  model.settings = SimpleNamespace(ollama_url="http://local.test/api/chat")
  model.healthcheck = lambda: False
  monkeypatch.setattr(cli, "OllamaModel", lambda: model)

  assert cli.run_live(None, strict=False) == 2
  assert "Ollama is unavailable" in capsys.readouterr().out


def test_live_strict_mode_fails_on_benign_false_positive(monkeypatch) -> None:
  class UnsafeForBenignModel(CompromisedModel):
    settings = SimpleNamespace(ollama_url="http://local.test/api/chat")
    healthcheck = lambda self: True

    def generate(self, case):
      if not case.is_attack:
        return ModelResponse('<script>blockedBenignOutput()</script>')

      return super().generate(case)

  monkeypatch.setattr(cli, "OllamaModel", UnsafeForBenignModel)

  assert cli.run_live(None, strict=True) == 1


def test_parser_defaults_to_deterministic_demo(monkeypatch) -> None:
  monkeypatch.setattr("sys.argv", ["llm-lab"])
  monkeypatch.setattr(cli, "run_demo", lambda report: 7)

  assert cli.main() == 7
