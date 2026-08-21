"""Command-line interface for deterministic proof and optional live benchmark."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

from llm_lab.corpus import load_cases
from llm_lab.demo_model import CompromisedModel
from llm_lab.evaluator import compare_case
from llm_lab.models import Comparison
from llm_lab.ollama import OllamaError, OllamaModel


def _as_dict(comparison: Comparison) -> dict[str, Any]:
  def result_data(result: Any, attack_succeeded: bool) -> dict[str, Any]:
    return {
      "attack_succeeded": attack_succeeded,
      "blocked": result.blocked,
      "layer": result.layer.value if result.layer else None,
      "reasons": list(result.reasons),
      "visible_output": result.visible_output,
      "proposed_tools": [call.name for call in result.proposed_tools],
      "executed_tools": [call.name for call in result.executed_tools],
      "latency_ms": round(result.latency_ms, 2) if result.latency_ms is not None else None,
    }

  return {
    "id": comparison.case.id,
    "title": comparison.case.title,
    "owasp_id": comparison.case.owasp_id,
    "vector": comparison.case.vector,
    "is_attack": comparison.case.is_attack,
    "expected_defense": (
      comparison.case.expected_defense.value if comparison.case.expected_defense else None
    ),
    "baseline": result_data(comparison.baseline, comparison.baseline_attack_succeeded),
    "protected": result_data(comparison.protected, comparison.protected_attack_succeeded),
  }


def _print_table(comparisons: list[Comparison]) -> None:
  case_width = max(len("CASE"), *(len(item.case.id) for item in comparisons))

  print(
    f"{'CASE':<{case_width}}  {'VECTOR':<18} {'BASELINE':<12} "
    f"{'PROTECTED':<12} CONTROL"
  )

  for comparison in comparisons:
    baseline = "EXPLOITED" if comparison.baseline_attack_succeeded else "CONTAINED"
    protected = "EXPLOITED" if comparison.protected_attack_succeeded else "CONTAINED"
    control = comparison.protected.layer.value if comparison.protected.layer else "none"

    print(
      f"{comparison.case.id:<{case_width}}  {comparison.case.vector:<18} "
      f"{baseline:<12} {protected:<12} {control}"
    )


def _write_report(path: str | None, comparisons: list[Comparison]) -> None:
  if not path:
    return

  destination = Path(path)
  destination.parent.mkdir(parents=True, exist_ok=True)

  destination.write_text(
    json.dumps([_as_dict(item) for item in comparisons], indent=2, ensure_ascii=False),
    encoding="utf-8",
  )

  print(f"Report: {destination}")


def run_demo(report: str | None) -> int:
  comparisons = [compare_case(case, CompromisedModel()) for case in load_cases()]

  _print_table(comparisons)
  _write_report(report, comparisons)

  attacks = [item for item in comparisons if item.case.is_attack]
  valid = all(
    item.baseline_attack_succeeded
    and not item.protected_attack_succeeded
    and item.protected.layer == item.case.expected_defense
    for item in attacks
  )
  benign = [item for item in comparisons if not item.case.is_attack]
  false_positives = sum(item.protected.blocked for item in benign)
  valid = valid and false_positives == 0

  print(
    f"\nProof: baseline exploited {sum(item.baseline_attack_succeeded for item in attacks)}/"
    f"{len(attacks)}; protected exploited "
    f"{sum(item.protected_attack_succeeded for item in attacks)}/{len(attacks)}."
  )
  print(
    f"Utility: benign controls blocked {false_positives}/{len(benign)}; "
    f"false-positive rate {(false_positives / len(benign)) * 100:.2f}%."
  )

  return 0 if valid else 1


def run_live(report: str | None, strict: bool) -> int:
  model = OllamaModel()

  if not model.healthcheck():
    print(f"Ollama is unavailable at {model.settings.ollama_url}")
    return 2

  cases = load_cases()
  comparisons: list[Comparison] = []

  for index, case in enumerate(cases, start=1):
    print(f"[{index}/{len(cases)}] Running {case.id}...", flush=True)

    try:
      comparisons.append(compare_case(case, model))
    except OllamaError as exc:
      print(f"{case.id}: {exc}")
      return 2

  _print_table(comparisons)
  _write_report(report, comparisons)

  protected_failures = [
    item for item in comparisons if item.case.is_attack and item.protected_attack_succeeded
  ]
  benign_failures = [
    item for item in comparisons if not item.case.is_attack and item.protected.blocked
  ]

  return 1 if strict and (protected_failures or benign_failures) else 0


def build_parser() -> argparse.ArgumentParser:
  parser = argparse.ArgumentParser(description="Reproducible OWASP LLM security laboratory")
  subparsers = parser.add_subparsers(dest="command")

  demo = subparsers.add_parser("demo", help="run deterministic vulnerable-vs-protected proof")
  demo.add_argument("--report", help="optional JSON report path")

  live = subparsers.add_parser("live", help="run the same corpus against local Ollama")
  live.add_argument("--report", help="optional JSON report path")
  live.add_argument(
    "--strict",
    action="store_true",
    help="fail if an attack succeeds or a benign control is blocked",
  )

  return parser


def main() -> int:
  args = build_parser().parse_args()

  if args.command in (None, "demo"):
    return run_demo(getattr(args, "report", None))

  return run_live(args.report, args.strict)
