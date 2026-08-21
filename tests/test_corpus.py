from llm_lab.corpus import OWASP_IDS, VECTORS, load_cases


def test_corpus_is_unique_and_covers_supported_vectors() -> None:
  cases = load_cases()

  assert len({case.id for case in cases}) == len(cases)
  assert {case.vector for case in cases} == VECTORS


def test_every_attack_has_a_specific_success_oracle_and_control() -> None:
  attacks = [case for case in load_cases() if case.is_attack]

  assert len(attacks) == 13
  assert all(
    case.success_signals or case.dangerous_tools or case.success_min_output_chars
    for case in attacks
  )
  assert all(case.expected_defense is not None for case in attacks)


def test_corpus_covers_every_owasp_llm_top_10_2026_category() -> None:
  covered = {case.owasp_id for case in load_cases() if case.is_attack}

  assert covered == OWASP_IDS


def test_corpus_contains_only_synthetic_protected_values() -> None:
  values = [value for case in load_cases() for value in case.protected_values]

  assert values
  assert all(value.startswith("LAB-CANARY-") for value in values)


def test_corpus_has_a_meaningful_benign_utility_set() -> None:
  benign = [case for case in load_cases() if not case.is_attack]

  assert len(benign) >= 20
