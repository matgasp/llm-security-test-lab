"""Deterministic application controls around an untrusted language model."""

from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from collections.abc import Iterable
from urllib.parse import urlparse

from llm_lab.models import GuardDecision, ToolCall


_BASE64 = re.compile(r"(?<![A-Za-z0-9+/])[A-Za-z0-9+/]{24,8192}={0,2}(?![A-Za-z0-9+/])")
_URL = re.compile(r"https?://[^\s<>\]\)\"']+", re.IGNORECASE)
_INJECTION_RULES = (
  (
    "instruction-override",
    re.compile(
      r"\b(ignore|disregard|forget|override)\b.{0,80}"
      r"\b(previous|prior|system|developer|instructions?|rules?|policy)\b",
      re.IGNORECASE | re.DOTALL,
    ),
  ),
  (
    "hidden-context-extraction",
    re.compile(
      r"\b(reveal|print|show|return|expose)\b.{0,80}"
      r"\b(system|developer|hidden|private|secret|instructions?|prompt|context)\b",
      re.IGNORECASE | re.DOTALL,
    ),
  ),
  (
    "role-or-priority-injection",
    re.compile(
      r"\b(system\s+(message|override)|developer\s+message|administrator\s+priority|"
      r"unrestricted\s+mode|jailbreak)\b",
      re.IGNORECASE,
    ),
  ),
  (
    "resource-exhaustion-request",
    re.compile(
      r"\b(generate|produce|return|continue)\b.{0,100}"
      r"\b(\d+\s*(gb|million)|without\s+(a\s+)?limit|forever|until\s+stopped)\b",
      re.IGNORECASE | re.DOTALL,
    ),
  ),
)


def _strip_invisible_characters(text: str) -> str:
  visible: list[str] = []

  for character in text:
    codepoint = ord(character)
    is_variation_selector = 0xFE00 <= codepoint <= 0xFE0F
    is_tag_character = 0xE0000 <= codepoint <= 0xE007F

    if unicodedata.category(character) == "Cf" or is_variation_selector or is_tag_character:
      continue

    visible.append(character)

  return "".join(visible)


def _decode_base64_candidates(text: str) -> list[str]:
  decoded: list[str] = []

  for candidate in _BASE64.findall(text):
    try:
      raw = base64.b64decode(candidate, validate=True)
      value = raw.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError, ValueError):
      continue

    printable = sum(character.isprintable() or character.isspace() for character in value)

    if value and printable / len(value) >= 0.9:
      decoded.append(value)

  return decoded


def canonicalize(text: str, *, max_decode_depth: int = 2) -> str:
  """Expose common text obfuscation before policy checks."""

  normalized = html.unescape(unicodedata.normalize("NFKC", text))
  normalized = _strip_invisible_characters(normalized)

  layers = [normalized]
  frontier = [normalized]

  for _ in range(max_decode_depth):
    next_frontier: list[str] = []

    for value in frontier:
      next_frontier.extend(_decode_base64_candidates(value))

    if not next_frontier:
      break

    layers.extend(next_frontier)
    frontier = next_frontier

  return "\n".join(layers)


class InputGuard:
  """Detect known injection forms at each trust boundary.

  This is a risk-reduction control, not a proof that arbitrary injection is
  impossible. Output and capability controls remain mandatory.
  """

  def __init__(self, max_text_chars: int = 20_000) -> None:
    self.max_text_chars = max_text_chars

  def check(self, user_prompt: str, untrusted_content: str | None = None) -> GuardDecision:
    findings: list[str] = []
    sources = (("user", user_prompt), ("external-content", untrusted_content))

    for source, value in sources:
      if not value:
        continue

      if len(value) > self.max_text_chars:
        findings.append(f"{source}:input-too-large")
        continue

      canonical = canonicalize(value)

      for rule_name, pattern in _INJECTION_RULES:
        if pattern.search(canonical):
          findings.append(f"{source}:{rule_name}")

    return GuardDecision(allowed=not findings, reasons=tuple(dict.fromkeys(findings)))


class OutputGuard:
  """Prevent protected values and active external content from leaving the app."""

  def __init__(
    self,
    protected_values: Iterable[str],
    allowed_hosts: Iterable[str] = (),
    max_output_chars: int = 20_000,
  ) -> None:
    self.protected_values = tuple(value for value in protected_values if value)
    self.allowed_hosts = frozenset(host.casefold() for host in allowed_hosts)
    self.max_output_chars = max_output_chars

  def check(self, text: str) -> GuardDecision:
    findings: list[str] = []
    folded = text.casefold()

    if len(text) > self.max_output_chars:
      findings.append("output-too-large")

    if any(value.casefold() in folded for value in self.protected_values):
      findings.append("protected-value-disclosure")

    for url in _URL.findall(text):
      host = (urlparse(url).hostname or "").casefold()
      if host not in self.allowed_hosts:
        findings.append("non-allowlisted-external-url")
        break

    if re.search(r"<\s*script\b|\bon\w+\s*=", text, re.IGNORECASE):
      findings.append("active-html-content")

    return GuardDecision(allowed=not findings, reasons=tuple(dict.fromkeys(findings)))


class CapabilityPolicy:
  """A deny-by-default policy engine for model-proposed tool calls."""

  def __init__(
    self,
    allowed_read_only_tools: Iterable[str] = (
      "search_public_docs",
      "retrieve_tenant_records",
    ),
  ) -> None:
    self.allowed_read_only_tools = frozenset(allowed_read_only_tools)

  def check(
    self,
    calls: Iterable[ToolCall],
    *,
    authorized_tenant: str | None = None,
  ) -> GuardDecision:
    findings: list[str] = []

    for call in calls:
      if call.name not in self.allowed_read_only_tools:
        findings.append(f"tool-not-authorized:{call.name}")
        continue

      if call.name == "search_public_docs" and not self._valid_public_search(call):
        findings.append("invalid-tool-arguments:search_public_docs")

      if call.name == "retrieve_tenant_records" and not self._valid_tenant_retrieval(
        call, authorized_tenant
      ):
        findings.append("tenant-access-denied:retrieve_tenant_records")

    return GuardDecision(allowed=not findings, reasons=tuple(findings))

  @staticmethod
  def _valid_public_search(call: ToolCall) -> bool:
    if set(call.arguments) != {"query"}:
      return False

    query = call.arguments.get("query")

    return (
      isinstance(query, str)
      and 0 < len(query) <= 200
      and not _URL.search(query)
      and not any(character in query for character in "\r\n")
    )

  @staticmethod
  def _valid_tenant_retrieval(call: ToolCall, authorized_tenant: str | None) -> bool:
    return (
      authorized_tenant is not None
      and set(call.arguments) == {"tenant_id"}
      and call.arguments.get("tenant_id") == authorized_tenant
    )


class EvidencePolicy:
  """Require a model claim to reference evidence trusted by the application."""

  def check(
    self,
    evidence_ids: Iterable[str],
    *,
    trusted_evidence_ids: Iterable[str],
  ) -> GuardDecision:
    supplied = set(evidence_ids)
    trusted = set(trusted_evidence_ids)

    if not supplied:
      return GuardDecision(False, ("missing-evidence",))

    if not supplied.issubset(trusted):
      return GuardDecision(False, ("untrusted-evidence",))

    return GuardDecision(True)
