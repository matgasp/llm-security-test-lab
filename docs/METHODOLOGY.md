# Methodology

## Question under test

The laboratory asks a narrow, verifiable question: **if an LLM or its surrounding data flow produces the harmful result represented by an OWASP GenAI LLM Top 10 case, do deterministic application controls prevent that result from reaching a user, downstream sink, or privileged capability?**

This is stricter than treating a model's spontaneous refusal as a defense. The demonstration model always produces the attacker's desired output.

## Paired experiment

Every corpus case traverses both paths with exactly the same input and model response. Live generations are cached and replayed so model variability cannot change one side of the pair:

```text
baseline:  input -> compromised model -> trusted output/tool -> observable harm
protected: input -> input/resource control -> compromised model
                    -> capability/evidence policy -> output control -> response
```

A test passes only when:

1. the case-specific oracle finds the harmful outcome in the baseline;
2. the same oracle does not find harm in the protected path;
3. the blocking layer matches the hypothesis recorded in the corpus;
4. all ten OWASP category identifiers are present;
5. all twenty benign utility controls remain available.

A baseline tool call is only an in-memory authorization simulation. The laboratory contains no implementation that deletes files, installs packages, runs shell commands, or sends data over the network.

The deterministic proof reports the number and percentage of benign controls blocked by the protected path. This is a corpus-specific false-positive rate, not an estimate for arbitrary production traffic.

## OWASP 2026 coverage

The corpus covers LLM01 Prompt Injection, LLM02 Sensitive Information Disclosure, LLM03 Excessive Agency, LLM04 Supply Chain, LLM05 Data and Model Poisoning, LLM06 Unbounded Consumption, LLM07 Misinformation, LLM08 Hidden Context Exposure, LLM09 Vector and Embedding Weaknesses, and LLM10 Improper Output Handling.

Coverage means at least one representative, version-controlled regression scenario for every category. It does not mean every possible technique within each broad category has been exhausted.

## Controls

### Input and resource boundary

Text is size-limited before Unicode NFKC normalization, invisible-character removal, and bounded decoding of Base64 candidates. High-confidence rules are applied separately to the user request and external content, preserving each finding's source. Explicitly excessive generation requests are rejected before model execution, while live generation also has a server-side token budget.

Input filtering reduces known attacks but can be bypassed by rephrasing. It is not the primary security boundary.

### Output boundary

The application rejects the complete response when it finds a protected canary, active HTML, excessive size, or an external URL outside the allowlist. Rejected content is never copied into the blocking message.

In production, protected values should come from a vault or data-classification system, and validation must match the destination context: HTML, SQL, shell, Markdown, URL, or another sink.

### Capabilities and authorization

Model-proposed calls pass through a deny-by-default policy. Only explicitly read-only tools are eligible, and their argument names, types, sizes, and destinations are validated. Tenant-scoped retrieval requires an application-authenticated tenant identifier; a vector similarity score cannot grant access. A rejected call appears in `proposed_tools` but never in `executed_tools`.

This is the highest-impact control: even when input detection and model behavior fail, model text does not become authorization.

### Evidence

Claims configured as evidence-sensitive must cite an identifier present in an application-owned trusted set. Missing or unknown evidence blocks publication. A production verifier must also validate that the cited source actually supports the specific claim; this lab models source authorization, not full natural-language entailment.

## Attack-success oracle

The project does not use generic refusal words to infer safety. Every case declares concrete evidence:

- a synthetic value or known false claim became visible;
- output exceeded the defined bound;
- active attacker-controlled content reached a sink;
- a dangerous capability was authorized.

This avoids the common false positive where a refusal repeats part of an attack.

## Deterministic proof and live benchmark

`python -m llm_lab demo` is the reproducible application-control proof. It does not depend on a network, model weights, or sampling.

`python -m llm_lab live` is a complementary Ollama benchmark. It measures one model/runtime/version combination and can vary. A baseline refusal is useful model evidence, but it does not replace architectural controls.

## Limitations

The laboratory proves only the cases in its versioned corpus. It does not establish universal absence of OWASP vulnerabilities or universal input-filter accuracy and does not cover multimodal payloads, real persistent memory, a real vector database, training pipelines, or external tools. New encodings and semantic attacks can cross the input filter; output, evidence, authorization, and capability controls exist precisely to limit damage in that scenario.
