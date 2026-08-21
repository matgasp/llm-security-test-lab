# Contributing

Changes must preserve the paired experiment: the same attack case must be evaluated against both the intentionally vulnerable pipeline and the protected pipeline.

Every new attack case must contain:

- a unique identifier and delivery vector;
- a synthetic, case-specific attack-success signal;
- the compromised model output or proposed tool call;
- the deterministic defense layer expected to contain it;
- no real secret, personal data, live target, or destructive implementation.

Run before opening a pull request:

```powershell
python -m llm_lab demo
python -m pytest
python -m compileall -q src tests
```

Do not weaken an oracle merely to make a failing defense appear successful. A changed security expectation must be explained in the pull request.
