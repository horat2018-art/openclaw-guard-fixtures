# HAI Deterministic Evidence Packager

Standalone, read-only deterministic inventory, validation, selection, packaging,
and approximate token-budget tooling. It does not call models, use the network,
modify source evidence, or integrate with OpenClaw.

Run locally with `PYTHONPATH=src python3 -m hai_evidence --help` and tests with
`python3 -m unittest discover -s tests -v`.

Canonical package content is stable JSON. Timestamps are run metadata only.
The token count is an approximate `ceil(non-whitespace groups / 4)` estimate,
not a model tokenizer count. Protected or secret-like content is blocked.
