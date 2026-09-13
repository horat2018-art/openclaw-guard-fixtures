"""HAI MR-05 qualified deterministic runtime package.

Qualified deterministic runtime surfaces are implemented through HAI-OPS-02-R2.
The canonical multi-agent governance surface models OpenClaw, Hermes, and Codex as sibling lanes mediated by Inwjud, with deterministic memory-priority, coordination, conflict, and tamper-evident run-ledger contracts. HAI-OPS-01 qualifies deterministic operational-result records for the external Inwjud execute/collect/ledger controller. HAI-OPS-02 extends that observational contract to bounded local OpenClaw operator results: an external Inwjud adapter may invoke an already-qualified local-only OpenClaw agent, while MR05 itself performs no OpenClaw invocation and grants no model, network, peer-agent, Git, memory-promotion, Human-approval, or state-transition authority. Hermes remains a bounded local worker and Codex remains fail-closed at the live-policy boundary. Historical unbound OpenClaw records remain requalifiable. Live and production external execution remain unavailable. The explicit offline CLI supports approved-root single-file local preparation, local prepare-input materialization, one-shot composition, and a zero-send prepare/resume boundary using stdin JSON and an already-obtained response; all other CLI use remains fail-closed.
"""

__version__ = '0.0.0'
