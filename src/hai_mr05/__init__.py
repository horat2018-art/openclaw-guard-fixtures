"""HAI MR-05 qualified deterministic runtime package.

Qualified deterministic runtime surfaces are implemented through HAI-OPS-01-R2.
The canonical multi-agent governance surface models OpenClaw, Hermes, and Codex as sibling lanes mediated by Inwjud, with deterministic memory-priority, coordination, conflict, and tamper-evident run-ledger contracts. HAI-OPS-01 additionally qualifies deterministic operational-result records for the external Inwjud execute/collect/ledger controller: bounded local Hermes execution may be observed, Codex remains fail-closed at the live-policy boundary, and OpenClaw remains intentionally unbound until HAI-OPS-02. These contracts grant no peer-to-peer agent authority or external execution authority. Live and production external execution remain unavailable. The explicit offline CLI supports approved-root single-file local preparation, local prepare-input materialization, one-shot composition, and a zero-send prepare/resume boundary using stdin JSON and an already-obtained response; all other CLI use remains fail-closed.
"""

__version__ = '0.0.0'
