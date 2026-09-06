# HAI-MR-05

This repository contains the qualified deterministic HAI MR-05 runtime surface developed from the historical frozen MR-05C-R2 skeleton baseline. The current qualified runtime is not a production or live external-execution system.

Qualified deterministic APIs currently cover discovery, normalization, source acquisition and immutable local capture, frozen MR-03/MR-04 dependency execution, bounded context construction, controller orchestration, evidence persistence, disclosure qualification, cloud-context admission, cloud-request construction, proposal parsing and identity validation, deterministic verifier qualification, Human Gate / Human Decision record construction, and authoritative Final Result binding.

The frozen package remains `hai_mr05` at `src/hai_mr05/` on branch `hai/mr05-deterministic-workflow-integration`. The repository originated from the MR-05C-R2 skeleton and preserves the exact MR-05A/MR-05B contract references and exact MR-03/MR-04 commit pins. Frozen dependencies remain external and are never copied or vendored.

Implemented qualified APIs and legacy compatibility entrypoints are intentionally distinct. Legacy `not_implemented()` entrypoints remain fail-closed for compatibility and do not represent the implementation status of the qualified APIs. `cli.main()` remains intentionally unavailable and fail-closed.

The current qualified runtime grants no live cloud execution, network authority, provider-client authority, model-call authority, model-routing authority, authentication authority, automatic retry authority, automatic fallback authority, Human approval execution authority, Human Decision side-effect authority, autonomous state-transition authority, or OpenClaw production execution authority. PASS_FOR_REVIEW, Human Gate records, Human Decisions, and Final Result records are governed deterministic records and do not independently grant execution or progression authority.

The Git repository and exact committed runtime remain the source of truth. Documentation and metadata describe the qualified runtime surface but do not grant production readiness, external execution, staging, commit, push, or deployment authority.
