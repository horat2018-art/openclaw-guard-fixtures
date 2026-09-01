# HAI-MR-05

This repository is the MR-05C-R2 skeleton only. It contains no controller, discovery, normalization, MR-03/MR-04 execution, cloud, verifier, or Human approval implementation.

Frozen package: `hai_mr05` at `src/hai_mr05/`. Frozen branch: `hai/mr05-deterministic-workflow-integration`. The empty baseline subject is `chore: initialize mr05 empty baseline`.

The skeleton records exact MR-05A/MR-05B contract references and exact MR-03/MR-04 commit pins. Frozen dependencies remain external and are never copied or vendored.

All callable boundaries fail closed with a phase-not-implemented error. Network, provider, model, authentication, OpenClaw production, Obsidian, staging, push, and post-baseline commit behavior are not authorized.
