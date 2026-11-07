# soul-contracts

Machine-readable contracts for the Soul Agent Platform: JSON Schemas, canonicalization vectors, fixtures and the error registry. No runtime code.

<!-- platform:agent-bot-platform:start -->
Platform: true-line/agent-bot-platform at baseline/3 (commit f1008c8cd5e4e1b27125380731f4422b1f392392).
This repository's charter, seams and requirements are in the platform's
registry/repos.yaml entry for soul-contracts. Read the platform's AGENTS.md
before changing a seam or anything a requirement covers.
<!-- platform:agent-bot-platform:end -->

## Before you change anything

- Run `python scripts/validate.py`. CI runs the same script.
- Requirement wording, test specifications, the glossary and the source papers live in the platform, not here. Link to them at the pinned commit; never copy them back.
- `platform.lock.json` records the pinned platform commit and the requirement and test IDs that exist there. Schemas, fixtures and the error registry may cite only those IDs. To move the pin, run `python scripts/platform_lock.py <platform checkout> --commit <sha> --write` and update the platform block above in the same PR.
- No implementer edits a schema to make its own implementation pass. A decision that binds another repository is raised in the platform's [Decisions](https://github.com/true-line/agent-bot-platform/discussions/categories/decisions) category.
