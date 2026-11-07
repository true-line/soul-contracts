# soul-contracts

Machine-readable contracts for the Soul Agent Platform: JSON Schemas, canonicalization vectors, fixtures and the error registry. No runtime code.

<!-- platform:agent-bot-platform:start -->
Platform: true-line/agent-bot-platform, read at main.
This repository's charter, seams and requirements are in the platform's
registry/repos.yaml entry for soul-contracts. Read the platform's AGENTS.md
at the start of every task, and before changing a seam or anything a
requirement covers.
<!-- platform:agent-bot-platform:end -->

## Before you change anything

- Run `python scripts/validate.py`. CI runs the same script.
- Requirement wording, test specifications, the glossary and the source papers live in the platform, not here. Link to them on the platform's `main`; never copy them back.
- `scripts/validate.py` fetches the platform's `main` on every run and fails if it cannot reach it. Schemas, fixtures and the error registry may cite only requirement and test IDs defined there, and every link into the platform must use `main` and resolve. It logs the platform commit SHA it checked. Never pin a platform commit or keep a copy of its registry here (platform PDR-0020).
- A CI failure caused by a platform change on `main` is a real signal, not a flaky runner. Fix it; never bypass-merge it.
- Reading the platform at `main` surfaces Proposed pages and PDRs. They guide work; only Accepted ones bind it.
- No implementer edits a schema to make its own implementation pass. A decision that binds another repository is raised in the platform's [Decisions](https://github.com/true-line/agent-bot-platform/discussions/categories/decisions) category.
