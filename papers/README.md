# Papers

The source papers moved to the platform, which keeps them frozen and cites them by ID. Its `registry/sources.yaml` pins each one by SHA-256.

| Paper | Platform ID | At baseline/3 |
| --- | --- | --- |
| Soul Agent Platform whitepaper, draft 0.4, the source of record for these contracts | S6 | [soul-platform-draft-0.4.md](https://github.com/true-line/agent-bot-platform/blob/f1008c8cd5e4e1b27125380731f4422b1f392392/docs/papers/soul-platform-draft-0.4.md) |
| Soul Agent Platform whitepaper, draft 0.3 | S6, superseded version | [soul-platform-draft-0.3.md](https://github.com/true-line/agent-bot-platform/blob/f1008c8cd5e4e1b27125380731f4422b1f392392/docs/archive/soul-platform-draft-0.3.md) |
| Soul Agent Platform repository implementation plan | S7 | [repository-plan-2026-10-24.md](https://github.com/true-line/agent-bot-platform/blob/f1008c8cd5e4e1b27125380731f4422b1f392392/docs/papers/repository-plan-2026-10-24.md) |
| Soul Agent Platform operator questions | S8 | [operator-questions-2026-10-29.md](https://github.com/true-line/agent-bot-platform/blob/f1008c8cd5e4e1b27125380731f4422b1f392392/docs/papers/operator-questions-2026-10-29.md) |

`errors/registry.json` still names draft 0.4 by its SHA-256, and `scripts/validate.py` checks that value against the S6 pin in `platform.lock.json`.
