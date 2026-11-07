# Requirements

Product requirements moved to the platform: [product requirements](https://github.com/true-line/agent-bot-platform/blob/main/docs/02-requirements/product-requirements.md), generated from its `registry/requirements.yaml`.

`scripts/validate.py` reads the platform's `main` on every run and fails on a contract artifact that cites a requirement ID not defined there.
