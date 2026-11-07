# Conformance tests

What each conformance test must prove moved to the platform: [conformance catalog](https://github.com/true-line/agent-bot-platform/blob/main/docs/07-verification/conformance-catalog.md). soul-conformance owns the executable suites.

`scripts/validate.py` reads the platform's `main` on every run and fails on a contract artifact that cites a test ID not defined there.
