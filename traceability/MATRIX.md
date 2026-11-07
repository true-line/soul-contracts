# Requirement traceability

Source: draft 0.4, Appendix D (unchanged from 0.3). Maintained by WP1; every new test or schema updates this file in the same change. Test definitions: TESTS.md. `scripts/validate.py` checks coverage.

| Req                                          | Specified in                 | Verified by                                                      | First gate        |
|----------------------------------------------|------------------------------|------------------------------------------------------------------|-------------------|
| R1 Stable identity                           | 3, 5, 11                     | T15, T16                                                         | 3                 |
| R2 Control stays local                       | 3, 4 (administration), 5, 6  | T12, T24                                                         | 3 (T24), 4 (T12)  |
| R3 Authority outside the model               | 4, 7, Appendix A             | T01, T02, T03, T20                                               | 1 (T20), 2a       |
| R4 Owner assigns roles; evaluations advise   | 9, 10                        | T22                                                              | 3                 |
| R5 One ceiling, sub-allocations              | 8, 15                        | T11, T26                                                         | 2b                |
| R6 External material is data                 | 4, 6 (wake), 10              | T04, T10, T19                                                    | 1 (T04), 2b       |
| R7 Contracts first; N and N-1                | 6, 12, Appendix A            | T14                                                              | 0                 |
| R8 Honest profiles                           | 4, 7 (receipts), 8           | T21                                                              | 2a                |
| R9 Uplinks optional                          | 6, 9                         | T13, T25                                                         | 2b (T25), 4 (T13) |
| R10 Vendor-neutral contracts                 | 12, 13 (pilot configuration) | Schema review in WP1; no vendor token in any fixture             | 0                 |
| R11 One harness to the user                  | 3, 8                         | Pilot rubric: tasks completed through terminal chat and ACP only | 3                 |
| R12 Vendored and pinned, declared exceptions | 11                           | T16; clean-host activation reports missing toolchains            | 3                 |

## Compatibility baseline (Appendix E)

The WP1 compatibility inventory that draft 0.4 Appendix E asks for is the module inventory and dependency map in `true-line/agent-bot-daemon` `docs/daemon-plugin-split.md`: Appendix A, plus §2.3 (duplicated wire code) and §2.4 (cycles), at commit `6480b35`. It is referenced here, not copied, and is re-pinned when that inventory changes.
