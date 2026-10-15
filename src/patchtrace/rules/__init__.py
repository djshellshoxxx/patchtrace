"""YARA-X rule workflow (contract `yara-rules/1`; plan: docs/specs/program-e/YRX-integration-plan.md).

R0 contract freeze: `limits` (the numbers of plan s7 as one frozen dataclass whose digest enters every cache key),
`errors` (`PT-RULE-*` codes and `RuleError`), `contracts` (strict frozen records) and `ports` (Protocols and the plain data
that crosses them). R2 adds `engine` (the YARA-X facade), `worker` (the hidden capped child) and `runner` (the parent
side). Only `engine` and `worker` may import `yara_x`/`iced_x86`: the parent process, the GUI and the CLI never load the
extension. Rule text is untrusted data: it is bounded, escaped and compiled with the linters, never executed.
Persisted contracts are additive only from here on.
"""
