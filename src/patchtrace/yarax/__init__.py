"""YARA-X rule authoring from reviewed function pairs (contract `yara-rules/1`; plan YRX-integration-plan.md).

Rules are derived evidence: a match means a file contains a pattern, never that it is affected or fixed. Only
`engine`, `worker` and `adapters/mask_iced` may import `yara_x` or `iced_x86`; everything else here is pure.
"""
