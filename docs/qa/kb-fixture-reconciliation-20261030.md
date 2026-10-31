# Synthetic KB fixture reconciliation — 2026-10-30 Pacific

Source: PR #136 at `2fcd627e52a6d784d5c2e5b4ea8105e90b8589b3`, preserving
PR #69's 24 unique paths. The author branches remain unchanged. No production
parser is modified by this repair.

The original selection produced **12 passed and 17 fixture-setup errors**.
Registering the existing socket-denial fixture exposed **two failures**: an
unknown-type scenario looked up in the wrong corpus, and a nonempty assertion
contradicting the intentionally empty SYN-CSAF-005 case. Both are corrected.
A new guard assertion also failed on the purported Unicode attack because its
inner JSON contained literal backslashes, not a Cyrillic character. A separate small
raw fixture now decodes to U+0417; the original corpus remains byte-identical. BOM and CRLF cases now cross
the actual importer boundary: reject BOM, accept CRLF.

Verification: the repaired fixture selection plus existing `test_kbc*.py`
regressions passed **934 tests in 19.95 s**. Full repository Ruff and patch hygiene
passed. Independent review approved the bounded repair. These are synthetic
and local regression results, not native or live-provider acceptance. Final
combined-source Linux/Windows full suites remain required before integration.

Scenario labels are not themselves boundary tests; not all named oversized,
deep, or VEX multiple-item cases contain such structures. CSAF/VEX structural
checks do not validate provider compatibility. Package/relationship checks
inspect metadata; injection protocol tests do not prove application recovery.
The existing authored placeholder CVRF dialect remains separate from the live
MSRC adapter. No target, package payload, or model-directed command is executed.
