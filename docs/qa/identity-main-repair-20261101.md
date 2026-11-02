# Independent main identity repair — November 1, 2026

Base main `6579ed83211b7ff2039e3152728ac1cddc3e93d6`; product port `65857d4aad2a67d1d2a8ede3a4856ba0caba4fcd`, followed by test-contract repair `5406708` (same patch as independently reviewed `c971831`). This contains no #144 matching-policy or KB parent dependency. Original defects reproduced on main: 28 failed, 3 passed.

Manual one-to-one ambiguity stays ambiguous. Complete immutable source evidence, validated alternative identities and cancellation-safe normalized content hashing bind both in-process and child results; original raw evidence identity remains separate. NFC/NFD stored IDs cannot collide before canonical hashing. Independent code reviews and the main-port source/child import provenance are in `identity-main-port-verification-20261101.json` and `identity-main-child-import-provenance-20261101.json`. The original review/source failures remain preserved.

Coordinator source review and 128 focused checks passed in3.19s before the old refused-source literal expectation was discovered in the broader combined full suite. The test-only follow-up independently computes the amended SPEC31 identity and checks exact original raw hash/version, preserving all earlier refusal/determinism/result-ID assertions. Independent wrong-ID and lost-raw-hash controls both fail. Final main-port coordinator check:125 passed in2.66s, including complete worker module and real child controls. Counts overlap and are not summed. Full source/command details are in the receipts.

Full Linux/Windows/Qt/native/quality/package checks are required on the published head before merge. This slice does not establish whole issue#120 or combined feature acceptance.
