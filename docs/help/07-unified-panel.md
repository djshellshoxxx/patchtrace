# Unified comparison

Unified is an **experimental** derived view. Open it through View or Ctrl+Shift+U. It presents pairing decisions and change classes alongside source observations. It does not replace the original Ghidriff output or silently correct its relationships.

A decision describes correspondence: matched, tentative, candidate, contested, ambiguous, older-only, newer-only, or unknown. The change class separately describes unchanged, cosmetic, material, review, unknown, or not-applicable. A material change is a reason to inspect code; it does not establish the purpose of a patch.

Use the Decision, Change, Class, and Source filters, then search by name or address. Check Show hidden before concluding that no rows exist. Read the selected row's details and Copy provenance. Named proofs behind unchanged or cosmetic classifications must be read in their stated scope, especially when they depend on decompiled text.

The source includes paired-code controls for available stored decompiled text or disassembly. A missing code channel remains unavailable. Explain opens an interpretation path that still requires reviewing the request preview.

The GUI run action is gated by unified/enabled, which defaults off. The existing guide identifies no confirmed Setup control for enabling it; do not assume one exists.

Source: [evidence guide](../guide/12-evidence-and-engines.md) and src/patchtrace/ui_unified.py. **UNVERIFIED:** GUI enablement procedure, extraction/decompilation integration, release gates, and native Windows operation were not validated here.
