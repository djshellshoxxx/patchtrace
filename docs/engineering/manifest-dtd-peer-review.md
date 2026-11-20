# Independent manifest DTD and cache review — 2026-11-19

Reviewed root implementation commit `0ac15cbc` against `f2458aae`.
Reviewer implemented the separate WinPairs boundary repair, not these changes.
The inspected runtime files matched the reviewed commit when the controls ran:

- `manifest.py` SHA-256:
  `b1e83c0dbb9fb04fa9b2439433b4a2192364e684a1f9db1073b6f47b97f13aa9`
- `cache.py` SHA-256:
  `fb4636ec4635986c6cb255d24d01b6d14334acd3dabed09196f917dddb02cd25`

## Conclusion

No blocking defect found in this bounded review. The parser-level DTD refusal
complements the conservative decoded-text screen. The cache version change
invalidates previously reusable entity-expanded metadata without deleting its
historical records. The public metadata shape, verified-byte inspection and
native trust boundaries remain unchanged.

## Independent controls

Four additional peer controls passed in 0.91 seconds:

1. The C ElementTree path processes 63 authored variants: empty/internal/SYSTEM/
   PUBLIC/parameter DTD declarations across four whitespace prefixes and three
   encodings, plus three normal encoding controls. Every DTD-bearing input
   exposes no facts and preserves the stored-byte digest; unsupported malformed
   UTF-16 combinations may report `manifest_xml_invalid` instead of the DTD code.
2. The same 63 variants run with `_elementtree` disabled and verify the pure
   Python fallback. Both paths retain ordinary UTF-8 and BOM-prefixed UTF-16
   assembly identity facts.
3. A real project-store row using the *current key and ownership guard* but a
   version-2 envelope is a cache miss. Reading it preserves its row ID and body
   hash. Publishing recomputed current metadata then supplies a valid cache hit.
4. Both imported cache constants equal 3, version-2 and version-3 keys differ,
   and restoration of the current version recovers the same current key.

These are **four pytest tests containing 126 parser variants**, not 130 tests.
An initial peer harness had a quoting syntax error in its embedded child script;
that authoring error was corrected before the passing run and was not attributed
to the product. No downloaded binary was executed and no external DTD resource
was contacted.

The reviewer also inspected the implementation's reopened legacy-row regression,
envelope equality check, exact keyed lookup and owner-thread publication. The
cache-key and envelope version checks cover different replay attempts; preserving
both is necessary. This review does not establish native Windows, full-suite,
remote-service or broader metadata-cache authenticity acceptance.

## Reproduction

After integrating `0ac15cbc`, run from the repository root:

```sh
PYTHONPATH=src:tests QT_QPA_PLATFORM=offscreen python -m pytest -q \
  docs/engineering/evidence/test_manifest_dtd_peer_controls.py
```

The [independent controls](evidence/test_manifest_dtd_peer_controls.py) and
[terminal result](evidence/manifest-dtd-peer-result.txt) are retained alongside
this review. The runtime was Python 3.12.14 with pytest 9.2.0.
