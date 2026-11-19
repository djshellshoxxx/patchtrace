# PW-02 native/held-reader integration design checkpoint

This checkpoint is **design and source provenance only**. No native Windows
execution, SDK build, package decoding, workflow dispatch or new test result is
claimed. Corrected pure-contract source `645839646a68815ee1822ee61039af42d583903a`
and QA tip `dc4ebf9ccf04abc284ffe334b858c6d39047b68d` remain unchanged. Root's
integrated design base is `27e4318b87e0af3be0fc11a1906b86d95c44f46b`, tree
`d0d68f3fb82ceb2032d002f9023fadae67b89e78`.

The archive contains the withdrawn initial draft, the revised native handoff,
the joint file/interface map, primary documentation URLs, capture/seal scripts
and 17 exact canonical Git source snapshots. The original first-slice and ASCII
correction QA histories remain separate and immutable.

## Decisions and remaining gates

- Parent-directed file transfer inside the existing Job-contained suspended
  supervisor is the next native direction. No worker receives parent-process
  duplication authority. An explicit inherited standard-handle list and narrowed
  noninheritable working-file duplicates replace the withdrawn initial proposal.
- Bootstrap bounds/trust, parent-versus-child handle closing, cancellation and
  termination uncertainty are explicit. Missing containment/cleanup evidence
  refuses admission and retains the affected stage.
- A selected file keeps its original R/W+DELETE handle with READ sharing through
  native no-replace basename rename. A separate rooted read-only open uses a
  compatible sharing mask and must match full native identity/state. Its sharing
  does not remove the original lock. Native compatibility remains unverified.
- A neutral HeldInput/PairInputReaders path is mapped through current inspection,
  both attachment hash checks and immutable project copying. The independent
  report reviewer owns the detailed KB design in
  `qa/pw02-kb-held-reader-design`; its separate controls are not copied or credited
  as native evidence here.
- ProjectStore's verification of its own copies needs the same neutral read/
  budget checkpoint, including pre-COMMIT. A later cancellation cannot undo a
  committed project. Durable package provenance and retained-project repair need
  an explicit binding; a lost temporary lease cannot be reconstructed from a
  journal pathname.
- The only next authorized implementation is the portable serial worker-grant/
  receipt boundary on a separate branch from `068513a7`. Jobs, native publication,
  KB readers and persistence remain outside that slice. Native Windows and the
  frozen local CAB/MSU pair journey remain necessary for full PW-02 completion.

## Archive verification

`evidence.zip`: **267,262 bytes**, **26 members**, **764,589 uncompressed bytes**.
SHA-256: `7015cbfe58cda8a885d48bb1d25946169bbca4e031350c7eb27920a75fcce94d`.
All member sizes, SHA-256 values and ZIP CRCs were checked. Source snapshots were
read with Git replacement objects disabled and file-only Git transport; this
capture invoked no network or package/target process. `manifest.json` lists every
member. No test or native gate was rerun for this documentation-only checkpoint.

External source packet:
`qa/pw02-local-packages/native-seam-design/`. Its `interface-map.md` is the compact
review entry point; `native-handoff.md` contains lifecycle, authority and native
acceptance details. `initial-README.md` retains the superseded child-opened
parent-process proposal with its original hash rather than silently replacing it.
