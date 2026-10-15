# Pilot synergy oracle (PIL-T, plan s5)

**Every file here is SYNTHETIC.** They were generated on 2026-10-14 for PatchTrace tests from the "Synergy test" tables of `docs/specs/program-e/PIL-integration-plan.md` section 5. No vendor published the advisories, no binary exists (the build digests are hashes of labels), and nothing here is live evidence. CVE ids use the impossible year 2099 (`CVE-2099-20001`, `CVE-2099-20002`, `CVE-2099-30001`); the publisher is "PatchTrace Synthetic Fixture Vendor (not Microsoft)" at `example.invalid`.

## What it proves

The oracle is the acceptance gate of the fusion and ranking engine (PIL-B2): nine functions of a module `examplenet.sys`, two CVEs fixed by the same update, and nine "arms" (which evidence channels the engine may use). The plan's claim is that only the full arm isolates the true function, because independent channels agree there and every single channel falls short. `tests/test_pilot_synergy.py` holds the checks; `tests/pilot_synergy_support.py` turns the ledger into fake ports and holds the one seam to the engine.

## Files

| File | Purpose |
|---|---|
| `generate.py` | Regenerates every JSON file below (`PYTHONPATH=src python tests/fixtures/pilot/synergy-1/generate.py`, `--check` exits 1 on drift). The two tables of plan s5 are transcribed there verbatim; the structured values (rank ranges, tie partners, FITS sets) are parsed from those cells. |
| `synthetic-pilot-advisory.json` | Validator-clean CSAF 2.0 for both CVEs: CVE-2099-20001 states CWE-787 (title "... IPv6 Fragment Reassembly ...", description "heap-based buffer overflow"), CVE-2099-20002 states CWE-125 ("... IPv6 Options Parse ..."). Two file-hash products carry the SHA-256 of the older and newer synthetic build; both CVEs are fixed on the newer build, so the window is confounded. |
| `ledger.json` | The hand-built ledger: nine candidates (`F1` to `F9`) with explicit older and newer RVAs, 17 flat `Observation` records (`pilot/1`, ids derived through `patchtrace.pilot.keys`), the `adv:*` observations of the four sources that state the CWE of CVE-2099-20001, the per-CVE contexts PIL-A2 will report, the KEV snapshot, tool cache keys. |
| `expected.json` | The oracle: the plan's two tables with their verbatim cells, the nine arm definitions, the full-arm class, rank block and caps per function and CVE, KEV and the "why" facts for F1. |
| `sample-cwe125-advisory.json` | Validator-clean CSAF 2.0 for the committed sample project (`patchtrace.sample`): one CVE (CVE-2099-30001, CWE-125), products carrying the SHA-256 of `synthetic_pe(0)` and `synthetic_pe(1)`; its statuses also sit on the file-hash products themselves, so the sample's verified bytes resolve through a verified mapping. Used by `tests/test_pilot_sample_e2e.py`. |

## Modelling decisions (where the plan is silent or thin)

- **Locality is not in the ledger.** Name matching depends on the CVE (F1 matches CVE-2099-20001, F6 matches CVE-2099-20002), so PIL computes it from the candidate names and the advisory component phrase (K anchors, `enrichment.cve.name_terms`, where `reassembly` and `reassemble` are one token). The `no-names` arm replaces names by Ghidra placeholders (`FUN_...`).
- **The repeated CWE is one observation per source** (`adv:cwe-stated`, `-nvd`, `-msrc`, `-kev`), all with origin `D_vendor_text`: four sources, one witness.
- **DiE `toolchain-changed` is attached to F3** (the function whose churn it explains), not broadcast. A binary-level flag would cap F9 (lexical B1 evidence only) in the full arm, contradicting the plan; `test_die_flag_caps_lexical_only_lead` adds the binary-level flag through `ToolEvidenceSource.pair_observations()` instead.
- **Where the A1 ports run out.** No port delivers the `adv:*` observations of sources that are not CSAF (NVD, MSRC entry, KEV `cwes`), and none delivers `pair:*` observations (the pairing verdict is only `Candidate.identity`; F8's contest is `identity: contested`). `Sources.advisory_observations` carries the former; PIL-A2 and PIL-B2 decide the real route.
- **The FLOSS string is joined to F2** by value hash with the ChangeFacts string delta (static strings are never attributed by FLOSS alone).
- **F1's `RtlSizeTAdd` call is a Ghidriff label only** (`label-only`, no ChangeFacts callee delta), so ChangeFacts alone ranks F1 below the callee changes of F5 and F7, as the plan's arm table says.
- **The arms ablate evidence, not context.** `pairing` (the candidate universe and its verdicts) and `die` (build facts) are present in every arm; the single-channel arms also leave out the Ghidriff call labels. With these definitions the rules of plan s7 reproduce all nine rows of the arm table, including the tie ranges `2-8` (F3 carries the DiE nuisance and sorts last) and `1-3` (F8's contested pairing sorts last).
- **The best hypothesis is kept and all are listed.** The description's "heap-based buffer overflow" also gives CWE-122 (vocabulary), so F1 has two hypotheses of the same rule; `fits[0]` is the explicit CWE-787 one.
- **Only what the plan states or its rules force is asserted.** Rank blocks, not exact positions, for the partial and queue classes; the order inside a block depends on tie-breakers the plan leaves open.
- **Derived from s7 rather than stated in s5** (so a reviewer can challenge them): F9 listed before F8 (identity, contested last); `depth` typed for F8 and lexical for F9; one met expected change each for F9, F8, F6 and F4 (guard added, size recomputed); the rank blocks 4-6 and 7-9; the five members of the B1-only tie; the display order inside a tie (candidate key, because no attention rank is given); with a binary-level toolchain flag added to the full arm, F9 is capped and F8 and F1 are not.

## When PIL-B2 lands

Every engine test is marked `PIL_B2` (`xfail(strict=True, reason='PIL-B2', raises=EngineMissing)`). With `patchtrace.pilot.service.localize` present they run for real: a pass is reported as XPASS(strict), a failure; remove the marker, or adapt `localize()` in `tests/pilot_synergy_support.py` if the engine's input bundle differs. A wrong class, rank or cap is an ordinary assertion failure.
