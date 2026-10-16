# LBL-30: preregistration and single-use Tier R training CLI

Status: implemented on isolated branch, **live acceptance pending**. This is a narrow supplement to
`docs/specs/program-e/LBL-DATA-integration-plan.md` section 3 and C9 PREREG section 8. It changes
training CLI policy only; no persisted report schema or release calibration policy changes.

## Admission states

- No `--prereg`: evaluation is explicitly unlocked. The training key uses
  `unlocked-placeholder`, the report `prereg_sha256` is null, and the dataset is not preregistered.
- `--prereg FILE`: read exact file bytes, refuse CR/CRLF, hash them with SHA-256, and require
  equality with the `C9-PREREG-v1` SHA recorded in `--qa` (default `docs/qa.md`).
  A missing, unreadable, or conflicting record is a usage error **before training input reads**.
  A verified preregistration SHA **cannot execute a normal run**: training with this SHA
  requires the exclusive final-run receipt. Use `--unlocked-prereg` on draft data for dev rehearsals.
- `--prereg FILE --unlocked-prereg`: read and validate the draft, but pass *no preregistration
  SHA* to training. The CLI summary may include a draft SHA under `unlocked_rehearsal`;
  the report and artifact still carry the unlocked placeholder. The draft is never considered
  the preregistered result.
- `--unlocked-prereg` without a file is an error.

## One-look final request

The `--locked-form` switch by itself is refused: it may not inspect locked-role rows without the exclusive receipt.\n\nThe only final CLI path is `train run --final-locked-test --locked-form --prereg FILE
--corpus-dir EXTERNAL --qa QA --out DIR`. It refuses `shift`, `--smoke`,
`--unlocked-prereg`, missing protocol, and a lock directory inside the repository.
The matching `C9-PREREG-v1` QA row must explicitly contain `owner approved`,
`owner approval recorded`, `owner sign-off approved`, or `owner signed off`.
This textual sign-off is a manual owner record, not a cryptographic identity signature.

After validating the *protocol* and CLI flags, the command calls
`run_locked_test(corpus_dir, prereg_sha, evaluate)` with an exclusive-create receipt.
The receipt is written **before** the callback reads labels, outputs, or feature rows.
If the callback errors or the machine crashes, the SHA is still spent. An existing receipt
refuses a retry. No receipt is created by default or by `--unlocked-prereg`.
The final response includes `locked_test_receipt` only when the callback returns.

Final-mode `--locked-form` additionally enforces the existing minimum 12 locked-role lineage
guard; it is **not** a substitute for the single-use receipt. A report with failed/insufficient
gates is not relabeled as successful. Any SHA previously spent must never be retried.

## Verification and scope boundaries

Hermetic tests cover LF/CRLF, missing/mismatched QA digest, draft substitution,
invalid final flags, matching-row approval, exclusive receipt, duplicate refusal and a
failing callback that still consumes the receipt. Full Linux/Windows QA must pass before merge.

This code does not complete the C9 preregistration text, corpus expansion, label audits,
Tier W Windows-binary validation, locked look, or any G0/G2/G3 gate. Numeric calibration
must remain disabled and application display ordinal-only until independent real acceptance.
