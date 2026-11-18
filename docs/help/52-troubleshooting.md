# Troubleshooting

Start with the full message. Most messages name a code (`PT-...`) followed by the reason. Copy the code and the reason when you ask for help. Do not paste project files or code text unless you have checked them.

## Offline use

PatchTrace is offline by default. Comparing builds, reading stored evidence, ranking and writing reports make no network request. A request happens only when you start a network operation and approve it.

- **There is no product-wide offline switch.** Nothing is fetched in the background, so nothing needs switching off. `Allow Ghidriff symbol-server lookups (may access the Internet)` in **Setup** is unchecked by default.
- **KEV.** When network updates are off, the KEV panel shows: *Network updates are switched off here. Import file still works.* Importing a catalog file you saved still works.
- **CLI.** `intelligence fetch --offline` uses only `--cache-dir`. `intelligence explain` reads stored advisories and sends nothing. `kb search --offline` never fetches. `kb acquire --offline` refuses to fetch and exits 2 if a consent flag is also given (`offline mode never fetches; remove the consent flags`).
- **No backend.** Without an analysis runtime you can still open the Sample, read stored results and export reports. Native comparison needs the runtime (see [13](13-install-an-offline-backend-bundle.md) and [11](11-configure-the-analysis-backend.md)).

## Consent prompts

A consent prompt is a Yes or No question shown before a network request. The default answer is No.

| Prompt title | What it covers | If you answer No |
|---|---|---|
| `Consent · Winbindex metadata` | One metadata GET to the Winbindex host, named in the prompt. Only the file name is sent. | Status: *Search not performed; consent declined.* |
| `Consent · Microsoft symbol server` | The exact download requests listed in the prompt. Each file is checked against its SHA-256 and size. | Status: *Download not performed; consent declined.* |

Read the host and the request list before answering Yes. A prompt lists exactly what will be contacted. A CLI request needs the matching `--consent-hosts` or `--consent-providers` value, which must equal the planned hosts exactly. Otherwise the command stops before any request. See [17](17-network-use-and-consent.md).

## Cancelled and blocked operations

- **Cancelled.** Status text such as *Cancelled · previous results preserved* means earlier committed results are unchanged. Wait for the status to reach a terminal state before you start the same operation again.
- **`PT-CANCEL`.** Appears at the start of a message when the operation stopped at your request. A partial output may be kept in quarantine and is not used as a result.
- **Blocked.** A blocked panel names its missing prerequisite. Resolve that prerequisite (for example, a project or a finished run), then refresh. See [40](40-blocked-and-unsupported-states.md).

## Project is locked

`PT-STORAGE: project is locked by another writer or lock is inaccessible` means another PatchTrace window or process holds the project's lock file. Close the other window first and retry. Do not delete the lock file to get past it, because that bypasses the ownership check.

## Offline backend ZIP import errors

These errors come from **Setup > Install offline backend ZIP…**. They use the code `PT-OFFLINE`. Nothing is installed when an import fails. Earlier runtimes are kept.

| Message (after `PT-OFFLINE:`) | What to do |
|---|---|
| `select an existing offline ZIP` | Choose the file again. |
| `expected archive SHA-256 must be 64 lowercase hexadecimal characters` | Correct the **Trusted offline ZIP checksum** field, or leave it empty. |
| `archive SHA-256 differs from the trusted expected SHA-256` | The file is not the one you checked. Obtain it again from its source. |
| `unsupported bundle format or schema`, `this bundle is not a Windows x64 backend` | Use a bundle built for this package and platform. |
| `ZIP entries do not match the exact manifest inventory`, `ZIP has unexpected files`, `payload SHA-256 hash or size mismatch` | The archive is incomplete or altered. Obtain a fresh copy. |
| `unsafe archive path`, `symlink or special file in ZIP is forbidden` | The archive is refused as unsafe. Do not extract it by hand. |
| `insufficient disk space for this offline backend and extraction reserve` | Free space on the install drive, then retry. |
| `runtime already installed; existing files were not overwritten` | The runtime ID is already present. Keep it, or use a different install root. |
| `installation lock exists; a concurrent or interrupted install must be reviewed` | Check that no other install is running. Review the lock before you remove anything. |
| `Windows destination path too long; use a shorter runtime ID or install root` | Use a shorter install root. |
| `installation failed; no runtime published` | Nothing was published. Retry, and keep the retained log if it repeats. |
| `PT-CANCEL: installation cancelled; existing runtimes were preserved` | You cancelled. Existing runtimes are unchanged. |

## Bundle verification errors

**Setup > Verify bundle files** and `patchtrace backend verify` check the bundle next to PatchTrace against `backend/manifest.json`. A matching manifest proves integrity only, not who published the files. These codes can appear:

| Code | Meaning |
|---|---|
| `PT-BUNDLE-MISSING` | No `backend/manifest.json`, or no bundled runtime at this location. The message says to extract the complete ZIP again. |
| `PT-BUNDLE-MANIFEST` | The manifest cannot be read, is too large, or is not valid. |
| `PT-BUNDLE-PLATFORM` | The bundle is for another platform than this host. |
| `PT-BUNDLE-HASH` | A listed file's SHA-256 differs from the manifest. |
| `PT-BUNDLE-SIZE` | A listed file's size differs from the manifest. |
| `PT-BUNDLE-EXTRA` | A file the manifest does not list, or an unexpected entry in the payload. |
| `PT-BUNDLE-LINK` | A link or junction sits where the bundle expects a real file or directory. |
| `PT-BUNDLE-WORKDIR` | The work, cache or temp path is inside the bundle install tree. Choose a path outside it. |
| `PT-BUNDLE-PIN-MISMATCH`, `PT-BUNDLE-PIN` | Developer-side build checks for the pinned downloads. They are not raised when you use a finished bundle. |
| `PT-BUNDLE-LICENSE`, `PT-BUNDLE-SIZE-LIMIT`, `PT-BUNDLE-PATH-LENGTH` | Declared codes with no raise site in this build. The Windows path-length check is reported as `PT-OFFLINE` (see above). |

If a check fails, do not edit the files in the bundle. Obtain a complete copy and install it again.

## Dependency and comparison failures

- **No analysis has been started. Configure dependencies in Setup or import a Ghidriff JSON.** This is the initial diagnostic-log message, not an analysis failure. Use [**Sample**](03-explore-the-sample.md) for a backend-free exercise, [**Import JSON**](06-import-ghidriff-results.md) for existing output, or [configure the backend](11-configure-the-analysis-backend.md) for **Run comparison**.
- **Missing Ghidriff, Ghidra, or Java.** Open **Analysis → Setup → Backend and desktop**, check the external Python executable and Ghidra installation directory, then select **Diagnose dependencies**. Choose the backend's Python executable, not `PatchTrace.exe`. Save corrected settings with **Save setup**.
- **Diagnose dependencies passes, but a comparison fails.** The check confirms paths and tools. It does not prove that every file pair compares. Read the retained log for the failing step.
- **Results look old.** Check the run identity and the *stale* notice. A failed attempt keeps the previous committed result. See [38](38-stale-results.md).

### Comparison timeout or quiet progress

The timeout message begins **PT-BACKEND: analysis timed out; configured limit … seconds** and includes the elapsed time and last observed stage. Follow its recovery path:

1. Open **Analysis → Setup → Backend and desktop → Comparison timeout (seconds)**.
2. Choose a limit appropriate for another attempt, then **Save setup**. The default is 3,600 seconds; the allowed range is 10–86,400 seconds. This changes the next run, not an attempt already running.
3. Start a new **Run comparison**. Earlier committed results remain available if the attempt failed.
4. Inspect the diagnostic directory named in the message, `runs/quarantine-<run-id>/` under the project. It can contain `analysis.log`, `failure.txt`, and `backend-execution.json` when available. Keep the configured limit and last observed stage with any bug report.

During a run, a status such as **Ghidriff: … · … / … seconds · last output … seconds ago** reports observed backend activity. **No output yet** or an old last-output time does not by itself prove a hang; some stages are quiet. Use **Cancel job** to request cancellation and wait for the terminal status before retrying. See [running a comparison](05-run-a-comparison.md).

### Empty function or finding list

For **FUNCTION MATCHES**, clear **Search names or addresses…**, choose **All categories** and **All review states**, and uncheck **Manual corrections only** and **Matches with findings only**. Then check whether a comparison/import completed for the intended pair. Identical inputs can legitimately have no changed functions; an empty filtered list alone does not prove identity.

For **FINDINGS & ANALYST REVIEW**, clear **Search findings…**, choose **All reviews** and **Current & stale**. A comparison does not automatically produce AI findings: interpretations are optional. You can still review matches and save notes. See [reviewing findings](19-review-findings-and-record-conclusions.md) and [empty-result limits](43-limits-truncation-and-empty-results.md).

Other panels have their own filters and status messages. A blocked, partial, or unavailable result is not evidence that no relevant change exists.

## Still stuck

Record the version, the panel or command, the full `PT-` code and message, and whether the operation touched the network. Keep the project unchanged while you investigate. Report what you could not reproduce as unverified rather than as fixed.

Sources: `src/patchtrace/offline_bundle.py` (PT-OFFLINE messages), `src/patchtrace/backend_bundle.py` (CODES and checks), `src/patchtrace/backend.py` (PT-CANCEL and PT-BUNDLE messages), `src/patchtrace/backend_progress.py` (progress and timeout recovery), `src/patchtrace/persistence.py` (PT-STORAGE lock), `src/patchtrace/ui.py` (consent prompts, Setup labels and filters), `src/patchtrace/kev/view_model.py`, `src/patchtrace/kbcorrelation/cli_online.py`.
