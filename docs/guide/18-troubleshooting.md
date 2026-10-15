# 18. Troubleshooting

Symptoms, causes and next steps, drawn from the in-app messages, `docs/user-guide.md`, `docs/install.md`, `docs/linux.md`, `docs/qa.md` and the code. Messages that start with `PT-` carry a stable code; the table at the end maps prefixes to subsystems. If nothing here helps, collect the version, OS, backend versions, the steps and a **sanitised** log (redaction is best effort: read it first, [17](17-privacy-and-network.md)).

## Start-up and installation

| Symptom | Cause | Next step |
|---|---|---|
| Windows: app does not start, or `_internal` not found | only `PatchTrace.exe` copied, or run from inside the zip | Extract the whole zip, keep `PatchTrace.exe` and `_internal` together |
| Windows: SmartScreen warning, or a blocked file | the package is unsigned; the zip carries the Mark of the Web | Right-click the zip, Properties, **Unblock**, then extract; or `Unblock-File` |
| Checksum differs | corrupted or modified download | Download again; compare with the `.sha256` file and a second channel |
| Linux: `Could not load the Qt platform plugin "xcb"` | host Qt libraries missing (usually `libxcb-cursor0`) | `ldd PatchTrace/_internal/PySide6/Qt/lib/libQt6XcbQpa.so.6 \| grep 'not found'`, install the listed packages ([10](10-getting-started.md)) |
| Linux headless check | no display | `QT_QPA_PLATFORM=offscreen ./PatchTrace/PatchTrace --self-test` should exit 0 |
| `patchtrace: error: ...` and exit 2 for a mistyped verb | first CLI argument is dispatched to the CLI, never to Qt | Run `patchtrace --help` |

## Creating and opening projects

| Symptom | Next step |
|---|---|
| "Unsupported input" | Both files must be real PE AMD64 (`.exe`, `.dll`, `.sys`). 32-bit, ARM64, ELF, archives and renamed text are rejected by header |
| Destination refused | Choose an absent or empty folder, or use **Open** for an existing project. A path that is a file, or a Windows path that is too long, is refused (`PT-BACKEND` output-path rules apply to analysis) |
| `PT-STORAGE: project is locked by another writer or lock is inaccessible` | Another PatchTrace instance (or a crashed one's lock) holds the project. Close the other instance; check folder permissions. The lock is a kernel advisory lock on `.patchtrace.lock`, so a crash releases it |
| Project on a synced folder (OneDrive) behaves oddly | Keep projects on a local, non-synced path. Dot-prefixed directories in the Ghidra path are refused (`PT-BACKEND`) |
| Opened a project from a much newer build | Back up first (**Project > Back up project...**); future schema migrations are possible, and unknown contract versions are refused |

## Running a comparison

| Symptom | Cause / next step |
|---|---|
| **Run comparison** is disabled | It needs a pair, a configured backend and an idle job. Open **Setup**; hover the button for the "Availability" line |
| Diagnose cannot find Ghidriff | Setup must point at the backend `python.exe` (for example `...\PatchTrace-backend\Scripts\python.exe`), not `PatchTrace.exe` |
| Ghidra or Java failure | Select the **unpacked Ghidra root** (it contains `Ghidra/application.properties`), run `java -version` in a new shell, restart PatchTrace after changing Java settings, read the job log and `analysis.log` |
| `PT-BACKEND: ghidriff exited with code N; ...` | The classification text names the likely cause; open `analysis.log` in the project |
| Comparison times out | Raise the timeout in Setup (10 to 86,400 s, default 3,600). A retry is a new attempt; earlier results stay |
| Import rejected | Use the **raw Ghidriff JSON** for the exact pair and orientation. HTML, Markdown, arbitrary JSON and PatchTrace exports are not accepted; unknown top-level roots fail closed |
| Empty function list | Clear the filters. An identical pair has no changed functions; category lists are not an enumeration of all functions |
| Cancelled job leaves a process | Use Task Manager only after the status shows a terminal state. Cancellation kills the whole child tree (Job Object / process group); report it if a Java process survives |
| Assembly tab says unavailable | The import did not keep instruction text. It is never fabricated from an instruction hash |

## Reading results

| Symptom | Explanation |
|---|---|
| Ranking shows `[ — ]` | A detector lacked evidence (for example no decompiled code on one side). That is unknown, not zero |
| Finding is **stale** | The project changed after it was made (correction, swap). Re-interpret the current selection |
| Evidence link does not jump | The finding is stale; the raw immutable context is shown instead of current code |
| Everything is `Single engine` or `Unknown` in Engine evidence | No secondary engine has run or been imported. Use **Probe engines**, then **Run selected engines** or `secondary run` ([12](12-evidence-and-engines.md)) |
| BinDiff will not run | It needs an absolute path to BinDiff 8 and two validated `.BinExport` files for this exact pair; a `.BinExport` without a SHA-256 id needs the explicit override. Run **Validate .BinExport files** and read the reason slug |
| rz-diff "unsupported" | `rz-diff` is not on PATH; pass `--rz-diff` |
| **Run** is disabled in the Unified tab | The `unified/enabled` setting is off (default), no finished Ghidriff run exists, or an engine run is active ([99](99-open-doc-questions.md)). The CLI `unified run` does not need the setting |
| Unified result "stale" | An input changed; `unified status` shows why; run again |
| A dock I expect is missing | Only 5 panels are built; the others are planned ([13](13-panels-and-layout.md)). Check `patchtrace panels list` |
| Layout looks wrong | **View > Reset panel layout**. A corrupt stored layout is replaced by defaults and the status line says so |
| Export lacks code or notes | Check the Export options (code default off, notes default on) and regenerate the preview |

## Network and consent

| Symptom | Next step |
|---|---|
| `correlate --fetch` exits 2 | `--consent-providers` missing, or not equal to `--providers` |
| `acquire` / `intelligence fetch` / `kev fetch` exits 2 | `--consent-hosts` missing or not exactly the allowed host list |
| AI send does nothing | A remote provider needs HTTPS; Ollama must be on a loopback host (`PT-PROVIDER` message names which rule) |
| `kev status` says stale (partial, exit 0) | Run `kev fetch` again, or use `--max-age-days N` to make staleness exit 3 |
| Nothing was sent but I expected it | Correct: every request needs its own consent ([17](17-privacy-and-network.md)) |

## Bundle and runtime

| Symptom | Next step |
|---|---|
| `backend status` exits 4 "no bundle" | You run a lite package; use external tools or import a backend ZIP ([10](10-getting-started.md)) |
| `PT-BUNDLE-*` problem | `MISSING`, `MANIFEST`, `PLATFORM`, `SIZE`, `EXTRA`, `HASH`, `LINK`, `WORKDIR`, `PIN-MISMATCH`, `LICENSE`, `SIZE-LIMIT`. The fast check names the first problem; the remedy is to extract the complete archive again |
| Imported runtime install failed or was cancelled | Existing installs are untouched. A stranded hidden staging directory or stale install lock must be reviewed and removed by hand |
| Exit code 4 | A legitimate empty result, not a failure |

## Error code prefixes

| Prefix | Subsystem |
|---|---|
| `PT-SCHEMA`, `PT-STORAGE`, `PT-INPUT`, `PT-CANCEL`, `PT-EXPORT` | core contracts, project storage, imports, exports |
| `PT-BACKEND` | Ghidriff / Ghidra / Java configuration and run classification |
| `PT-BUNDLE-*` | offline backend bundle verification |
| `PT-ENRICH-*` | ranking, signals, CVE context (`INPUT`, `OWNERSHIP`, `CONFIG`, `LIMIT`, `CANCEL`, `STALE`, `CACHE`, `NETWORK`, `PROVIDER`) |
| `PT-ACQ-*` | Winbindex / symbol-server acquisition |
| `PT-NWAY-*` | series (`INPUT`, `LIMIT`, `PAIR`, `STORAGE`, `CANCEL`) |
| `PT-SECONDARY-*` | BinDiff, rz-diff, BinExport, scheduler |
| `PT-UNIFIED-*` | unified engine (`INPUT`, `STORE`, `LIMIT`, `IR`, `EXTRACT`, `TIMEOUT`, `STALE`, `UNSUPPORTED`, `CANCEL`) |
| `PT-INTEL-*`, `PT-TOOL-*` | CSAF advisories; capa / FLOSS / diec adapters |
| `PT-KBC-*`, `PT-KEV-*`, `PT-PILOT-*`, `PT-RULE-*`, `PT-FAB-*` | KB correlation, KEV, patch-intent leads, YARA-X rules, anchor fabric |
| `PT-PROVIDER` | AI provider transport |
| `PT-GUI-*` | GUI framework (`MANIFEST`, `TIPS`, `TASK`, `LAYOUT`) |

Messages are fixed templates: labels and numbers, never raw file, advisory or engine text. See [19](19-glossary.md) for terms.
