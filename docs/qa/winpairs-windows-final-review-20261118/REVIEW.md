# Independent Windows publication repair review

**Verdict: no blocking source/test finding. Approved to proceed to exact-head hosted Windows qualification. Native Windows acceptance remains pending.**

Reviewed commit `1c49199e9333e955e2bd947fda2824d68b7da65d`, tree `aa7749a9a1c2abe7c3a4bde2473e717411f7ac9e`, against parent `bb4277aed685d485b57ffe7a718e70bab3e34467`. The reviewer did not author or modify this repair. Review and execution used a separate detached worktree, which remains clean.

## Observed original failure

The PR304 log records failures in shared Windows publication, including ordinary downloaded artifacts and resolve-only JSON receipts. The native held-handle test reached its fsync hook and successfully rejected parent/stage replacement and stage writes before its final publication assertion failed. The available error87 wrapper does not identify the original failing Win32 call or parameter.

An independent portable control against the published source blob `20306c85950c62fcc18b8bd0bc13d4665375933e` reproduced cleanup OSError87 replacing both a primary FileExistsError and a primary KeyboardInterrupt. This is concrete exception-flow evidence, not proof of the native error87 cause. Neither BOOLEAN nor non-null RootDirectory is classified as an established ABI defect.

## Source and contract review

- Native information calls bind HANDLE, IO_STATUS_BLOCK pointer, buffer pointer, ULONG byte length and information class, with signed NTSTATUS return handling and RtlNtStatusToDosError translation.
- Rename uses class10, the held source and parent, ReplaceIfExists=False, and exact UTF-16LE bytes. Allocation retains the documented sizeof(FILE_RENAME_INFORMATION)+encoded-name-length lower bound; it does not shrink to the flexible member offset.
- Disposition uses class13 and the exact held source. The existing source DELETE access, synchronous nonalert opens, parent traversal/read-attribute access, no-reparse operations, identity checks and no-overwrite behavior remain intact.
- Every information call has freshly zeroed completion storage. Negative statuses are translated; pending and other nonzero positive returns do not receive success credit.
- Primary publication errors, collision classification and cancellation survive secondary discard and source-close failures. Both owned-source cleanup attempts run as appropriate to CRT descriptor ownership. Post-publication guard failure does not discard the published object, and close failure prevents a success claim.
- No path-based rename, replacing publication or name-based cleanup fallback was added. Secondary notes remain bounded through the PublicationBlocked wrapper.

## Independent validation

The three repository publication/integrity suites independently reran with **101 passed, 2 skipped**. The two skips require native Windows. Repository Ruff and git diff --check passed.

The separate review module contains **15 passing controls**. These cover constructor binding without Win32 fallback; full-width handle values; one-character, BMP and non-BMP UTF-16 names; fresh completion storage; pre-transfer CloseHandle failure together with discard failure; cleanup KeyboardInterrupt/SystemExit preserving a collision; post-rename parent/identity guard failures with close failure; successful rename without disposal; close cancellation; and bounded secondary notes.

Portable ctypes models and injected lifecycles do not emulate Windows filesystem behavior. Actual Windows publication, concurrent-target preservation, cleanup, ancestor/stage locking and reparse controls remain required on the exact published candidate. The original native failure evidence is preserved without a speculative cause attribution.

## Primary contracts

- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information
- https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information
