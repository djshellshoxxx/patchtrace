# Independent Windows publication review — 2026-11-18

Read-only review of the observed failure at PatchTrace `bb4277ae`; root owns the repair. No target bytes were acquired or executed, and no repository files were changed by this reviewer.

## Established observations

- The retained Windows boundary log reports 15 failures, 61 passes, and 3 skips. The native ancestor/stage test reached its fsync hook and completed its replacement/write-denial assertions, then publication returned `missing`. The public error was OS error 87. This localizes the failure after staging but does not identify the precise invalid parameter: cleanup can mask an earlier exception.
- Current Microsoft Win32 documentation explicitly permits a directory handle for relative rename. It does **not** establish that nonnull `RootDirectory` is categorically unsupported. The failure on this runner remains real despite that documented contract.
- Both Microsoft Learn and Microsoft's captured `WinBase.h` declare the Win32 deletion member as `BOOLEAN`, as does the native disposal structure. A claimed one-byte-versus-four-byte ABI mistake is therefore not supported by the inspected primary sources.
- An in-memory Python control reproduces exception masking: `KeyboardInterrupt` from `_write_stage` followed by `OSError(87)` from owned cleanup surfaces the `OSError`, with cancellation only in `__context__`. This is exception-flow evidence, not a native Windows result.

## Native repair plan review

Using `NtSetInformationFile` for rename class 10 and disposal class 13 is coherent with the native documented contract. Preserve the existing source handle, rooted parent handle, false replacement flag, source identity checks, and synchronous/nonalert source-open invariant. Bind the NTSTATUS result as signed 32-bit; map failure using `RtlNtStatusToDosError`, not thread-local Win32 last-error state.

Rename requires source DELETE access. Keep the parent's traverse/read-attributes access. Encode the simple target name as UTF-16LE and count bytes, retaining a zeroed buffer at least `sizeof(FILE_RENAME_INFORMATION) + encoded-name length`. Keep every pointed-to object alive through the call. Disposal uses a one-byte BOOLEAN; after successful disposal, only close the held handle. Never reopen a stage or destination path for cleanup. Preserve the primary exception or cancellation if cleanup also fails, and retain bounded secondary diagnostic context.

Native acceptance must cover ordinary publication, one-character and non-BMP target names, concurrent destination creation without replacement, failure/cancellation cleanup, held ancestor/stage protection, and the existing synthetic reparse control. Portable fixed-width ABI tests verify argument layout and dispatch only. They cannot establish Windows filesystem behavior. No fallback to an unanchored path is acceptable.

## Evidence

- Failure log: `/workspace/scratch/e83fbf4505c3/pr304-windows-boundary-failure.log`, SHA256 `a3c06a20a70fc31af0ef6c63515289b4e22026afeef2229701df7fe1a7893a04`.
- Reviewed `winpairs.py` before repair: SHA256 `2911de3b12887f300be05606395cbdd78440614875864540f33e109010750710`.
- Captured Microsoft header: `WinBase.h`, 262,806 bytes, SHA256 `c0ac06ea6b2335bd085af0e3071f9dd099bf9bd4c2f79ba2034b4813636cd7c1`; bounded normal-transport receipt `WinBase-fetch.json`. This is a captured main-branch snapshot, not an asserted upstream commit pin.
- Exception-flow reproducer: `check_exception_mask.py`. Execute with the reviewed checkout on `PYTHONPATH`, using the shared Python environment. It writes no files and does not invoke a native API.

## Primary references

- [Win32 rename structure](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_rename_info)
- [Native rename structure](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/ns-ntifs-_file_rename_information)
- [Native set-information API and classes](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntifs/nf-ntifs-ntsetinformationfile)
- [Win32 disposition structure](https://learn.microsoft.com/en-us/windows/win32/api/winbase/ns-winbase-file_disposition_info)
- [Native disposition structure](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/ntddk/ns-ntddk-_file_disposition_information)
- [I/O status and pending semantics](https://learn.microsoft.com/en-us/windows-hardware/drivers/ddi/wdm/ns-wdm-_io_status_block)
- [Microsoft header source](https://github.com/microsoft/win32metadata/blob/main/generation/WinSDK/RecompiledIdlHeaders/um/WinBase.h)

## Rizin checkpoint

First pilot MISS and its evidence remain sealed. The separate diagnosis is paused before compilation or authored-control analysis at `/workspace/scratch/e83fbf4505c3/l2-postmeasurement-diagnosis/20261118T083739Z-rizin-discovery/paused-checkpoint.json` (SHA256 `601b9677c3cbf6c89a053c3ed1ea38e3e9c78f3d095f33b59552338bf339f86b`). The checkpoint contains the predeclared control plan, authored sources, pinned upstream source receipts, and unexecuted control harness. Candidate reruns: zero.
