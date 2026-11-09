# Desktop, persistence, lifecycle and Windows release: additional reuse research

Research date: 2026-11-03 America/Vancouver (2026-11-04 UTC). Research only: no target binaries, native analysis engines, installers or test suites were executed. This note proposes bounded follow-up work for Claude; it is not a claim that Windows acceptance passed.

## 1. Scope, baseline and active ownership

Repository observations refer to main `b77d84e5decf736b031f0a24094001274de41178`. Read `AGENTS.md`, `CLAUDE.md`, `docs/modules.md`, relevant GUI/report/release specifications, the proposed dock specification and prior R6 release research. `tasks/todo.md` is not safely readable as UTF-8 and was not edited. Source observations below are static inspection, not reproduced defects unless explicitly attributed to an existing test.

At the refreshed snapshot, PR #175 is `origin/claude/ws-a-20261104` at `dabba4aea4ba0fa19e71ede05ce4fb8ab6741942`, PR #176 is `origin/claude/ws-p-20261104` at `db0a0b05d48e4c8fb394ec4e221677b5efb37954`, and PR #173 is `origin/claude/ws-i-20261104` at `93587a0c19c654cd003938ad780520340248a87e`. They are active draft/open work, not main. Recheck their heads before implementation.

Main already contains `gui/qt/{host,docks,layout,tasks,table}.py`, versioned layout storage, generation-controlled task delivery, SQLite transactions and verified backup machinery, self-contained HTML export, a PyInstaller folder build and a per-user NSIS installer. `docs/specs/gui-framework.md` retains older “not built” statements; those are not an implementation inventory. The remaining proposed core dock extraction in PR #127 (`origin/docs/dockable-workspace-spec-20261030:docs/specs/DOCKABLE-WORKSPACE-SPEC.md`) is a separate unmerged specification: native feature docks do not mean that the central navigator/code/findings splitter has already become independently dockable.

Do not duplicate PR #175's icon, executable version-resource and `tools/check_windows_exe.py` work. PR #176 owns investigation/project adoption, keyboard table sorting, stale inspection failure handling and export disclosure. Its `gui/qt/project_adoption.py` retains the previous service until refresh succeeds and restores recent-project settings on failure. Treat that as a candidate integration seam; first compare the latest PR, then extend its regression coverage. Prior R6 concerns about backup verification based only on size/mtime are stale against current `verified_backup.py` and `tests/test_verified_backup_byte_integrity.py`; retain the NTFS acceptance requirement without refiling an already repaired generic defect.

## 2. Reuse decisions

| Candidate | Decision | Concrete use and limit |
|---|---|---|
| Qt native `QMainWindow`/`QDockWidget` | **Adopt existing APIs** | Extend current host and proposed core extraction. No second layout owner. |
| Qt model/view and `QAbstractItemModelTester` | **Adapt testing pattern** | Exercise `VirtualTable` resets/sorts/selections with existing PySide6 test support. |
| Qt `QSaveFile` | **Reference semantics** | Whole-document replacement/error handling; keep backend export Qt-free. |
| KDE KXmlGui `KMainWindow` | **Reference only** | Delayed settings save, explicit close veto and separate session/window state; do not import KF6. |
| SQLite backup API and crash-test ideas | **Adopt existing API; adapt tests** | Keep `Connection.backup`, verify full project closure and failure publication. |
| Qt Advanced Docking System / KDDockWidgets | **Defer** | Reconsider only for a demonstrated native-Qt requirement gap. |
| PyInstaller Windows external-program guidance | **Adapt after reproduction** | Process DLL search state is separate from child environment allowlisting. |
| NSIS core / Modern UI | **Keep and audit** | Existing compiler/version gate, per-user scope and manifest uninstall. |
| WebEngine, PDF renderer, new Markdown framework | **Defer** | Existing static HTML/JSON/Markdown covers current contract. |

Qt documents native split/tab/nested docking and state restoration [S1]. ADS advertises richer docking and perspectives plus LGPLv2.1; its binding distribution must be audited independently [S15]. KDDockWidgets' upstream license identifies GPLv2/GPLv3 or commercial terms [S16]. These facts establish alternatives, not a reason to migrate. The proposed workspace spec already chooses native Qt.

## 3. Dock and settings reliability: close the small gaps

**Verified API facts.** `QMainWindow::saveState` identifies docks/toolbars by unique `objectName` and embeds the application-supplied version. Qt's current documentation explicitly limits `restoreState` to compatible application-produced local state; it describes insufficient inner-field/depth bounds after the outer structure is accepted [S1]. Main's `layout.py` supplies schema, SHA-256 and 64-KiB checks. The digest detects accidental mismatch; it is not authentication against someone who can rewrite all settings. Do not import layout blobs from projects, reports, shared bundles or advisory data.

**Recommendation.** Keep `<id>.dock` append-only and create shells before restore, as current host does. Extend `tests/test_gui_host_layout.py` for newly extracted core sections rather than copying upstream layout internals. Test default layout → move/tab/float/hide → restart; new panel addition with an older saved state; retired panel ID; schema mismatch; incomplete three-key settings; oversized blob; and reset with all panels hidden. Use only known application-generated blobs for structural tests, not mutation fuzzing of Qt's binary deserializer.

Floating geometry requires a Windows acceptance case: save on a second monitor at 200% DPI, disconnect it, reopen on one monitor at 100%/150%, and verify every shown dock can be reached by keyboard and recovery controls. Passing an offscreen state round-trip does not establish this. Preserve selected match, filters, source orientation, consent and analysis settings when applying presets; layout should not mutate project evidence.

**Observed additional seam.** `ui.py::closeEvent` calls `settings.sync()` but does not inspect `settings.status()`. Qt defers writes and recommends sync before checking status; its default atomic synchronization may fail rather than silently downgrade [S2]. Add one bounded settings-save result at the host boundary so a failed layout write can be reported during the live session without preventing worker cleanup. Keep atomic sync enabled. Avoid writing every drag movement; KDE's documented delayed `setSettingsDirty`/autosave separation is a useful reference [S6]. This is a reliability recommendation, not a reproduced lost-settings incident.

## 4. Model/view and asynchronous lifetime

Qt requires model API calls on the owning thread; a view-bound model belongs to the GUI thread, while background preparation must deliver queued updates [S3]. Current `TaskRunner` already has channels/generations, cancellation tokens, lanes with thread-owned state, GUI delivery, callback release and a bounded shutdown. `tests/test_gui_tasks.py` already covers supersession, project switches, bridge deletion, hung workers and GUI-thread final destruction. Do not replace this with QtConcurrent or a second executor to solve the same problem.

Use `QAbstractItemModelTester` in the existing model tests: Qt says it repeats non-destructive consistency checks when models change, but does not replace application-specific destructive testing [S4]. Exact upstream implementation lead is `qtbase/src/testlib/qabstractitemmodeltester.cpp`; use the shipped binding rather than copying C++. Test `VirtualTable` with duplicate display text but distinct stable keys, empty results, filter reset after sorting, persistent index restoration, and schema/column change. PR #176's keyboard sorting changes are owned there: coordinate acceptance rather than changing the same handler independently.

The important remaining lifecycle test crosses abstractions. Begin inspection and a lane-backed store request, switch project, then close while a late success and late failure arrive. Assert old-project callbacks cannot persist into the replacement, the previous store closes on its creating thread, callbacks are not delivered to destroyed widgets, and run/sidecar publication is either complete or explicitly abandoned. Cancellation means obsolete delivery is suppressed; it does not itself prove a worker or native descendant has stopped. Qt's `QThread` guidance similarly distinguishes the wrapper object's owning thread, worker execution and orderly wait/cleanup [S5].

**Small diagnostic improvement to evaluate:** `PanelHost.shutdown` currently discards `TaskRunner.shutdown()`'s list of stuck workers. Preserve bounded names/counts in local diagnostics so close-time resource leaks can be investigated; do not attach raw exceptions, credentials or arbitrary paths. A daemon thread being unable to block process exit is not a durability guarantee. This requires a focused regression with an injected hung benign worker, then the existing shutdown gate; no wholesale scheduler rewrite.

## 5. Persistence and recovery: reuse SQLite, test project closure

Main's `ProjectStore` uses creating-thread SQLite connections, `BEGIN IMMEDIATE` for creation/save, current snapshot plus history, validation before commit and `quick_check` at open. `backup()` stages a new directory, uses `Connection.backup`, copies `artifacts`, `runs`, `exports`, `kb`, `intelligence`, then publishes without replacing an existing destination. Keep that architecture.

SQLite documents online backup as a consistent database-copy API and distinguishes it from ad hoc copying a live file [S7]. SQLite's rollback commit design covers journal recovery and identifies filesystem/flush assumptions; it does not make a directory of arbitrary sidecars transactional [S8]. Therefore acceptance must verify the **project closure**, not only `PRAGMA quick_check`: reopen the published backup and resolve every referenced artifact/raw result/derived sidecar, validate ownership and digests, compare notes/reviews/history, then exercise navigation and report export. Detect a concurrent sidecar update or constrain backup against mutation through existing service ownership. Do not infer correctness merely from copying folders after the database.

Adapt upstream crash-test concepts to a tiny synthetic project: fail after staging creation, during database copy, mid-sidecar copy, before publication and after publication. Before publication there must be no destination presented as complete; afterward it must reopen. Test locked destinations, full disk, same-size restored-mtime corruption, repeated backup-name collision and interrupted history-prune backup. Keep old evidence on failure and record orphan staging cleanup without recursively deleting the analyst's chosen project directory.

**Separate the stores before changing WAL policy.** SQLite documents network-filesystem limitations, extra `-wal`/`-shm` lifecycle and checkpoint responsibilities [S9]. It also records the WAL-reset fix in 3.51.3 and backports 3.44.6/3.50.7, with the multi-connection write/checkpoint conditions. `ProjectStore` in `persistence.py` does not enable WAL in its constructor, but writable KB workspace databases explicitly enable it in `kbcorrelation/store.py`. Record actual `sqlite3.sqlite_version`/source ID and journal mode for both stores in build evidence; inspect the KB connection/checkpoint pattern before deciding applicability. WAL mode alone does not establish that this documented defect affects PatchTrace, and Python's version is insufficient to identify the SQLite runtime. Do not enable WAL in the project store as a speculative performance fix. A new SQL framework or recovery extension is not needed for the identified gaps. SQLite deliverable code/documentation is dedicated to the public domain; its build scripts may have different terms [S10].

## 6. Windows native subprocess containment and frozen launch

`jobs.py::_windows_process` already creates a suspended child, configures `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`, assigns it, then resumes it; assignment failure terminates the suspended child. Keep the fail-closed sequence and existing `tests/test_jobs.py` assignment-denial/descendant-heartbeat tests. Microsoft documents default child association, nested jobs and explicit breakaway exceptions [S11]. A Job Object is lifecycle/resource containment, not a sandbox that authorizes arbitrary target execution.

**Memory accounting matters.** The existing `memory_limit_bytes` maps to per-process committed-memory limits; Microsoft distinguishes `ProcessMemoryLimit`, aggregate `JobMemoryLimit` and the two peak counters [S12]. Do not label the existing value “whole analysis tree RAM cap” or choose a new aggregate cap without measuring Java/Ghidra needs. Test allocation failure and cancellation separately with authored helpers. Actual native headroom remains external acceptance, coordinated with backend ownership.

**Highest-value new investigation: frozen DLL search inheritance.** PyInstaller 6.22.3 documents that its Windows bootloader calls `SetDllDirectoryW` for the bundle, that child processes inherit the effect, and that external programs may need it reset alongside PATH sanitization [S13]. Repository search found no `SetDllDirectory`/`GetDllDirectory`/`_MEIPASS` reset handling in `src`, `tools` or relevant tests. This is a concrete untested compatibility risk, not a demonstrated failure and not solved by an environment allowlist.

First add an authored helper that records its DLL search state and loads its own harmless side-by-side dependency. Compare source Python, frozen `PatchTrace.exe`, portable extraction and installed package. If reproduced, add a small external-tool spawn adapter inside the existing Windows spawn serialization: snapshot/reset the process DLL directory, create the child, restore in `finally`, preserve containment on every error. All spawn paths touching that process-global state must coordinate; do not reset globally at application startup and hope later Qt/plugin loads survive. Distinguish external tools from any bundled helper requiring the frozen search path. No target PE executes during these checks.

## 7. Reports: preserve local rendering and export boundaries

`reports.py` already renders escaped, self-contained HTML with a restrictive CSP, emits JSON/Markdown, preserves prior differing exports and validates destinations. `tests/test_report_export_backup.py` and `test_export_destination_guard.py` are existing acceptance seams. Report v2 (`report-export-contract-v2.md`) is still a separate opt-in contract; do not silently change v1 output while adding a preview.

`QSaveFile` supplies temporary-write/commit semantics, including remembering short-write failures. Qt warns that direct-write fallback can destroy the original and makes cancellation ineffective [S14]. Reference that failure model for the Qt-free exporter; do not import PySide6 into `reports.py`. Test short writes, failed fsync/replace, an existing locked report, backup collision and destination aliasing. Distinguish replacement atomicity from crash/power-loss durability across all files.

Avoid a new renderer dependency. If an in-app preview later becomes required, Qt's `QTextBrowser` has independent link-navigation controls and a `loadResource` override [S17]. Turning off external links alone is not a complete resource policy: use an application-produced document with explicit allowed resources, intercept links and keep external launch consented. Existing HTML CSP is a browser policy, not proof of identical Qt rich-text behavior. Acceptance should include network-attempt capture, local-file image references, UNC paths, hostile markup/bidi/surrogates and a huge report. PR #176 already corrects disclosure that included code/evidence excerpts can contain paths; preserve this precision.

## 8. Packaging, installer and release acceptance

Main already pins PyInstaller 6.22.3 and NSIS 3.13, builds on Windows, inventories dependencies/files, rejects unused WebEngine/PDF/QML binaries, checks the upb extension, copies notices and runs frozen CLI smoke. NSIS's official download page confirms 3.13 [S18]. `package_windows_installer.py` verifies compiler version, but version output is not an archive/source authenticity check. Reconcile exact compiler download digest and build constraints with the integrator's reproducibility work.

Keep `installer/PatchTrace.nsi`'s `RequestExecutionLevel user`, HKCU registration, current-user shortcuts and zlib compressor. NSIS documents that `RMDir` without `/r` removes only empty directories and explicitly warns against recursive `$INSTDIR` deletion [S19]. Existing generated uninstall manifests correctly express this principle. Required Windows cases: upgrade over prior version; locked running process; interrupted install; app moved after install; Unicode/space/long paths; and user-created project under install directory survives uninstall. Detect remaining obsolete bundled files after upgrade without deleting unrelated files. Current uninstall semantics alone do not prove transactional upgrades.

Keep unsigned prerelease policy until an explicit owner change. Do not revive old signing-price/eligibility/SmartScreen claims from `docs/research/windows-signing-options.md` as established facts. Microsoft's current SignTool docs establish SDK provenance, explicit digest options, RFC3161 timestamping, `/pa` application-policy verification and exit code 2 for warnings [S20]. They do not grant redistribution rights to the Windows SDK tools. Future signing must precede final checksums/inventory/installer packaging; SDK/provider terms, key custody and reproducible artifact identity remain separate from the application's MIT license.

Qt/PySide redistribution remains a component-level review: Qt's LGPL text includes notices, replacement/relinking and related conditions [S21]; PyInstaller's exception allows application bundling subject to dependency licenses and does not exempt copied PyInstaller source modifications [S22]. Current `third_party/notices/README.md` records Qt 6.12.0 `025bdad181de241e81bf853c8a2d7bf3d19261a9`, PySide `f50facb83fc3dc5f3240c854668c7a6dd93871b2`, PyInstaller `ecd7993d65c43b254f4e3f718e36d5b4a70a3ed5`. These are repository provenance records, not newly verified upstream checkouts. NSIS core/zlib, bzip2 and LZMA carry different listed terms [S23]; the existing zlib choice must not be generalized to arbitrary plugins.

## 9. Claude implementation order and completion evidence

1. Reconcile PR #175/#176/#173 and the unmerged dock spec; update only stale statements needed for the selected slice. Keep GUI, backend containment, packaging and tracker ownership explicit.
2. Reproduce frozen external-helper DLL behavior; repair only if the supported frozen path demonstrates the issue. Pair with real Windows descendant cleanup and assignment-denial evidence.
3. Add model-tester coverage and the cross-project late-result/close regression. Surface settings sync failure and stuck-worker diagnostics without changing persistence contracts.
4. Exercise backup closure and crash publication on synthetic local projects; repeat restored-mtime/artifact cases on NTFS. Keep current backup implementation unless a failing test identifies a defect.
5. Complete proposed core dock extraction as small adapter slices under the existing host. Prove keyboard recovery, DPI/monitor restoration and unchanged evidence/presets.
6. Accept the exact downloadable portable and installer assets on clean Windows without Python/Qt installed: launch → local import → comparison → cancel → reopen → backup/restore → export → uninstall, with network disabled and no target execution.

Evidence must identify commit, packaged executable/installer SHA-256, dependency inventory, Windows build, DPI, filesystem, test case and observed result. Missing/skipped native evidence is blocked, not passed. This note ran no tests; its suggestions are not acceptance credit. The current research could not fetch canonical code.qt.io, KDE Invent or SQLite Fossil source views, nor pinned GitHub raw source pages. The following path map preserves useful leads and differentiates API-verified behavior from source-download blockers.

## 10. Primary-source ledger and exact upstream paths

All pages checked 2026-11-04. Mutable documentation is identified as such; no inaccessible tag is represented as a verified checkout.

- **[S1]** [Qt 6.12 QMainWindow](https://doc.qt.io/qt-6/qmainwindow.html). API/security documentation verified. Source origin `code.qt.io/cgit/qt/qtbase.git`, `src/widgets/widgets/qmainwindow.cpp`, `qdockwidget.cpp`, `qmainwindowlayout.cpp`; pinned v6.12.0 source view blocked.
- **[S2]** [Qt 6.12 QSettings](https://doc.qt.io/qt-6/qsettings.html). Source lead `src/corelib/io/qsettings.cpp`; documentation verified, not source body.
- **[S3]** [Qt 6.12 model thread safety](https://doc.qt.io/qt-6/qabstractitemmodel.html#thread-safety). Source lead `src/corelib/itemmodels/qabstractitemmodel.cpp`.
- **[S4]** [Qt 6.12 model tester](https://doc.qt.io/qt-6/qabstractitemmodeltester.html). Exact implementation lead `src/testlib/qabstractitemmodeltester.cpp`; docs establish test scope.
- **[S5]** [Qt 6.12 QThread](https://doc.qt.io/qt-6/qthread.html). Source lead `src/corelib/thread/qthread.cpp`; reference lifecycle semantics only.
- **[S6]** [KDE KMainWindow API](https://api.kde.org/kmainwindow.html), mutable KF6 documentation, verified. Canonical origin [KDE Invent](https://invent.kde.org/frameworks/kxmlgui), exact `src/kmainwindow.cpp`, `src/kmainwindow.h`; v6.20.0 raw fetch blocked. No source copying authorized by this research; exact file SPDX must be fetched before copying.
- **[S7]** [SQLite backup API](https://sqlite.org/backup.html) and [C API lifecycle](https://www.sqlite.org/c3ref/backup_finish.html). Canonical Fossil `sqlite.org/src`, exact `src/backup.c`, `test/backup.test`, `test/backup2.test`; attempted version-3.51.3 source retrieval blocked. Behavior verified in primary docs, source revision unverified.
- **[S8]** [SQLite atomic commit](https://sqlite.org/atomiccommit.html). Source leads `src/pager.c`, `test/crash.test`; adapt fault boundaries, not implementation code.
- **[S9]** [SQLite WAL](https://sqlite.org/wal.html), page updated 2026-08-25; documents fixed release/backports and applicability. Exact source lead `src/wal.c`.
- **[S10]** [SQLite copyright](https://sqlite.org/copyright.html), including deliverable/build-script distinction.
- **[S11]** [Microsoft Job Objects](https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects) and [AssignProcessToJobObject](https://learn.microsoft.com/en-us/windows/win32/api/jobapi2/nf-jobapi2-assignprocesstojobobject). Win32 platform contract; no open-source library adoption needed.
- **[S12]** [Microsoft extended job limits](https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information). Verify process versus job limit labels against API members.
- **[S13]** [PyInstaller 6.22.3 external-program pitfalls](https://pyinstaller.org/en/stable/common-issues-and-pitfalls.html#launching-external-programs-from-the-frozen-application). Documentation verified; exact source leads `bootloader/src/pyi_main.c`, `bootloader/src/pyi_utils_win32.c`, `PyInstaller/hooks/rthooks/pyi_rth_pyside6.py`. Tagged source fetch blocked.
- **[S14]** [Qt 6.12 QSaveFile](https://doc.qt.io/qt-6/qsavefile.html). Exact code path `src/corelib/io/qsavefile.cpp`; indexed dev header reports `LicenseRef-Qt-Commercial OR LGPL-3.0-only OR GPL-2.0-only OR GPL-3.0-only`. Tag body not freshly verified; do not copy under an assumed permissive license.
- **[S15]** [ADS upstream README](https://github.com/githubuser0xFFFF/Qt-Advanced-Docking-System), mutable master/indexed source, checked for LGPLv2.1 and Python binding separation. Leads `src/DockManager.cpp`, `src/DockContainerWidget.cpp`, `gnu-lgpl-v2.1.md`. No pinned release/license-file body retrieved; **defer**, not approved vendoring.
- **[S16]** [KDDockWidgets upstream license](https://github.com/KDAB/KDDockWidgets/blob/main/LICENSE.txt), indexed main text verified, no immutable revision established. Leads `src/core/LayoutSaver.cpp`, `LICENSES/GPL-2.0-only.txt`, `LICENSES/GPL-3.0-only.txt`. **Defer** dependency and code copying.
- **[S17]** [Qt 6.12 QTextBrowser](https://doc.qt.io/qt-6/qtextbrowser.html). Source lead `src/widgets/widgets/qtextbrowser.cpp`; docs verify separate navigation/resource hooks.
- **[S18]** [NSIS official release page](https://nsis.sourceforge.io/Download): 3.13, 2026-09-27. SourceForge source origin; exact source leads `Source/exehead/exec.c`, `Examples/example1.nsi`, `Contrib/Modern UI 2/MUI2.nsh`; source body not retrieved.
- **[S19]** [NSIS scripting reference](https://nsis.sourceforge.io/Docs/Chapter4.html#rmdir). Exact documentation source lead `Docs/src/basic.but`; verified command semantics.
- **[S20]** [Microsoft SignTool](https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool), platform SDK documentation; no SDK redistribution permission inferred.
- **[S21]** [Qt LGPL terms](https://doc.qt.io/qt-6/lgpl.html) and [Qt for Python licenses](https://doc.qt.io/qtforpython-6/licenses.html). Treat source code, examples, documentation and generated wheel components separately.
- **[S22]** [PyInstaller 6.22.3 license](https://pyinstaller.org/en/stable/license.html); exact distribution `COPYING.txt`, already preserved in repository notices. Build exception is component-specific.
- **[S23]** [NSIS license inventory](https://nsis.sourceforge.io/License), checked against local `third_party/notices/nsis-3.13/COPYING`; core/zlib, bzip2 and LZMA terms are separate. No plugins or SDKs receive an implied exception.

[S1]: https://doc.qt.io/qt-6/qmainwindow.html
[S2]: https://doc.qt.io/qt-6/qsettings.html
[S3]: https://doc.qt.io/qt-6/qabstractitemmodel.html#thread-safety
[S4]: https://doc.qt.io/qt-6/qabstractitemmodeltester.html
[S5]: https://doc.qt.io/qt-6/qthread.html
[S6]: https://api.kde.org/kmainwindow.html
[S7]: https://sqlite.org/backup.html
[S8]: https://sqlite.org/atomiccommit.html
[S9]: https://sqlite.org/wal.html
[S10]: https://sqlite.org/copyright.html
[S11]: https://learn.microsoft.com/en-us/windows/win32/procthread/job-objects
[S12]: https://learn.microsoft.com/en-us/windows/win32/api/winnt/ns-winnt-jobobject_extended_limit_information
[S13]: https://pyinstaller.org/en/stable/common-issues-and-pitfalls.html#launching-external-programs-from-the-frozen-application
[S14]: https://doc.qt.io/qt-6/qsavefile.html
[S15]: https://github.com/githubuser0xFFFF/Qt-Advanced-Docking-System
[S16]: https://github.com/KDAB/KDDockWidgets/blob/main/LICENSE.txt
[S17]: https://doc.qt.io/qt-6/qtextbrowser.html
[S18]: https://nsis.sourceforge.io/Download
[S19]: https://nsis.sourceforge.io/Docs/Chapter4.html#rmdir
[S20]: https://learn.microsoft.com/en-us/windows/win32/seccrypto/signtool
[S21]: https://doc.qt.io/qt-6/lgpl.html
[S22]: https://pyinstaller.org/en/stable/license.html
[S23]: https://nsis.sourceforge.io/License
