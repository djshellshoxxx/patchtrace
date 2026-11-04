# Additional PatchTrace research and Claude handoff

**Date:** 2026-11-03 America/Vancouver (2026-11-04 UTC). **Scope:** source research, current implementation/ownership reconciliation and concrete suggestions for unfinished features. **Baseline inspected:** main `b77d84e5decf736b031f0a24094001274de41178`. This dossier changes documentation only; proposed experiments are not completed acceptance.

## Start here

Claude should read [01: current state and gaps](01-current-state-and-research-gaps.md), then [06: action plan and reuse register](06-claude-action-plan-and-reuse-register.md), then the relevant technical note. The action plan contains **15 bounded work packets** with existing code seams, upstream sources, owners, dependencies and completion evidence. Read the repository's [engineering policy](../../../AGENTS.md), [module map](../../modules.md) and affected specification before implementing a packet. Research recommendations do not amend those contracts.

| Note | What it contributes |
| --- | --- |
| [01 — Current state and research gaps](01-current-state-and-research-gaps.md) | Main versus active PRs, historical R1–R8 research, stale claims and unfinished acceptance. |
| [02 — Engine and runtime reuse](02-engine-runtime-reuse.md) | Ghidra/PyGhidra lifecycle, BinExport mutation/provenance, Rizin producer qualification, diffoscope reports, LLVM and Sourceware references. |
| [03 — Advisory metadata and provenance](03-metadata-provenance-reuse.md) | CSAF conformance, verified source/license pins, offline verification observations, product identifiers and independent PE/PDB checks. |
| [04 — Desktop, persistence and release](04-desktop-persistence-release-reuse.md) | Native Qt seams, settings/shutdown, complete-project backup, frozen Windows child launch, reports and exact installer acceptance. |
| [05 — Corpus, calibration and reproducibility](05-corpus-calibration-reproducibility.md) | Non-GitHub source admission, reprotest/LLVM reuse, existing calibration oracles, lineage and retained-evidence lifecycle. |
| [06 — Claude action plan and reuse register](06-claude-action-plan-and-reuse-register.md) | Prioritized P01–P15 implementation packets and a compact 16-row source/license/reuse register. |
| [Repository snapshot](repository-snapshot.json) | Machine-readable open-PR metadata and immutable heads observed at 2026-11-04 02:27:24 UTC; no CI or approval claims. |

## Decisions that materially change the next work

### 1. Extend the implementation that exists

Main already has supervised native processes, Ghidra extraction, strict secondary-engine parsing, a native MSRC adapter, provenance/conflict handling, native Qt docks/tasks, SQLite backup, a corpus factory and calibration reference tests. Active PRs add more. Several older research/specification statements describe an earlier tree. Refiling those features as wholly missing would create conflicting implementations.

The new notes identify narrower gaps: completion receipts for retained analysis, mutation-isolated export, independent identity checks, full-project backup closure, source-origin contracts and platform qualification. Earlier matching/semantic/calibration research remains relevant; its historical experiments are not new acceptance for this main revision. See [01](01-current-state-and-research-gaps.md).

### 2. Qualify frozen Windows child launch before adding a workaround

PyInstaller's documented DLL-directory changes can affect external child processes independently of PATH. Static inspection found existing Windows spawn serialization but no corresponding DLL-directory reset handling. This is an **untested compatibility concern**, not a reproduced PatchTrace failure. P01 specifies an authored helper experiment across source, portable and installed execution; a narrowly coordinated repair is conditional on that evidence. Preserve existing Job Object containment. See [04 §6](04-desktop-persistence-release-reuse.md#6-windows-native-subprocess-containment-and-frozen-launch).

### 3. Keep raw artifact identity, structural identity and completion separate

Pinned BinExport source writes a timestamp and can promote undefined functions while exporting. A readable/analyzed GZF does not itself record which requested extraction stages completed. The useful reuse is knowledge of upstream APIs and producer behavior: retain authoritative originals, export private copies, and bind input/output/version/options to completion observations. Do not silently normalize away raw bytes or infer completion from file existence. These are P02–P03, detailed in [02](02-engine-runtime-reuse.md).

### 4. Use independent CSAF validation as development tooling

PatchTrace openly implements a subset of mandatory checks. P05 compares that declared coverage with a pinned Secvisogram schema/mandatory test set using synthetic or permitted fixtures. Its full preset includes network tests; deny network and fail unexpected requests. Keep Node outside the desktop runtime. Source inspection also corrected a stale license catalog: the inspected validator is Apache-2.0, not the catalog's MIT label. The exact commit, license hash and contrary catalog are retained in [03](03-metadata-provenance-reuse.md).

### 5. Make beyond-GitHub research usable by the corpus

The recipe schema hard-codes a GitHub-shaped URL, while the fetcher separately defaults to GitHub and a two-component repository path. An allowlist-only change is insufficient for nested GitLab repositories, Fossil or archives. P11 first specifies a narrow typed origin preserving exact host, immutable identity, selected-file/license evidence and existing admission limits. Archives and Fossil are separate future cases, not strings coerced into Git commit fields. See [05 §4](05-corpus-calibration-reproducibility.md#4-non-github-corpus-origins-the-concrete-integration-barrier).

### 6. Verify the complete evidence lifecycle

Database consistency alone cannot prove that all referenced sidecars, raw outputs, reviews and exports are present in a restored project. P07 and P10 extend existing backup/replay machinery with bounded publication, interruption and reopen checks. The notes distinguish `ProjectStore` from the KB workspace store, which already enables WAL; they do not assert that a documented SQLite issue affects this installation. Similarly, existing PDB mismatch and LLVM symbol tests are credited; the new identity proposal independently checks LLVM GUID/age. See [03](03-metadata-provenance-reuse.md), [04](04-desktop-persistence-release-reuse.md) and [05](05-corpus-calibration-reproducibility.md).

## Research outside GitHub

This pass did more than collect alternative hosting names. It inspected **versioned Debian source** for diffoscope/reprotest and **MetaCPAN release source** for an independent CSAF implementation. Sourceware supplied libabigail contracts/API source and Binutils documentation. Qt, KDE, SQLite and SourceForge supplied official API, lifecycle, licensing or packaging evidence. The technical notes identify exact files and inspected versions where available.

| Origin | Useful material | Evidence boundary |
| --- | --- | --- |
| Debian Sources / Salsa | diffoscope report model and command wrapper; reprotest environment-variation design | Debian package source inspected; some canonical Salsa views inaccessible. GPL/file-level terms retained; no wholesale wrapper adoption. |
| CPAN / MetaCPAN | CSAF numbered mandatory checks and downloader cases | Release 0.26 inspected; distribution/POD license discrepancy recorded. Reference cases without shipping Perl. |
| Sourceware | libabigail ABI/status/suppression contracts; static Binutils metadata controls | API/doc observations; no current Binutils distribution or libabigail executable qualification. ELF integration deferred. |
| Qt / KDE Invent | Native dock/model/settings and session/lifecycle APIs | Official documentation inspected; some canonical implementation views unavailable. Prefer existing bindings over copying source. |
| SQLite / Fossil | Backup, commit, WAL and license contracts | Official documentation inspected; no newly verified Fossil source checkout or project-specific WAL defect reproduction. |
| SourceForge / NSIS | Existing installer semantics and component licenses | Official release/manual/license material; exact distributed compiler/plugin closure remains release work. |
| Heptapod / Codeberg | Additional source discovery leads | Access denied or blocked; not promoted into verified code, license or compatibility claims. |

Detailed source ledgers distinguish **source-inspected candidates**, **documentation-only references** and **blocked leads**. API use, development tooling, design adaptation and source copying are different decisions. PatchTrace's MIT license does not replace component, fixture or advisory-data terms; process separation is not a general license exemption.

## Coordination and verification

The final metadata query returned 59 open PRs; an independent repository-wide `is:pr is:open` search returned the same PR numbers. The initial query returned 58 before #177 was opened. Main remained at the inspected SHA. Key active heads are pinned in [01](01-current-state-and-research-gaps.md) and the [snapshot](repository-snapshot.json). This is a point-in-time inventory, not a claim that every PR or check was reviewed in full.

Preserve ownership of #173 tracker/spec repair, #174 native gates/Rizin, #175 Windows identity, #176 investigation/replay/GUI and #177 parallel QA. Keep #170/#171 automation separate. `tasks/todo.md` is invalid UTF-8 at the inspected baseline and is already owned by repair work; this dossier does not overwrite it or `docs/qa.md`. Implementation owners can reconcile the packets into the repaired tracker afterward.

Four research streams were followed by independent cross-review. Corrections incorporated here include the two SQLite stores, existing PDB tests, networked CSAF presets, proposed versus existing redirect policy, and LLVM's shared COFF JSON writer versus unqualified output schema. The reviews were source/document checks, not native runs.

No target binaries, engines, installers or calibration experiments were executed for this pass. No application code, dependencies, workflow or persisted schema changed. The handoff requires fresh compatibility, native Windows, statistical and distribution evidence where indicated. A finished research packet is not a finished product feature.
