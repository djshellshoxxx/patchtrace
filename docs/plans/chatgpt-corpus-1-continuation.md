# PROMPT 2 corpus batch 1: candidate admission and continuation

Status: authoring only. No code, shell commands, compiler, target image, test, schema validator or corpus checker was executed. No tests are claimed to pass.

## Scope and branch boundary

This batch starts at `claude/instance-d-gui` commit `8af0e0effa7628f2bdf1ed8afc6d21f30e816924` and writes only new files on `chatgpt/corpus-1`. It supplies 24 project entries for PROMPT 2 group A, plus this plan, reaching the user's 25-file conversation limit. Groups B through F are not supplied. Six further group-A projects remain.

The base contains 16 recipe projects in `tools/calibration/tier_r/catalogue/recipes.json`: zlib, libpng, lz4, zstd, lua, expat, pcre2, cJSON, mbedtls, brotli, miniz, jansson, libyaml, libdeflate, stb and c-ares. The prompt's count of 13 is stale relative to this observed base. All 24 candidates here are outside those 16. Some may already occur in found-case metadata; a found case is not a working build recipe.

## Files and purpose

- `tools/calibration/catalogue/yyjson-candidate.json`: yyjson candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/jsoncpp-candidate.json`: jsoncpp candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/tinyxml2-candidate.json`: tinyxml2 candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/pugixml-candidate.json`: pugixml candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/inih-candidate.json`: inih candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/parson-candidate.json`: parson candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/libspng-candidate.json`: libspng candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/qoi-candidate.json`: qoi candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/monocypher-candidate.json`: monocypher candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/libtommath-candidate.json`: libtommath candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/libtomcrypt-candidate.json`: libtomcrypt candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/nghttp2-candidate.json`: nghttp2 candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/llhttp-candidate.json`: llhttp candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/http-parser-candidate.json`: http-parser candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/jsmn-candidate.json`: jsmn candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/libvterm-candidate.json`: libvterm candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/tinycbor-candidate.json`: tinycbor candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/hiredis-candidate.json`: hiredis candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/nanopb-candidate.json`: nanopb candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/protobuf-c-candidate.json`: protobuf-c candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/libogg-candidate.json`: libogg candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/speex-candidate.json`: speex candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/snappy-candidate.json`: snappy candidate recipe, licence evidence, compiler argv proposals and admission gates.
- `tools/calibration/catalogue/libhydrogen-candidate.json`: libhydrogen candidate recipe, licence evidence, compiler argv proposals and admission gates.

## Candidate format and location

The JSON objects are human-reviewable, machine-readable proposal data under the explicitly requested `tools/calibration/catalogue/` path. Their keys are AUTHOR-DEFINED for this batch, not claims about existing PatchTrace fields. They are deliberately not `tier-r-recipes/1`, `tier-r-recipe/1`, `case-card/1` or `known-answer-labels/1` documents. They are not registered with the production recipe loader, and no active catalogue is changed.

The active base uses `tools/calibration/tier_r/catalogue/recipes.d/` and `releases.d/`. That loader boundary matters: an unverified source path or missing dependency must not become executable build instructions merely because a candidate file was added. Do not copy the proposal object wholesale into an active recipe.

Each object includes its name, upstream, selected SPDX licence, suitability, proposed scope and build system, configure policy, compiler invocation previews, proposed artifacts, unmeasured size range, determinism risks, exact admission blockers and verification instructions. An upstream default-branch licence was fetched for each admitted candidate. Its Git blob SHA is recorded as a Git blob SHA, never presented as a commit pin or a licence SHA-256. Default-branch licence evidence does not verify historical pins or every source file.

## Conflicts resolved without changing existing files

1. SPEC-32 section 2 prohibits executing upstream configure, CMake, make, Python and Tcl scripts. Therefore configure commands are explicitly absent and compiler-only plans are provided. A mention of an upstream build system describes a candidate fact, not permission to run it.
2. Several candidate projects are C++. The current Recipe flag allow-list and the C source locator do not establish C++ build/label support. The C++ entries are blocked for production admission until that support is verified; clang-on-Linux previews answer only compilation feasibility.
3. Source trees are fetched read-only. Proposed wrapper or config writes must live in a private build overlay, never modify the fetched checkout.
4. libcsv was excluded after its retrieved COPYING identified LGPL. utf8proc was excluded because its bundled Unicode data has additional terms beyond this request's elected licence list. linenoise was replaced because its terminal implementation is an unnecessary portability complication for a PE-first corpus. These are exclusions from this batch, not alterations to any upstream project.
5. No CLAUDE worker co-author trailer is added: no Claude worker authored these files. The user's direct GitHub/branch instructions override the generic worker brief's local-only/no-push instruction. Shared files, including modules.md, todo and qa, remain untouched under the user's new-files-only rule.

## Admission sequence

1. Pick the candidate's precise scope before searching release or security-fix history. Subset recipes for LibTomCrypt, nghttp2 and hiredis do not establish coverage of the full project.
2. After operation-specific network consent, resolve each chosen ref to a real 40-hex commit and pin it. Read every compiled file's notices and relevant generated-data notices, elect a permitted licence, and compute the licence file SHA-256 at that commit. Reject unknown or non-permissive scope.
3. Freeze the source/header list and dependency commits. Resolve globs against the pinned manifest, sort exact paths and include the resulting list in the recipe digest. Confirm that each source path exists. Read build manifests as text; never execute them.
4. Supply complete, reviewed literal config/header writes where needed. If generated inputs are absent from the selected upstream snapshot, return BLOCKED. Do not run a source generator to make the build succeed.
5. Materialize compile/link argv from the candidate preview only after review. Resolve tools to absolute approved executables, use shell=False, private paths, minimal environment and SPEC-32 limits. Record the exact compiler, linker, runtime/sysroot and LLVM inspector versions. The preview's generic executable names are not runner-approved paths.
6. Check language support, export macros and link closure. Compile each source to a unique object, then link in sorted source order. In subset recipes, either complete the documented dependency closure or retain BLOCKED; never describe a partial subset as a complete project.
7. Inspect the resulting debug PE for machine x64 and valid function ranges. Strip a copy for engines and assert code/RVA preservation. Keep all images and debug material outside git. Native ELF compatibility checks are not PE corpus evidence.
8. Run identical-source A/A twice in distinct directories. Record byte equality or exact differing sections. Failure is evidence to report, never an instruction to normalize away arbitrary bytes.
9. Only after admission, create new active-recipe files using exact fields from the current contracts. Existing `Recipe` has `copy_files`, not the shorthand `copy` appearing in some prose. Do not add proposal metadata to a strict persisted contract.
10. Run later focused checks and record actual statuses. Proposed command strings below were not run here and must be checked against the then-current CLI before use:

```text
python -m tools.calibration.tier_r catalogue-check
python tools/corpus_check.py all
python -m tools.calibration.corpus guard
```

No full-suite result is implied. The user prohibited code execution in this authoring conversation.

## Label and evaluation constraints

No label is inferred from a CVE title, function name, compiler success, an LLM statement or a source diff alone. Use SPEC-32's debug inventory, source/body decision table and disagreement handling. Ambiguous spans, inlining, ICF and induced caller changes stay ambiguous when the contract requires it. Never execute a built target to resolve ambiguity.

All releases, fixes, A/A pairs, nuisance builds and mutants derived from one upstream stay in its lineage. Forks, renamed projects, embedded code and dependencies require ancestry and body-identity audits before split assignment. Shared origin counts once. Keep engine-native metrics separate; never average engine scores. Unknown is not a negative vote, and conflicting evidence stays available.

SPEC-28's current amended protocol assigns roles by lineage hash and requires all related variants to inherit the role. The research note suggests additional project/time controls. A later group-E protocol must explain the difference and offer a preregistered temporal diagnostic without silently changing existing role assignment or splitting a project across locked roles.

Tier R supports experimental synthetic/open-source evaluation only. It does not establish accuracy on Windows system binaries and does not open any probability or vulnerability-confidence display gate. Microsoft binaries, PDBs and Winbindex-derived labels remain excluded from git and from this batch.

## Continuation queue

Next: group A entries 25 through 30, then group B for all 30 projects, then groups C, D, E and F.

Candidate names for the remaining six are mpack, tlsf, minIni, libbase64, libb64 and simdjson. Every upstream URL, licence, source list, build command, release and CVE fact for those six is UNVERIFIED in this plan. They are research leads, not admitted project entries. Replace a lead if its permitted-licence scope, dependency size, compiler feasibility or history cannot satisfy the task.

Group B requires three to six release pairs and two to five CVE-fix cases per selected project. No release ref, SHA, CVE id, affected file or function is supplied in this batch. Some small libraries may have fewer than two public CVE cases; the next worker must establish that fact and report the shortfall or propose a replacement with evidence. Never manufacture a CVE id or duplicate one security event to satisfy the count. An UNVERIFIED marker permits honest uncertainty, not invented hashes. For each proposed fix, record the upstream advisory or CVE List evidence, exact fixing commit and chosen parent, patch scope, named functions and an exact git/API verification command. Merge commits need explicit parent selection. Release ordering needs ancestry/release-date checks, not lexical tag sorting.

Group C requires 40 complete operator definitions, each with authored before/after C, labels, compile-safety preconditions and nuisance non-change rules. Reconcile the existing 30 operator ids in the base contract before proposing new ids. Do not overwrite the registry.

Group D requires reproducible nuisance construction, including compiler versions, optimization, link order, timestamps, LTO and PGO. PGO cannot be produced here by running a target: require a pinned previously obtained profile with provenance or report BLOCKED. Never make target execution an implicit corpus step.

Group E requires JSON Schema for cards, function labels, provenance, label-quality confidence and grouped split assignment, plus a worked leakage-control example. The existing strict contracts have no generic label-confidence float; specify an additive proposal separately, use categorical provenance quality until verified, and never call it vulnerability confidence. Keep existing schema generation unchanged.

Group F requires ten fully specified adversarial label-noise cases, evaluator outcomes, denominator/abstention treatment and concrete oracle checks. Unknown truth must not become a negative label.

## Not verified

No candidate source commit, release ordering, CVE association, affected function, licence at a historical pin, generated config header, compiler flag, source-list completeness, dependency closure, size estimate, MinGW build, native clang build, Windows build, PE validity, debug inventory, stripped-code/RVA preservation, A/A determinism, corpus check, JSON Schema validation, lint or test result has been verified by execution in this task. The recorded default-branch licence text and blob identities are read evidence only. Network-enabled source/tag/advisory verification and all builds/checks remain later work.

No existing files were changed. No -2 filename was needed against the captured base tree; GitHub's create-file operation must still reject any path that unexpectedly exists.
