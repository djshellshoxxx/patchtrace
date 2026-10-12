# BinExport and BinDiff

Research date: 2026-10-12.
Verification labels:
- **[src]**: I read the source or docs at the pinned commit.
- **[run]**: I ran the tool.
- **[inf]**: inference that I did not verify.

I ran neither BinExport nor BinDiff here, because there was no Ghidra install and I did not install the BinDiff package. All facts below come from source.

Sources pinned:
- https://github.com/google/binexport @ `2bff7af27af206354b2a90a9de566dc6bbae3e1b` (main, 2026-10-09)
- https://github.com/google/bindiff @ `13c437afa0740bd704cf396e3de3eb8d1a471ead` (main, 2026-09-18)

## Releases [src: GitHub releases API/pages]
| Project | Latest release | Date | Assets |
|---|---|---|---|
| BinExport | `v12-20240417-ghidra_11.0.3` ("BinExport 12, Updated for Ghidra 11.0.3") | 2024-04-17 | `BinExport-Linux.zip`, `BinExport-macOS.zip`, `BinExport-Windows.zip`, `BinExport_Ghidra-Java.zip`. The release notes say these are **not code-signed**. |
| BinDiff | `v8` ("BinDiff 8 Open Source") | 2023-09-25 | `bindiff8.msi`, `BinDiff8.dmg`, `bindiff_8_amd64.deb` (+ `.asc`). Bundles BinExport `v12-20230925-bindiff8`. |

- **Newer main branches have no release:**
  - BinDiff main has commits through 2026-09.
  - BinExport main has "Ghidra: Improve compatibility with version 12.x" (`8cec8e2`) and a flow-graph fix (`b56dea7`).
  - Any Ghidra 12 support therefore needs a **source build** [src: git log].
- **Licence:** both projects are Apache-2.0 (`LICENSE`) [src].
  - The BinDiff Java UI ships a bundled JRE in the packages [inf from v7 notes "Shipping with updated Java runtime"]. Check third-party notices before redistributing the packages.

## BinExport2 protobuf (`binexport2.proto`, proto2 syntax) [src]
- Top level is `message BinExport2`. The format is heavily **index-deduplicated**: instructions, basic blocks, expressions and so on are stored once and referenced by index.

| Field # | Field | Type |
|---|---|---|
| 1 | `meta_information` | `Meta{ executable_name=1 (basename incl. extension), executable_id=2 (often SHA-256 hex), architecture_name=3 (e.g. "x86-64"), timestamp=4 (unix int64) }`. Field 5 is reserved. |
| 2 | `expression[]` | `{type=1 enum (default IMMEDIATE_INT), symbol=2, immediate=3 uint64, parent_index=4, is_relocation=5}` |
| 3 | `operand[]` | `{expression_index[]=1}` |
| 4 | `mnemonic[]` | `{name=1}` |
| 5 | `instruction[]` | `{address=1 uint64 (omitted when it follows the previous instruction), call_target[]=2, mnemonic_index=3, operand_index[]=4, raw_bytes=5, comment_index[]=6}` |
| 6 | `basic_block[]` | `{instruction_index[]=1 of IndexRange{begin_index=1,end_index=2 (exclusive; absent = begin+1)}}` |
| 7 | `flow_graph[]` | `{basic_block_index[]=1, entry_basic_block_index=3, edge[]=2 {source_basic_block_index, target_basic_block_index, type (CONDITION_TRUE/FALSE/UNCONDITIONAL/SWITCH), is_back_edge}}` |
| 8 | `call_graph` | `{vertex[]=1 {address=1, type=2 (NORMAL=0, LIBRARY=1, IMPORTED=2, THUNK=3, INVALID=4), mangled_name=3, demangled_name=4, library_index=5, module_index=6}, edge[]=2 {source_vertex_index, target_vertex_index}}`. Vertices **must be sorted by address**. |
| 9 | `string_table[]` | string |
| 10 | `address_comment[]` | deprecated |
| 11 | `string_reference[]` | `Reference{instruction_index, instruction_operand_index, operand_expression_index, string_table_index}` |
| 12 | `expression_substitution[]` | Reference |
| 13 | `section[]` | `{address, size, flag_r, flag_w, flag_x}` |
| 14 | `library[]` | `{is_static, load_address, name}` |
| 15 | `data_reference[]` | `{instruction_index, address}` |
| 16 | `module[]` | `{name}` |
| 17 | `comment[]` | `{instruction_index, instruction_operand_index, operand_expression_index, string_table_index, repeatable, type}` |
| 93992622 | `md_index[]` | `{address, md_index double}` |

- The comment fields above are abbreviated. Confirm enum value lists against the proto (L93-432).

## Ghidra exporter (`java/`)
- **Build:** README says OpenJDK 21+, **Ghidra 11.0.3**, Gradle 8.7+, and protobuf 3.25.0.
  - `build.gradle` detects the protobuf version from `GHIDRA_INSTALL_DIR/gradle.properties` and accepts an `-PghidraProtobufVersion` override.
  - Output: `dist/ghidra_<ver>_PUBLIC_<YYYYMMDD>_BinExport.zip`.
  - Install via File → Install Extensions [src `java/README.md`].
  - **Extension zips only load into the matching Ghidra version.** The released zip targets 11.0.3. Anything else (11.x later, 12.x) must be built from main against the target Ghidra [inf, standard Ghidra extension behavior].
- **Two entry points:**
  - `BinExportExporter` (extends `ghidra.app.util.exporter.Exporter`) writes files with the extension `BinExport`. It is GUI File → Export… → "Binary BinExport (v2) for BinDiff".
  - Script `java/ghidra_scripts/BinExport.java` (a GhidraScript):
    1. `askFile("Choose export file","Export")`
    2. `askChoices("Choose options","IDA Pro Compatibility",[ "Subtract Imagebase", "Remap mnemonics", "Prepend Namespace to Function Names" ])`
    3. Exports `currentProgram`, then prints "Export successful" or "Export failed" (printerr). It does **not** throw on failure, so check the file.
- **Headless:**
  - Ghidra's `GhidraScript` consumes positional script arguments for `ask*` calls in order [src: Ghidra master `GhidraScript.java` L759-769, L1942-1970]. For `askChoices`, the value is split on `;` (L1924).
  - Expected invocation [inf, not run]:
    ```
    analyzeHeadless <projDir> <projName> -import <bin> -scriptPath <ext>/ghidra_scripts \
      -postScript BinExport.java /out/<name>.BinExport "Subtract Imagebase;Remap mnemonics"
    ```
    (Or use `-process` with an already analyzed program.)
  - Whether an empty choice list is accepted headless is unverified, so test it. Passing explicit choices is safer.
  - The extension must be installed into `<ghidra>/Ghidra/Extensions` for the classes to be on the path.
  - Ghidriff/pyghidra users could instead call `BinExport2Builder` directly [inf].
- **Feature gap:** the Ghidra export has "No operand trees" compared with IDA [src README table].
- **Field mapping:**
  - `executable_id` = `program.getExecutableSHA256()`
  - `executable_name` = the program's executable name [src `BinExport2Builder.java` L164]

## BinDiff CLI (`main_portable.cc`) [src]
```
bindiff [--primary=]<a.BinExport> [--secondary=]<b.BinExport> [--output_dir=DIR] [--output_format=bin|log|bin,log|none]
        [--config=FILE] [--nologo] [--md_index] [--ls] [--print_config] [--ui]
```
- **Arguments:** named flags beat positional ones. More than two positionals gives the error "Extra arguments on command line". A missing primary gives "Need primary input (--primary)".
- **`--output_format`:**
  - Default `bin`. Case-insensitive values are `bin`/`binary` and `log`.
  - `none` writes nothing (similarity only), and must be the only value given.
  - Any other value gives "Invalid output format: X".
- **`--output_dir`:**
  - Defaults to the current directory, or to the input directory in batch mode.
  - It must be an existing directory, otherwise "Output parameter (--output_dir) must be a writable directory".
- **Output file:**
  - `<out>/<primary basename without ext>_vs_<secondary basename without ext>.BinDiff`, or `.results` for the log format.
  - The name is truncated if it is too long (`GetTruncatedFilename`).
  - The basename comes from the **input path**, not `Meta.executable_name` (`CallGraph::GetFilename`).
- **Stdout** includes:
  - `matched: N of P/S (primary/secondary, p/s non-library)`
  - `Similarity: X% (Confidence: Y%)`
- **Exit codes:**
  - `0` = success, which also covers printing help when nothing was done.
  - `1` (`EXIT_FAILURE`) = any error status, printed as `Error: <msg>`.
  - One path calls `exit(1)` directly (L485).
  - There is **no** "files differ" exit code.
- **Batch mode:** if the primary is a directory, BinDiff diffs all ordered pairs of `.BinExport` files in it (see nway.md).

### `.BinDiff` SQLite schema (`database_writer.cc` L241-317) [src]
```sql
basicblockalgorithm(id SMALLINT PRIMARY KEY, name TEXT)
functionalgorithm(id SMALLINT PRIMARY KEY, name TEXT)
file(id INT, filename TEXT, exefilename TEXT, hash CHARACTER(40), functions INT, libfunctions INT, calls INT,
     basicblocks INT, libbasicblocks INT, edges INT, libedges INT, instructions INT, libinstructions INT)
metadata(version TEXT, file1 INT, file2 INT, description TEXT, created DATE, modified DATE,
         similarity DOUBLE PRECISION, confidence DOUBLE PRECISION, FOREIGN KEY(file1/file2) REFERENCES file(id))
function(id INT PRIMARY KEY, address1 BIGINT, name1 TEXT, address2 BIGINT, name2 TEXT,
         similarity DOUBLE PRECISION, confidence DOUBLE PRECISION, flags INTEGER, algorithm SMALLINT,
         evaluate BOOLEAN, commentsported BOOLEAN, basicblocks INTEGER, edges INTEGER, instructions INTEGER,
         UNIQUE(address1,address2), FOREIGN KEY(algorithm) REFERENCES functionalgorithm(id))
basicblock(id INT PRIMARY KEY, functionid INT, address1 BIGINT, address2 BIGINT, algorithm SMALLINT, evaluate BOOLEAN)
instruction(basicblockid INT, address1 BIGINT, address2 BIGINT)
```
- `commentsported(address BIGINT PRIMARY KEY)` may also be created by the UI or plugins.
- **Row values:**
  - `file` rows: id 1 = primary, id 2 = secondary.
  - `file.hash` = `Meta.executable_id`. The column is declared `CHARACTER(40)`, but SQLite does not enforce the length, so a 64-character SHA-256 fits.
  - `exefilename` = `Meta.executable_name`.
  - `metadata.version` = `"BinDiff " + kBinDiffDetailedVersion`. `created`/`modified` = `DATETIME('NOW')`.
- **`functionalgorithm` ids:**
  - Assigned sequentially from 1 in `GetDefaultMatchingSteps()` order, followed by `"function: call reference matching"`, then `"function: manual"`.
  - Names look like `"function: hash matching"`, `"function: name hash matching"`, `"function: prime signature matching"`, `"function: MD index matching (flowgraph MD index, top down)"`, `"function: loop count matching"`, `"function: string references"`, `"function: instruction count"`, `"function: address sequence"`, `"function: call sequence matching(...)"`, `"function: edges flowgraph MD index"`, `"function: edges callgraph MD index"`, `"function: edges proximity MD index"`, `"function: relaxed MD index matching"`.
  - **Always join by name. Never hard-code ids**: they depend on config.
- **`function.flags`** is a bitmask (`change_classifier.h`):
  - STRUCTURAL = 1 (G)
  - INSTRUCTIONS = 2 (I)
  - OPERANDS = 4 (O)
  - BRANCHINVERSION = 8 (J)
  - ENTRYPOINT = 16 (E)
  - LOOPS = 32 (L)
  - CALLS = 64 (C)
- **Unmatched functions are not stored.** Compute them as the call-graph vertices absent from `function.address1`/`address2`.

## Validating genuine files (vs. lookalikes)
- **.BinExport [src + inf]:**
  - There is **no magic number**: the file is a bare serialized proto2 `BinExport2` message. BinDiff only checks that `ParseFromIstream` succeeds (L339) and the extension `.BinExport`, case-insensitive.
  - Recommended validator:
    1. Parse with protobuf (generate Python bindings from the pinned `binexport2.proto`, Apache-2.0).
    2. Require `meta_information.executable_id`, `executable_name` and `architecture_name` to be non-empty.
    3. Require `call_graph.vertex` to be non-empty and sorted by address.
    4. Check every `*_index` field is within the bounds of its table.
    5. Require each `flow_graph.entry_basic_block_index` to be in its `basic_block_index` list.
    6. Optionally check `executable_id` equals the SHA-256 of the input PE (true for the Ghidra exporter).
  - Bounds checks matter because a crafted .BinExport caused out-of-bounds reads in BinDiff before v7 (v7 release notes).
- **.BinDiff:**
  1. The first 16 bytes must be `SQLite format 3\0`.
  2. Tables `metadata`, `file`, `function`, `functionalgorithm`, `basicblock`, `instruction` must exist with the column sets above (use `PRAGMA table_info`).
  3. `metadata` must have exactly one row, with `version LIKE 'BinDiff %'`.
  4. `file` must have ids {1,2}, and `metadata.file1=1`, `file2=2`.
  5. `function.algorithm` values must all exist in `functionalgorithm`.
  6. `0 ≤ similarity, confidence ≤ 1` [inf: range not asserted in code].
  - Open the database read-only (`mode=ro` URI).

## Platforms
- **Release builds:** Windows (`.msi`), macOS (`.dmg`, universal since v7), Linux amd64 (`.deb`).
- **Source build:** CMake + Ninja, GCC 15/Clang, or VS2022 + the Win11 SDK [src README L84-106].
- **BinExport release zips:** per-OS native plugins (IDA/Binary Ninja) plus a Java Ghidra extension.

## Open questions
- Exact headless `askChoices` behavior with empty input.
- Whether the v8 `.deb`/`.msi` CLI matches current main flags. v8 notes mention a "similarity scores only" option, which matches `--output_format=none`.
- No release supports Ghidra 11.1+ or 12; main claims 12.x compatibility but this is unverified.
- Licences of the JRE bundled in the packages.

## Implications for PatchTrace contracts
- **Pinning:** BinExport and BinDiff are optional external tools. Pin to BinDiff `v8` binaries, or to a source build at a commit. The BinExport Ghidra extension must be built for the user's exact Ghidra version.
- **Invocation:** `bindiff --nologo --output_dir=<tmp> --output_format=bin a.BinExport b.BinExport`.
  - Success = exit 0 **and** the expected `<a>_vs_<b>.BinDiff` exists (derive the name from input basenames, so rename inputs uniquely). Exit 1 = failure; capture stderr `Error: …`.
- **Ingestion:** validate files as described above. Read matches from `function` joined to `functionalgorithm` by id, and keep `similarity`, `confidence`, `flags` and the algorithm name. Derive unmatched functions from the BinExport call graph.
- **Addresses:** stored as BIGINT (SQLite signed int64). Addresses ≥ 2^63 come back negative, so mask with `& 0xFFFFFFFFFFFFFFFF`. The Ghidra exporter can subtract the image base ("Subtract Imagebase"), so record which option was used.
