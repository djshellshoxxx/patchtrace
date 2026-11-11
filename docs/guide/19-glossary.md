# 19. Glossary

Terms as PatchTrace uses them. Where a word has a stricter meaning here than in everyday use, that meaning wins. Longer treatments: [concepts](../concepts.md), the specs index `docs/specs/INDEX.md`.

## Core objects

| Term | Meaning |
|---|---|
| **Pair** | An older and a newer build of the same PE file. Order is chosen by you, never inferred. |
| **Orientation** | Which side is older and which newer. Explicit everywhere; swapping marks earlier interpretations stale. |
| **Artifact** | One input file as stored in a project: name, SHA-256, size, side, format `PE`, architecture `x86-64`, kept as a read-only content-addressed copy. |
| **Project** | A folder with `project.sqlite3`, `artifacts/`, `runs/`, `exports/`; a `ComparisonProject` snapshot with revisions and bounded history. One writer at a time. |
| **Run** (analysis run) | One attempt of an engine over the pair; stores the raw output and a settings record. Failed runs keep their log and never replace committed results. |
| **Function record** | A function of one side in one run: name, address, address space, code, assembly, callers, callees, metadata. |
| **Match** | A relation between function records of the two sides with a category: `modified`, `added`, `removed`, `unmatched`, `ambiguous`, `split`, `merged`, `unchanged`. Describes correspondence, not severity. |
| **Correction** (manual override) | Your recorded replacement of a match, with a required reason. The engine output stays. |
| **Review status** | Your decision on a match or finding: `unreviewed`, `accepted`, `rejected`, `needs-review`. Independent for matches and findings. |
| **Finding** | A validated, cited hypothesis from optional AI interpretation (or the sample). Traceability, not truth. |
| **Stale** | Computed from a project state that no longer exists (after a correction, swap or new run). Shown, never silently reused. |
| **Revision** | Counter that rises on every committed change of a project. |

## Evidence vocabulary

| Term | Meaning |
|---|---|
| **Evidence** | A recorded observation with provenance: engine or tool, run, artifact hash, function. |
| **Provenance** | The answer to "where did this come from": always shown, always copyable. |
| **Unknown** | No observation. Never a negative vote; never zero. |
| **Contested** | An engine pairs an endpoint differently from the primary result. Kept and shown; never voted away. |
| **Corroborated / Agree** | At least one secondary engine pairs the same endpoints and none contradicts. Not independent proof. |
| **Single engine** | Only the primary engine has a comparable record. |
| **Insufficient / Unknown (verdict)** | Secondary output cannot be compared to this match. |
| **Shared origin** | Evidence derived from the same upstream data; counts once (`D_` origin tags such as `D_ghidra`, `D_bytes`, `D_symbols`, `D_vendor_text`). |
| **Independence component** | A set of evidence families joined by a shared origin; fusion counts a component once. |
| **Triage index** | The opt-in 55 to 83 number in the Evidence tab; ordinal, uncalibrated, about *matching* only. |
| **Ordinal** | Ordered labels (for example tiers), not numbers you can add or average. |
| **Calibrated** | Checked against held-out labelled data to behave like the probability it claims. Nothing in the product is calibrated today. |
| **Claims profile** | A wording rule set for a panel (for example "pairing" panels may not use probability or vulnerability wording). |
| **Advisory fact** | A vendor claim from CSAF with provenance. Not verification of a function. |

## Engines and tools

| Term | Meaning |
|---|---|
| **Ghidriff** | The primary comparison engine (GPL-3.0, separate process) running on Ghidra. Its JSON is normalized into matches. |
| **Ghidra / JDK** | The disassembler/decompiler and its Java runtime. External, not bundled in the normal package. |
| **BinDiff** | Google's structural differ; optional second opinion, needs `.BinExport` inputs. Never bundled. |
| **BinExport / `.BinExport`** | The BinExport2 protobuf export of a disassembly; untrusted input, validated in a capped worker. |
| **rz-diff** | rizin's differ; optional byte-level second opinion. |
| **Unified engine** | PatchTrace's derived, ordinal fusion of stored engine outputs plus its own pass ladder (SPEC-31). Experimental. |
| **Pass ladder** | The ordered, uniqueness-gated matching passes P00 to P19 (manual, import/export key, exact name, bytes, masked bytes, operand class, ..., assignment). |
| **Tier** (unified) | `M` manual, `A` auto-accept key, `B` needs a second independent atom, `C` candidate only, `W` weak external evidence. |
| **Decision** | Unified pairing result: `matched`, `tentative`, `candidate`, `contested`, `ambiguous`, `older-only`, `newer-only`, `unknown`. |
| **Materiality** | Unified change class: `unchanged`, `cosmetic`, `material`, `review`, `unknown`, `not-applicable`. |
| **Proof id** | `UNCH/1`, `COS-ADDR/1`, `COS-LAYOUT/1`, `COS-PSEUDO/1`: the named rule behind an `unchanged` or `cosmetic` row. |
| **IR / GZF** | Instruction-level facts extracted once per artifact; Ghidra's packed analysed-program file Ghidriff can leave behind. |
| **capa / FLOSS / diec** | Static tools for capabilities, strings and packer/compiler identification. Their evidence is read from stored runs. |
| **Delta** | What changed between the older and newer stored tool evidence. |

## Ranking and leads

| Term | Meaning |
|---|---|
| **Attention** | `attention/1`: integer 0 to 100 from eight lexical detectors (BND, INT, OVF, VAL, ERR, SIZE, WIL, SCRUB) that orders changed functions for reading. Not exploitability. |
| **WIL** | Windows Implementation Library feature flags (`Feature_<uint32>`); a gate pattern is evidence of a staged change. |
| **Lead** (patch-intent) | An ordered, explained place to look for a changed function pair, optionally against a CVE. Classes: `fit`, `review`, `partial`, `code`, `queue`. Order uses integer keys, no score. |
| **Anchor** | A typed, addressable thing (function, string, import, CVE, CWE, rule, ...) that panels and the fabric point at. |
| **Anchor fabric** | The store and read API of anchors with witnesses and origin components (`fabric/1`). |
| **KEV** | CISA's Known Exploited Vulnerabilities catalog; context about a CVE, never a ranking input. |
| **CSAF** | Common Security Advisory Framework 2.0, the format of Microsoft advisories used here. |
| **KB** | Microsoft Knowledge Base update number; the KB-to-CVE index is built in part but the user-facing search is planned. |
| **CWE hypothesis** | A rule describing the shapes a fix for a weakness family commonly takes; search guidance, not a finding. |
| **Rule candidate / version** | A proposed / accepted YARA-X rule for one changed-function pair; accepting stores a version, exporting writes a `.yar`. |

## GUI and process

| Term | Meaning |
|---|---|
| **Dock / panel** | A feature view inside the one main window, declared by a `PanelSpec` and built lazily. |
| **Manifest** | The list of every reserved panel (id, area, tab group, shortcut), built or not. |
| **Port** | One of four Protocols a panel uses to talk to the window: project, mutation, navigation, shell. |
| **Task** | Background work on the `TaskRunner`; results return on the GUI thread. |
| **Announcer** | The single sender of screen-reader announcements. |
| **Chip** | A status badge with text, ASCII glyph and shape, colour only as an extra. |
| **Consent** | Your per-operation approval naming the exact host(s) before any request. |
| **Quarantine** | Staging area where downloaded files are identified (headers only) before promotion; never executed. |
| **Bundle** | The private runtime in `backend/` next to the executable, described by `manifest.json`; or the importable offline backend ZIP. |
| **Lite / full package** | Without / with a bundled backend. Only lite packages are published. |
| **Contract** | A versioned persisted or CLI schema named `name/N` (for example `enrichment/1`, `fabric/1`); changed additively only. |
| **Envelope** | The `enrichment-cli/1` JSON wrapper of every CLI result. |
| **Prerelease** | A `v0.1.0-beta.N` GitHub release; no final release exists. |
| **Gate** | A pass/fail check: a test gate, the release gate (every third counted merge), or an acceptance gate. |
| **Tier R / Tier W** | Calibration corpus tiers: open-source redistributable (R); Windows binaries kept local, never committed (W). Developer data, not shown in the app. |
| **Ordinal-only display** | The calibration seam `display_level()` returns `ordinal` unless a valid artifact passes its gates; none ships. |
