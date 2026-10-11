# Normalized schemas (SPEC-02)

The 15 JSON Schema draft 2020-12 files under ../schemas/ are normative field/type/required/enum/default contracts, generated from `models.py` by `PYTHONPATH=src python tools/generate_schemas.py`. Their IDs are `https://patchtrace.local/schemas/v1/{Entity}.json`; this is an identity namespace and need not be fetched. Unknown extra fields fail. JSON UTF-8 only; no unsafe object deserialization. All records carry stable project-owned string identity and schema_version exactly 1. UUID defaults do not permit deriving correspondence from addresses. Timestamps are UTC ISO 8601.

| Entity | Lifecycle / relationships / null semantics |
|---|---|
| Artifact | Immutable hash of copied bytes; exactly one each side; name display only; path relative to project |
| ComparisonProject | Mutable aggregate persisted atomically; revision increments on derived-state invalidation; exactly two artifacts |
| AnalysisRun | New ID per execution/import; status queued/running→completed/failed/cancelled/identical; raw path/hash nullable until publication |
| BackendCapabilities | Runtime observation; missing mapping is false, not an inferred capability |
| FunctionRecord | Belongs to artifact/run; code/assembly/address null means unavailable; address space explicit; calls textual unless resolved |
| FunctionMatch | Run-owned side lists; categories added/removed constrain side; split/merge represented by multiple functions; quality qualitative backend description |
| DiffHunk | Match-owned zero-based half-open old/new line ranges; textual correspondence only |
| EvidenceReference | Artifact/run/function/side plus inclusive one-based lines; text captured exactly from context; end>=start |
| AnalysisContext | Project/revision/matches scoped; digest of exact supplied payload; omissions explicit; stale after invalidation |
| InterpretationRun | Provider/model/prompt context fixed; raw text quarantined separately from accepted findings; no credentials |
| Finding | Context and selected matches only; model hypothesis separate from analyst conclusion; starts unreviewed |
| Hypothesis | Explanation plus support/counterevidence IDs; confidence qualitative not probability; unknowns/preconditions/verification |
| AnalystAnnotation | Human-origin note/bookmark/correction/validation with target identity; stale may retain historical text |
| JobEvent | Run-owned stage/message, progress null means indeterminate; no made-up percentage |
| ExportManifest | Immutable project revision/format/flags/finding IDs/output digest; report can be regenerated |

Addresses retain upstream hexadecimal text and declared virtual/relative/file-offset/unknown type. Never compare equal addresses as matching evidence. Upstream Ghidra address strings are virtual when verified metadata defines loader address space; unresolved names remain unknown. Never invent instruction-to-decompiler mapping.

## Examples and invariants
Valid Artifact: `{ "schema_version":1,"id":"a-old","side":"older","name":"old.dll","sha256":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","size":1024,"relative_path":"artifacts/aaaaaaaa.bin","architecture":"x86-64","format":"PE" }`.
Invalid Artifact: same object with size=-1, schema_version=2, SHA256='guess', or an absolute/traversal storage path. Invalid FunctionMatch: category='added' with an older function. Invalid EvidenceReference: start_line=8,end_line=2. Invalid Finding: supporting evidence not contained in exact context. Invalid ComparisonProject: duplicate sides, absent run or wrong artifact-side ownership. Invalid import: old_meta/new_meta executable hashes do not match project pair.

Every schema supports empty strings only where unknown free text is permitted; null is used only for explicitly unavailable optional fields, never as a replacement for an empty list. Imported current v1 must pass aggregate ownership and semantic validation, not merely JSON schema types. Future versions fail with PT-SCHEMA. v1 has no prior migrations; new migrations must back up first, validate old/new schema and preserve IDs/historical records. Existing incompatible contexts never silently upgraded; mark stale or quarantine.
