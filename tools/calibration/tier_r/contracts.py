"""SPEC-32 contracts: `known-answer-labels/1`, `tier-r-recipe/1`, `mutation-case/1`, `tier-r-report/1`, plus typed views
of the corpus input formats `case-card/1` and `suite/1` (corpus/README.md).

Loaders: size cap -> strict JSON (duplicate keys, NaN rejected) -> pydantic strict, extra=forbid -> digest check. Input
views (cards, suites) ignore unknown keys because their authors may add notes; `tools/corpus_check.py` validates them.
"""
from __future__ import annotations

import re
from collections import Counter
from typing import Annotated, Any, Literal

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    ValidationError,
    field_validator,
    model_validator,
)

from ..common import canonical_json, digest, strict_json


def _relative(value: str) -> str:
    """Repository/source-relative POSIX path: no absolute path, drive, backslash or `..` component."""
    parts = value.split('/')
    if value.startswith('/') or '..' in parts or '' in parts or ':' in value or '\\' in value:
        raise ValueError(f'path {value!r} must be relative, "/"-separated and without ".."')
    return value


Sha256 = Annotated[str, Field(pattern=r'^[0-9a-f]{64}$')]
Commit = Annotated[str, Field(pattern=r'^[0-9a-f]{40}$')]
Ident = Annotated[str, Field(pattern=r'^[A-Za-z0-9][A-Za-z0-9._-]{0,95}$')]
Kind = Annotated[str, Field(pattern=r'^[a-z0-9][a-z0-9-]{0,47}$')]
RelPath = Annotated[str, Field(min_length=1, max_length=512, pattern=r'^[^\\:*?"<>|\x00]+$'), AfterValidator(_relative)]
Glob = Annotated[str, Field(min_length=1, max_length=256, pattern=r'^[A-Za-z0-9_./*?\[\]-]+$'),
                 AfterValidator(_relative)]
Rva = Annotated[int, Field(ge=0, le=2**32 - 1)]

LABELS_CONTRACT = 'known-answer-labels/1'
MAX_LABEL_BYTES = 64 * 1024 * 1024
MAX_FUNCTIONS = 200_000
MAX_DOC_BYTES = 8 * 1024 * 1024
MAX_IMAGE_BYTES = 64 * 1024 * 1024

Stratum = Literal['release', 'cve', 'control', 'mutation', 'aa', 'noise', 'authored']
Method = Literal['release-pair', 'cve-pair', 'case-card', 'mutation', 'aa-rebuild', 'aa-layout', 'toolchain-noise',
                 'suite']
LabelSource = Literal['source-diff', 'fix-diff', 'planted-mutation', 'same-source', 'authored-truth']
Identity = Literal['same', 'no-counterpart', 'ambiguous']
Label = Literal['unchanged', 'changed', 'cosmetic', 'no-counterpart', 'ambiguous']
Body = Literal['identical', 'address-only', 'different', 'n/a']
Check = Literal['ok', 'disagree', 'unchecked']
Profile = Literal['msvc-free', 'mingw-gcc', 'mingw-clang', 'clang-cl', 'msvc']
Opt = Literal['O0', 'O1', 'O2', 'O3', 'Os']
Taxonomy = Literal['N1', 'N2', 'N3', 'N4', 'N5', 'N6', 'N7', 'N8', 'N9', 'N10', 'N11', 'N12']
SEMANTIC_OPERATORS = ('cmp-flip', 'const-change', 'bounds-check-insert', 'bounds-check-remove', 'call-add',
                      'call-remove', 'arg-swap', 'loop-bound', 'off-by-one', 'int-width')
COSMETIC_OPERATORS = ('ws-comment', 'dead-code', 'reorder-defs', 'local-rename', 'macro-rewrite', 'inline-toggle')
Operator = Literal['cmp-flip', 'const-change', 'bounds-check-insert', 'bounds-check-remove', 'call-add', 'call-remove',
                   'arg-swap', 'loop-bound', 'off-by-one', 'int-width', 'ws-comment', 'dead-code', 'reorder-defs',
                   'local-rename', 'macro-rewrite', 'inline-toggle']
# Licences accepted for third-party sources: permissive only (same allow-list as tools/corpus_check.py, plus 0BSD).
PERMISSIVE_SPDX = frozenset({'MIT', 'Apache-2.0', 'BSD-2-Clause', 'BSD-3-Clause', 'Zlib', 'ISC', 'CC0-1.0', 'Unlicense',
                             'Libpng-2.0', 'curl', 'IJG', 'BSL-1.0', 'blessing', '0BSD',
                             'BSD-3-Clause WITH PCRE2-exception', 'Apache-2.0 OR GPL-2.0-or-later'})
STRATUM_METHODS: dict[str, frozenset[str]] = {
    'release': frozenset({'release-pair', 'case-card'}), 'cve': frozenset({'cve-pair', 'case-card'}),
    'control': frozenset({'cve-pair', 'case-card'}), 'mutation': frozenset({'mutation'}),
    'aa': frozenset({'aa-rebuild', 'aa-layout'}), 'noise': frozenset({'toolchain-noise'}),
    'authored': frozenset({'suite'})}
STRATUM_SOURCES: dict[str, frozenset[str]] = {
    'release': frozenset({'source-diff'}), 'cve': frozenset({'fix-diff', 'source-diff'}),
    'control': frozenset({'fix-diff', 'source-diff'}), 'mutation': frozenset({'planted-mutation', 'same-source'}),
    'aa': frozenset({'same-source'}), 'noise': frozenset({'same-source'}), 'authored': frozenset({'authored-truth'})}


class ContractError(ValueError):
    pass


class _Strict(BaseModel):
    model_config = ConfigDict(extra='forbid', strict=True, frozen=True)


class _Lenient(BaseModel):
    """Input views: typed where the factory relies on a field, unknown keys ignored (validated by corpus_check)."""
    model_config = ConfigDict(extra='ignore', strict=True, frozen=True)


# ---- known-answer-labels/1 ---------------------------------------------------------------------------------------

class SourceRef(_Strict):
    git: str | None = Field(default=None, pattern=r'^https://[A-Za-z0-9.-]+/[A-Za-z0-9._/-]+$')
    suite: str | None = Field(default=None, pattern=r'^[A-Za-z0-9._-]+/[A-Za-z0-9._-]+$')
    commit: Commit | None = None
    version: str | None = Field(default=None, pattern=r'^[A-Za-z0-9._-]{1,64}$')
    ref: str | None = Field(default=None, max_length=128)
    license_spdx: str = Field(min_length=1, max_length=64)
    mutation: str | None = Field(default=None, pattern=r'^[A-Za-z0-9._-]{1,96}$')

    @model_validator(mode='after')
    def one_origin(self):
        if (self.git is None) == (self.suite is None):
            raise ValueError('a source is either a pinned git commit or a suite version')
        if self.git is not None and self.commit is None:
            raise ValueError('a git source needs the 40-hex commit')
        if self.suite is not None and self.version is None:
            raise ValueError('a suite source needs its version')
        return self


class BuildInfo(_Strict):
    profile: Profile
    compiler: str = Field(min_length=1, max_length=64)
    compiler_version: str = Field(min_length=1, max_length=200)
    opt: Opt
    recipe_digest: Sha256
    link_order: Literal['sorted', 'reversed', 'rotated'] = 'sorted'
    variant: str = Field(default='', max_length=64, pattern=r'^[a-z0-9-]*$')


class ImageSide(_Strict):
    sha256: Sha256
    debug_sha256: Sha256
    pdb_sha256: Sha256 | None = None
    size: int = Field(ge=64, le=MAX_IMAGE_BYTES)
    file_name: str = Field(min_length=1, max_length=128, pattern=r'^[A-Za-z0-9._+-]+\.(dll|exe)$')
    image_base: int = Field(ge=0, le=2**64 - 1)
    source: SourceRef
    build: BuildInfo


class FunctionLabel(_Strict):
    name: str = Field(min_length=1, max_length=512)
    file: RelPath | None
    variant: str | None = Field(default=None, pattern=r'^[A-Za-z0-9._$-]{1,64}$')
    old_rva: Rva | None
    new_rva: Rva | None
    old_size: int | None = Field(default=None, ge=0, le=MAX_IMAGE_BYTES)
    new_size: int | None = Field(default=None, ge=0, le=MAX_IMAGE_BYTES)
    identity: Identity
    label: Label
    change_kind: Kind | None = None
    body: Body
    label_source: LabelSource
    check: Check = 'unchecked'
    taxonomy: tuple[Taxonomy, ...] = ()
    notes: str = Field(default='', max_length=500)

    @model_validator(mode='after')
    def invariants(self):
        both = self.old_rva is not None and self.new_rva is not None
        one = (self.old_rva is None) != (self.new_rva is None)
        if self.identity == 'same' and not (both and self.label in {'unchanged', 'changed', 'cosmetic', 'ambiguous'}):
            raise ValueError('identity same needs both RVAs and an unchanged/changed/cosmetic/ambiguous label')
        if self.identity == 'no-counterpart' and not (one and self.label == 'no-counterpart'):
            raise ValueError('identity no-counterpart needs exactly one RVA and label no-counterpart')
        if self.identity == 'ambiguous' and (self.label != 'ambiguous' or (self.old_rva is None and self.new_rva is None)):
            raise ValueError('identity ambiguous needs label ambiguous and at least one RVA')
        if self.label in {'changed', 'cosmetic'} and self.change_kind is None:
            raise ValueError(f'label {self.label} needs a change_kind')
        if self.label in {'unchanged', 'no-counterpart'} and self.change_kind is not None:
            raise ValueError(f'label {self.label} carries no change_kind')
        if (self.old_rva is None) != (self.old_size is None) or (self.new_rva is None) != (self.new_size is None):
            raise ValueError('a size is given exactly for each present side')
        if self.body != 'n/a' and not both:
            raise ValueError('a body fact needs both sides')
        if len(set(self.taxonomy)) != len(self.taxonomy):
            raise ValueError('duplicate taxonomy tag')
        return self

    def sort_key(self) -> tuple:
        return (-1 if self.old_rva is None else self.old_rva, -1 if self.new_rva is None else self.new_rva,
                self.name, self.variant or '', self.file or '')


class Summary(_Strict):
    functions: int = Field(ge=0)
    by_label: dict[str, int]
    by_identity: dict[str, int]
    by_body: dict[str, int]
    disagreements: int = Field(ge=0)
    runtime_functions: int = Field(default=0, ge=0)
    absent_functions: int = Field(default=0, ge=0)


class Reproducibility(_Strict):
    byte_identical: bool
    differing_sections: tuple[str, ...] = ()
    differing_bytes: int = Field(default=0, ge=0)
    detail: str = Field(default='', max_length=500)


def summarize(functions, *, runtime: int = 0, absent: int = 0) -> dict:
    return {'functions': len(functions),
            'by_label': dict(sorted(Counter(f.label for f in functions).items())),
            'by_identity': dict(sorted(Counter(f.identity for f in functions).items())),
            'by_body': dict(sorted(Counter(f.body for f in functions).items())),
            'disagreements': sum(1 for f in functions if f.check == 'disagree'),
            'runtime_functions': runtime, 'absent_functions': absent}


class KnownAnswerLabels(_Strict):
    contract: Literal['known-answer-labels/1']
    pair_id: Ident
    stratum: Stratum
    method: Method
    project: Ident
    lineage: Ident
    family: str = Field(min_length=1, max_length=64, pattern=r'^[a-z0-9-]+$')
    older: ImageSide
    newer: ImageSide
    label_source: LabelSource
    functions: tuple[FunctionLabel, ...] = Field(max_length=MAX_FUNCTIONS)
    summary: Summary
    case: dict[str, Any] = Field(default_factory=dict)
    reproducibility: Reproducibility | None = None
    notes: tuple[Annotated[str, Field(max_length=500)], ...] = Field(default=(), max_length=64)
    digest_sha256: Sha256

    @field_validator('case')
    @classmethod
    def bounded_case(cls, value):
        if len(canonical_json(value)) > 256 * 1024:
            raise ValueError('case provenance exceeds 256 KiB')
        return value

    @model_validator(mode='after')
    def invariants(self):
        if self.method not in STRATUM_METHODS[self.stratum]:
            raise ValueError(f'method {self.method} does not produce stratum {self.stratum}')
        allowed = STRATUM_SOURCES[self.stratum]
        if self.label_source not in allowed or any(f.label_source not in allowed for f in self.functions):
            raise ValueError(f'label_source not allowed for stratum {self.stratum}: {sorted(allowed)}')
        if self.older.sha256 == self.newer.sha256 and self.stratum != 'aa':
            raise ValueError('older and newer engine images are identical outside the aa stratum')
        keys = [f.sort_key() for f in self.functions]
        if keys != sorted(keys):
            raise ValueError('functions must be sorted by (old_rva, new_rva, name, variant, file)')
        for side in ('old_rva', 'new_rva'):
            values = [getattr(f, side) for f in self.functions if getattr(f, side) is not None]
            if len(values) != len(set(values)):
                raise ValueError(f'{side} values must be unique')
        expected = summarize(self.functions, runtime=self.summary.runtime_functions,
                             absent=self.summary.absent_functions)
        if self.summary.model_dump() != expected:
            raise ValueError('summary does not match the function records')
        return self


def validate_json(model: type[BaseModel], value) -> BaseModel:
    """Strict validation of plain JSON data (lists become tuples only through the JSON path in strict mode)."""
    return model.model_validate_json(canonical_json(value))


def finalize_labels(document: dict) -> dict:
    """Sort records, recompute the summary and the digest (the only way the factory writes a label document).
    Raises pydantic.ValidationError on any invariant violation."""
    doc = dict(document)
    funcs = [validate_json(FunctionLabel, f) for f in doc.get('functions', ())]
    funcs.sort(key=FunctionLabel.sort_key)
    summary = doc.get('summary') or {}
    doc['functions'] = [f.model_dump(mode='json') for f in funcs]
    doc['summary'] = summarize(funcs, runtime=summary.get('runtime_functions', 0),
                               absent=summary.get('absent_functions', 0))
    doc.pop('digest_sha256', None)
    doc = validate_json(KnownAnswerLabels, {**doc, 'digest_sha256': '0' * 64}).model_dump(mode='json')
    doc['digest_sha256'] = digest(doc)
    return doc


def _strict_doc(data: bytes, limit: int):
    if len(data) > limit:
        raise ContractError('document too large')
    try:
        return strict_json(data)
    except (UnicodeDecodeError, ValueError, RecursionError) as exc:
        raise ContractError(f'not strict JSON: {exc}') from None


def load_labels(data: bytes) -> KnownAnswerLabels:
    raw = _strict_doc(data, MAX_LABEL_BYTES)
    try:
        doc = KnownAnswerLabels.model_validate_json(data)
    except ValidationError as exc:
        raise ContractError(f'labels invalid: {exc}') from None
    if digest(raw) != doc.digest_sha256:
        raise ContractError('labels digest mismatch (edited after generation)')
    return doc


def dump_json(document: dict) -> bytes:
    """Deterministic on-disk form (sorted keys, 1-space indent, LF, trailing newline)."""
    import json
    return (json.dumps(document, sort_keys=True, indent=1, ensure_ascii=False, allow_nan=False) + '\n').encode('utf-8')


# ---- tier-r-recipe/1 ---------------------------------------------------------------------------------------------

_DEFINE = re.compile(r'^[A-Za-z_][A-Za-z0-9_]*(=[A-Za-z0-9_.()"+-]*)?$')
_CFLAG = re.compile(r'^(-std=(c89|c90|c99|c11|c17|gnu89|gnu99|gnu11|gnu17)|-Wno-[a-z0-9=-]+|-fno-[a-z0-9-]+|-fwrapv'
                    r'|-funsigned-char|-fsigned-char|-fvisibility=(default|hidden)|-msse2|-msse4\.1|-mavx2)$')


class CopyRule(_Strict):
    src: RelPath
    dst: RelPath


class WriteRule(_Strict):
    path: RelPath
    text: str = Field(max_length=64 * 1024)


class Pin(_Strict):
    ref: str = Field(min_length=1, max_length=128)
    commit: Commit
    license_sha256: Sha256
    date: str = Field(default='', max_length=32)


class Dependency(_Strict):
    project: Ident
    ref: str = Field(min_length=1, max_length=128)
    commit: Commit


class RecipeVariant(_Strict):
    """Overrides for some pins (matched by ref or commit); lists replace the base lists when given."""
    match: tuple[str, ...] = Field(min_length=1)
    sources: tuple[Glob, ...] | None = None
    exclude: tuple[Glob, ...] | None = None
    include_dirs: tuple[RelPath, ...] | None = None
    defines: tuple[str, ...] | None = None
    copy_files: tuple[CopyRule, ...] | None = None
    write: tuple[WriteRule, ...] | None = None


class Recipe(_Strict):
    contract: Literal['tier-r-recipe/1']
    project: Ident
    family: str = Field(pattern=r'^[a-z0-9-]{1,64}$')
    upstream_git: str = Field(pattern=r'^https://github\.com/[A-Za-z0-9._-]+/[A-Za-z0-9._-]+(\.git)?$')
    license_spdx: str
    license_file: RelPath
    license_evidence: str = Field(min_length=1, max_length=500)
    libc: Literal['mingw', 'freestanding']
    output: str = Field(pattern=r'^[A-Za-z0-9._+-]+\.dll$')
    sources: tuple[Glob, ...] = Field(min_length=1)
    exclude: tuple[Glob, ...] = ()
    include_dirs: tuple[RelPath, ...] = ()
    defines: tuple[str, ...] = ()
    cflags: tuple[str, ...] = ()
    copy_files: tuple[CopyRule, ...] = ()
    write: tuple[WriteRule, ...] = ()
    depends: tuple[Dependency, ...] = ()
    variants: tuple[RecipeVariant, ...] = ()
    pins: tuple[Pin, ...] = ()
    notes: str = Field(default='', max_length=1000)

    @field_validator('license_spdx')
    @classmethod
    def permissive(cls, value):
        if value not in PERMISSIVE_SPDX:
            raise ValueError(f'licence {value!r} is not on the permissive allow-list')
        return value

    @field_validator('defines')
    @classmethod
    def defines_ok(cls, value):
        bad = [d for d in value if not _DEFINE.match(d)]
        if bad:
            raise ValueError(f'unsafe define(s): {bad}')
        return value

    @field_validator('cflags')
    @classmethod
    def cflags_ok(cls, value):
        bad = [f for f in value if not _CFLAG.match(f)]
        if bad:
            raise ValueError(f'cflag(s) outside the allow-list: {bad}')
        return value

    @model_validator(mode='after')
    def pins_unique(self):
        if len({p.commit for p in self.pins}) != len(self.pins) or len({p.ref for p in self.pins}) != len(self.pins):
            raise ValueError('duplicate pin')
        for variant in self.variants:
            if variant.defines and any(not _DEFINE.match(d) for d in variant.defines):
                raise ValueError('unsafe define in a variant')
        return self

    def pin_for(self, commit: str) -> Pin | None:
        return next((p for p in self.pins if p.commit == commit), None)

    def resolved(self, ref: str, commit: str) -> dict:
        """Effective lists for one pin after variant overrides."""
        out = {'sources': self.sources, 'exclude': self.exclude, 'include_dirs': self.include_dirs,
               'defines': self.defines, 'copy_files': self.copy_files, 'write': self.write}
        for variant in self.variants:
            if ref in variant.match or commit in variant.match:
                for key in out:
                    value = getattr(variant, key)
                    if value is not None:
                        out[key] = value
        return out


class RecipeBook(_Strict):
    contract: Literal['tier-r-recipes/1']
    recipes: tuple[Recipe, ...]
    excluded: tuple[dict[str, str], ...] = ()

    @model_validator(mode='after')
    def unique(self):
        names = [r.project for r in self.recipes]
        if len(names) != len(set(names)):
            raise ValueError('duplicate recipe project')
        return self

    def get(self, project: str) -> Recipe | None:
        return next((r for r in self.recipes if r.project == project), None)


# ---- mutation-case/1 ---------------------------------------------------------------------------------------------

class MutationSite(_Strict):
    file: RelPath
    line: int = Field(ge=1)
    column: int = Field(ge=1)
    before: str = Field(max_length=2000)
    after: str = Field(max_length=2000)


class Rejection(_Strict):
    line: int = Field(ge=1)
    column: int = Field(ge=1)
    reason: str = Field(max_length=300)


class MutationCase(_Strict):
    contract: Literal['mutation-case/1']
    case_id: Ident
    base: SourceRef
    operator: Operator
    kind: Literal['semantic', 'cosmetic']
    seed: int = Field(ge=0, le=2**63 - 1)
    target_file: RelPath
    target_function: str = Field(min_length=1, max_length=256)
    site: MutationSite
    attempts: int = Field(ge=1, le=1000)
    rejected: tuple[Rejection, ...] = Field(default=(), max_length=200)
    helper: str | None = Field(default=None, max_length=128)
    moved_function: str | None = Field(default=None, max_length=256)
    patch_sha256: Sha256

    @model_validator(mode='after')
    def kind_matches(self):
        expected = 'semantic' if self.operator in SEMANTIC_OPERATORS else 'cosmetic'
        if self.kind != expected:
            raise ValueError(f'operator {self.operator} is {expected}')
        return self


# ---- tier-r-report/1 ---------------------------------------------------------------------------------------------

class EngineStatus(_Strict):
    engine: Literal['rz-diff', 'bindiff', 'ghidriff']
    status: Literal['ok', 'partial', 'blocked', 'failed']
    version: str | None = None
    reason: str | None = Field(default=None, max_length=500)
    runs: int = Field(default=0, ge=0)
    failures: int = Field(default=0, ge=0)


class Metrics(_Strict):
    pairs: int = Field(ge=0)
    truth_same: int = Field(ge=0)
    identity_tp: int = Field(ge=0)
    identity_fp: int = Field(ge=0)
    identity_fn: int = Field(ge=0)
    identity_precision: float | None
    identity_recall: float | None
    changed_truth: int = Field(ge=0)
    changed_tp: int = Field(ge=0)
    changed_fp: int = Field(ge=0)
    changed_fn: int = Field(ge=0)
    changed_precision: float | None
    changed_recall: float | None
    matched_negatives: int = Field(ge=0)
    fp_rate: float | None
    cosmetic_matched: int = Field(ge=0)
    cosmetic_flagged: int = Field(ge=0)
    ignored_predictions: int = Field(ge=0)
    ambiguous_records: int = Field(ge=0)


class PairResult(_Strict):
    pair_id: Ident
    stratum: Stratum
    engine: Literal['rz-diff', 'bindiff', 'ghidriff']
    status: Literal['ok', 'blocked', 'failed']
    reason: str | None = Field(default=None, max_length=500)
    metrics: Metrics | None = None
    output_sha256: Sha256 | None = None


class WrongMatch(_Strict):
    pair_id: Ident
    engine: Literal['rz-diff', 'bindiff', 'ghidriff']
    kind: Literal['wrong-counterpart', 'paired-no-counterpart', 'paired-unlabelled']
    old_rva: Rva | None
    new_rva: Rva | None
    old_name: str | None = Field(default=None, max_length=512)
    new_name: str | None = Field(default=None, max_length=512)
    expected_new_rva: Rva | None = None
    expected_old_rva: Rva | None = None
    similarity_milli: int | None = Field(default=None, ge=0, le=1000)


class InputRef(_Strict):
    pair_id: Ident
    stratum: Stratum
    labels_digest: Sha256


class TierRReport(_Strict):
    contract: Literal['tier-r-report/1']
    symbols: Literal['hidden', 'visible']
    inputs: tuple[InputRef, ...]
    engines: tuple[EngineStatus, ...]
    strata: dict[str, dict[str, Metrics]]
    pairs: tuple[PairResult, ...]
    wrong_matches: tuple[WrongMatch, ...] = Field(max_length=5000)
    wrong_matches_truncated: int = Field(ge=0)
    notes: tuple[Annotated[str, Field(max_length=500)], ...] = ()
    report_sha256: Sha256


def load_report(data: bytes) -> TierRReport:
    raw = _strict_doc(data, MAX_LABEL_BYTES)
    try:
        report = TierRReport.model_validate_json(data)
    except ValidationError as exc:
        raise ContractError(f'report invalid: {exc}') from None
    if digest(raw, 'report_sha256') != report.report_sha256:
        raise ContractError('report digest mismatch')
    return report


# ---- input views: case-card/1 and suite/1 (corpus/README.md) ----------------------------------------------------

class CardRef(_Lenient):
    ref: str = Field(min_length=1, max_length=128)
    commit: Commit


class CardFunction(_Lenient):
    name: str = Field(min_length=1, max_length=256)
    file: str = Field(min_length=1, max_length=512)
    change: str = Field(default='', max_length=500)
    kind: str | None = Field(default=None, max_length=48)


class CaseCard(_Lenient):
    contract: Literal['case-card/1']
    id: str = Field(pattern=r'^[a-z0-9][a-z0-9._-]{2,80}$')
    project: str = Field(min_length=1, max_length=64)
    upstream_git: str = Field(pattern=r'^https://')
    license_spdx: str
    license_evidence: str = Field(min_length=1)
    old: CardRef
    new: CardRef
    kind: Literal['release', 'cve-fix', 'constant-only', 'bounds-only', 'refactor-control', 'large-rewrite',
                  'build-system-only', 'no-op']
    cve: tuple[str, ...] = ()
    semantic_change: bool
    changed_functions: tuple[CardFunction, ...] = ()
    unchanged_controls: tuple[str, ...] = ()
    sources: tuple[str, ...] = ()

    @property
    def stratum(self) -> str:
        if self.kind in {'refactor-control', 'no-op', 'build-system-only'}:
            return 'control'
        return 'release' if self.kind in {'release', 'large-rewrite'} else 'cve'


class TruthEntry(_Lenient):
    label: Literal['same', 'changed', 'cosmetic', 'moved', 'added', 'removed', 'renamed', 'split', 'merged', 'inlined']
    function: str | None = None
    kind: str | None = None
    from_: Any = Field(default=None, alias='from')
    to: Any = None
    into: str | None = None
    taxonomy: tuple[Taxonomy, ...] = ()
    notes: str = ''


class SuitePair(_Lenient):
    old: str
    new: str
    intent: str = ''
    truth: tuple[TruthEntry, ...]


class SuiteBuild(_Lenient):
    kind: str = 'freestanding-dll'
    defines: tuple[str, ...] = ()


class Suite(_Lenient):
    contract: Literal['suite/1']
    suite: str = Field(pattern=r'^[A-Za-z0-9._-]{1,64}$')
    project: str = Field(pattern=r'^[A-Za-z0-9._-]{1,64}$')
    license_spdx: Literal['MIT', 'CC0-1.0', 'Unlicense']
    summary: str = ''
    versions: tuple[Annotated[str, Field(pattern=r'^[A-Za-z0-9._-]{1,64}$')], ...] = Field(min_length=2)
    build: SuiteBuild = SuiteBuild()
    pairs: tuple[SuitePair, ...] = Field(min_length=1)


def load_cards(data: bytes) -> tuple[CaseCard, ...]:
    raw = _strict_doc(data, MAX_DOC_BYTES)
    if not isinstance(raw, list):
        raise ContractError('a catalog file is a JSON array of case cards')
    try:
        return tuple(validate_json(CaseCard, item) for item in raw)
    except ValidationError as exc:
        raise ContractError(f'case card invalid: {exc}') from None


def load_suite(data: bytes) -> Suite:
    _strict_doc(data, MAX_DOC_BYTES)
    try:
        return Suite.model_validate_json(data)
    except ValidationError as exc:
        raise ContractError(f'suite invalid: {exc}') from None


def load_recipes(data: bytes) -> RecipeBook:
    _strict_doc(data, MAX_DOC_BYTES)
    try:
        return RecipeBook.model_validate_json(data)
    except ValidationError as exc:
        raise ContractError(f'recipes invalid: {exc}') from None


def load_mutation_case(data: bytes) -> MutationCase:
    _strict_doc(data, MAX_DOC_BYTES)
    try:
        return MutationCase.model_validate_json(data)
    except ValidationError as exc:
        raise ContractError(f'mutation case invalid: {exc}') from None
