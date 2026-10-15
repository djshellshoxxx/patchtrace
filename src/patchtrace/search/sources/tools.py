"""Groups `tool:<engine>:<side>`: FLOSS strings, capa capabilities and DiE build facts (WB1 section 7).

The store is reached through `ToolEvidencePort` (`ToolStore.latest` has exactly this shape), so this module reads
`tool-evidence/1` items by attribute and imports no tool internals. A string located in a function has
subject = that project function id; a group exists only for a run that produced validated output, so a missing
or failed run is `unavailable`, never an empty (and therefore "absent") segment. Secret-looking strings are
indexed as `[redacted: kind]` plus their hash only; the hash stays searchable through `value_sha`.
"""
from __future__ import annotations

from collections.abc import Callable, Iterable
from typing import Any, Protocol

from patchtrace.intelligence.tools.common import redacted_display, secret_kind
from patchtrace.search.segment import Flag, SegmentDoc
from patchtrace.search.sources.base import SourceSpec, name_fields, skipped

SIDES = ('older', 'newer')
TOOLS_VERSION = 1
PRODUCED = ('ok', 'none-found')
NO_PORT = 'Tool results are not available for this project.'
TRUNCATED = 'The tool kept only part of its output, so absence from this list proves nothing.'
SUBJECT_CHARS = 64


class ToolEvidencePort(Protocol):
    def latest(self, engine: str, side: str) -> tuple[Any, Any | None] | None:
        """Newest produced run of one engine and side with its `ToolEvidenceSet`, else None."""


def _subject(link: Any, fallback: str) -> str:
    return (link.project_function_id or link.function_id or fallback)[:SUBJECT_CHARS]


def _rva(link: Any) -> int | None:
    return link.rva if link.rva is not None else link.data_rva


def _string_docs(side: str, evidence: Any) -> Iterable[SegmentDoc]:
    rows = sorted(((s.value_hash, _subject(s.source_location, s.value_hash[:16]), _rva(s.source_location) or 0,
                    s.extraction_method, s.encoding, s.type, s) for s in evidence.strings),
                  key=lambda row: row[:6])
    for ref, (*_, item) in enumerate(rows):
        kind = item.secret_kind or secret_kind(item.display_value)
        shown = redacted_display(item.display_value, kind)
        yield SegmentDoc('string', side, _subject(item.source_location, item.value_hash[:16]), shown, ref,
                         extra=f'{item.type}; {item.encoding}; {item.extraction_method}; {item.confidence_class}',
                         rva=_rva(item.source_location), flags=int(Flag.SECRET) if kind else 0,
                         value_sha=item.value_hash, text_title=shown)


def _capability_text(item: Any) -> str:
    labels = (f'{label.group} {label.ident} {label.name}' for label in item.labels)
    return ' '.join(dict.fromkeys(part for part in (item.namespace or '', *item.attack, *item.mbc, *labels) if part))


def _capability_docs(side: str, evidence: Any) -> Iterable[SegmentDoc]:
    found = [c for c in evidence.capabilities if c.kind == 'capability']
    found.sort(key=lambda c: (c.rule_id, _subject(c.location, 'file'), _rva(c.location) or 0, c.scope, c.rule_sha256))
    for ref, item in enumerate(found):
        yield SegmentDoc('capability', side, _subject(item.location, 'file'), item.rule_id, ref,
                         extra=item.namespace or '', rva=_rva(item.location), text_title=item.rule_id,
                         text_body=_capability_text(item), **name_fields(item.rule_id))


def _environment_label(item: Any) -> str:
    return item.toolchain or item.packer or item.protector or item.detector_rule


def _environment_docs(side: str, evidence: Any) -> Iterable[SegmentDoc]:
    found = sorted(evidence.environment, key=lambda e: (e.category, _environment_label(e), e.version,
                                                        e.detector_rule, e.part_path))
    for ref, item in enumerate(found):
        label = ' '.join(part for part in (_environment_label(item), item.version) if part)
        body = ' '.join(dict.fromkeys(p for p in (label, item.detector_rule, item.detect_string, item.raw_type) if p))
        yield SegmentDoc('build', side, item.category, f'{item.category}: {label}', ref, extra=item.certainty,
                         text_title=item.category, text_body=body)


ENGINES: dict[str, tuple[str, str, tuple[str, ...], Callable[[str, Any], Iterable[SegmentDoc]]]] = {
    'floss': ('FLOSS', 'string', ('text',), _string_docs),
    'capa': ('capa', 'capability', ('name', 'text'), _capability_docs),
    'diec': ('Detect It Easy', 'build', ('text',), _environment_docs),
}


def _one(port: ToolEvidencePort, engine: str, side: str) -> SourceSpec:
    title, kind, table_sets, documents = ENGINES[engine]
    group = f'tool:{engine}:{side}'
    found = port.latest(engine, side)
    if found is None or found[1] is None or found[0].status not in PRODUCED:
        return skipped(group, (kind,), side, 'unavailable',
                       f'No {title} run has produced results for the {side} build. Run {title} to add them.')
    evidence = found[1]
    return SourceSpec(group, (kind,), table_sets, side, {'cache_key': evidence.cache_key, 'version': TOOLS_VERSION},
                      lambda: documents(side, evidence), reason=TRUNCATED if evidence.truncated else '')


def tool_specs(port: ToolEvidencePort | None) -> tuple[SourceSpec, ...]:
    """The six tool groups (three engines, two sides). Call on the GUI thread, like the other source builders."""
    specs = []
    for engine, (_, kind, *_rest) in ENGINES.items():
        for side in SIDES:
            specs.append(skipped(f'tool:{engine}:{side}', (kind,), side, 'unavailable', NO_PORT)
                         if port is None else _one(port, engine, side))
    return tuple(specs)
