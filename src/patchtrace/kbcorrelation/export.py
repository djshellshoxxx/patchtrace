"""Export of a context bundle as JSON or escaped Markdown (KB-integration-plan 8.1 `export`; slice K3). Pure.

Both forms carry pointers, hashes, rule ids and digests, the vendor-stated facts, unknowns and limitations. Neither
holds an absolute path, code or HTML: Markdown text is escaped by the caller-supplied ``escape`` (the reused
``intelligence.reports.escape_md``), so advisory text cannot add markup or links.
"""
from __future__ import annotations

import json
from collections.abc import Callable

from .context import ContextBundle
from .leads import ExploitationLookup, kev_source_of, kev_text

Escape = Callable[[str], str]
EXTENSIONS = {'.json': 'json', '.md': 'markdown'}


def to_json(bundle: ContextBundle) -> bytes:
    text = json.dumps(bundle.model_dump(mode='json'), sort_keys=True, indent=2, ensure_ascii=True)
    return (text + '\n').encode('utf-8')


def _card_lines(bundle: ContextBundle, escape: Escape, kev: ExploitationLookup | None) -> list[str]:
    lines: list[str] = []
    for card, profile, hypothesis in zip(bundle.context.cards, bundle.cwe_profiles, bundle.hypotheses, strict=True):
        kev_line = (f'- KEV: {escape(card.kev)}' if kev is None
                    else f'- KEV: {escape(kev_text(kev.status(card.cve)))}')
        lines += ['', f'## {escape(card.cve)}', '', f'- Title: {escape(card.title or "not stated")}',
                  f'- CWE: {escape(card.stated_cwe)} (stated by vendor, {card.source_kind.upper()})'
                  if card.stated_cwe else '- CWE: not stated by the vendor',
                  f'- Applicability: {escape(card.applicability or "unknown")}', kev_line,
                  f'- CWE profile status: {escape(profile.status)}']
        lines += [f'- Hypothesis {escape(h.rule_id)} (rule revision {h.rule_revision}, {escape(h.cwe_id)}): '
                  f'expected operations: {escape("; ".join(h.expected_operations))}. Caveat: {escape(h.caveat)}'
                  for h in hypothesis.hypotheses]
        lines += [f'- Unknown: {escape(u)}' for u in hypothesis.unknowns]
    return lines


def to_markdown(bundle: ContextBundle, escape: Escape, kev: ExploitationLookup | None = None) -> str:
    """``kev`` None keeps each card's stored KEV state (as attached); a lookup applies the catalog in use now and the
    header names it (KB-integration-plan A-13). ``CARD_KEV`` maps its answers to the card vocabulary."""
    lead = bundle.lead
    lines = ['# KB / CVE advisory context', '', f'- Lead: {escape(lead.kind)} {escape(lead.value)}',
             f'- Context key: {bundle.context_key}', f'- Investigation: {bundle.investigation_id} '
             f'(prepared from revision {bundle.base_revision})', f'- Edge set digest: {bundle.edge_set_digest}',
             f'- Rules digest: {bundle.rules_digest}', f'- Lexicon digest: {bundle.lexicon_digest}']
    if bundle.older_sha:
        lines.append(f'- Older SHA-256: {bundle.older_sha}')
        lines.append(f'- Newer SHA-256: {bundle.newer_sha}')
    if kev is not None:
        source = kev_source_of(kev)
        lines.append(f'- KEV source: {escape(source.text)}'
                     + (f' Snapshot {source.snapshot_id}.' if source.snapshot_id else ''))
    lines += _card_lines(bundle, escape, kev)
    lines += ['', '## Sources', ''] + [f'- {escape(s.kind)} {escape(s.release_id or "")} {s.sha256}'.rstrip()
                                       for s in bundle.sources]
    lines += ['', '## Coverage', ''] + [f'- {escape(c.state)}: {len(c.inspected_ids)} of {len(c.requested_ids)} '
                                        'requested documents inspected' for c in bundle.context.coverage]
    lines += ['', '## Unknowns', ''] + [f'- {escape(u)}' for u in bundle.context.unknowns]
    lines += ['', '## Limitations', ''] + [f'- {escape(x)}' for x in bundle.context.limitations]
    return '\n'.join(lines) + '\n'
