"""Regenerate the kbcorrelation/1 artefacts (KB-integration-plan section 7.2 and 7.4).

Run from the repository root:

    PYTHONPATH=src python tools/generate_kbc_schemas.py          # write
    PYTHONPATH=src python tools/generate_kbc_schemas.py --check  # exit 1 on drift

Outputs, deterministic and offline, in ``docs/schemas/kbcorrelation/``: one JSON Schema per contract plus
``examples.json`` (one valid and several invalid examples per contract, all SYNTHETIC: KB5099001, Example OS).
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'kbcorrelation'

CONTRACTS = ('SourceDoc', 'SourceRef', 'SearchScope', 'Coverage', 'ProductScope', 'KbCveEdge', 'ComponentHint',
             'BuildRow', 'BinaryRef', 'PairProposal', 'PairPlan', 'Attempt', 'AnalystDecision',
             'InvestigationRevision', 'ProjectLink', 'ContextReport', 'LeadRow', 'KbcIssue', 'OperationResult')
ERRORS_MODULE = frozenset({'KbcIssue', 'OperationResult'})

A, B, C, D = 'a' * 64, 'b' * 64, 'c' * 64, 'd' * 64
STAMP = '2099-03-01T00:00:00Z'
UUID = '12345678-1234-4234-8234-123456789abc'


def _did(domain: str, payload) -> str:
    from patchtrace.enrichment.identity import domain_id
    return domain_id(domain, 1, payload)


def valid_records() -> dict:
    """One valid SYNTHETIC record per contract."""
    from patchtrace.kbcorrelation import contracts as c
    from patchtrace.kbcorrelation import errors as e
    doc_id = _did('kbc.source', {'kind': 'cvrf-month', 'sha256': A})
    source = c.SourceDoc(doc_id=doc_id, kind='cvrf-month', sha256=A, size=1234, origin='local-import',
                         retrieved_at=STAMP, release_id='2099-Mar', dialect='cvrf-1.2-synthetic', parser_version=1,
                         authenticity='unverified-local-file', lineage='msrc', object_path=f'objects/aa/{A}.gz')
    ref = c.SourceRef(doc_id=doc_id, pointer='/Vulnerability/0/Remediations/0', assertion='advisory_fact')
    scope = c.SearchScope(kind='selected_months', months=('2099-Feb', '2099-Mar'))
    coverage = c.Coverage(coverage_id=B, source_kind='cvrf-month', scope=scope, state='complete_in_scope',
                          requested_ids=('2099-Feb', '2099-Mar'), inspected_ids=('2099-Feb', '2099-Mar'),
                          retrieved_at=STAMP)
    product = c.ProductScope(scope_id=C, family='windows-client', release='24H2', architecture='amd64',
                             display_name='Example OS 24H2 amd64', mapping='candidate', alias_catalog_version=1,
                             source_product_ids=(c.ProductRef(doc_id=doc_id, product_id='99001'),))
    edge_key = {'kb': 'KB5099001', 'cve': 'CVE-2099-10001', 'scope_id': C, 'relation': 'vendor-remediation',
                'doc_id': doc_id, 'pointer': ref.pointer}
    edge = c.KbCveEdge(edge_id=_did('kbc.edge', edge_key), kb='KB5099001', cve='CVE-2099-10001', scope_id=C,
                       relation='vendor-remediation', ref=ref, release_id='2099-Mar', fixed_build='26100.5001',
                       supersedes=('KB5098000',))
    hint = c.ComponentHint(hint_id=D, basename='examplesvc.dll', scope_id=C, tier='B', reasons=('named-in-title',),
                           claim_refs=(ref,))
    row = c.BuildRow(file_name='examplesvc.dll', sha256=A, version_key='10.0.26100', kb='KB5099001',
                     release_date=STAMP, release_version='5001', heading_class='standard', variant='full',
                     download='https://example.invalid/examplesvc.dll', record_sha256=B)
    older = c.BinaryRef(sha256=A, size=1000, basename='examplesvc.dll', machine='amd64',
                        file_version='10.0.26100.5000', build_ubr='26100.5000', origin='index-row',
                        availability='direct', authenticity='hash-matched-to-index')
    newer = older.model_copy(update={'sha256': B, 'file_version': '10.0.26100.5001', 'build_ubr': '26100.5001'})
    pair_key = {'older': A, 'newer': B, 'scope_id': C, 'window_id': 'w1'}
    pair = c.PairProposal(pair_id=_did('kbc.pair', pair_key), older=older, newer=newer, scope_id=C, window_id='w1',
                          bytes_state='pending', lineage_state='index-adjacent', fix_boundary='source-supported',
                          window=('KB5099001',), window_complete=True, grade='A', tier='B')
    plan = c.PairPlan(plan_sha=D, pair_id=pair.pair_id, hosts=('example.invalid',), destination_policy='private-staging',
                      requests=(c.PlanRequest(method='GET', url='https://example.invalid/examplesvc.dll',
                                              bytes=1000, why='older binary'),),
                      expected=(c.ExpectedFile(sha256=A, size=1000),))
    attempt = c.Attempt(op='plan', plan_sha=D, stage='preview', result='ok', created_at=STAMP)
    decision = c.AnalystDecision(op='choose-product', prior='NEEDS_PRODUCT', next='PRODUCT_SELECTED',
                                 reason='only one scope fits', created_at=STAMP)
    revision = c.InvestigationRevision(investigation_id=UUID, revision=2, parent=1,
                                       lead=c.Lead(kind='kb', value='KB5099001', raw='kb5099001'),
                                       state='PRODUCT_SELECTED', scope_ids=(C,), coverage_ids=(B,),
                                       selected_scope_id=C)
    link = c.ProjectLink(project_id='project-1', project_revision=3, older_sha=A, newer_sha=B, investigation_id=UUID,
                         revision=2, pair_id=pair.pair_id, state='attached')
    context = c.ContextReport(cards=(c.CveCard(cve='CVE-2099-10001', source_kind='cvrf', title='Synthetic issue'),),
                              coverage=(coverage,), unknowns=('no binary comparison has run',),
                              limitations=('documents are claims, not verification',),
                              hooks=('kb.meaning.coverage', 'kb.next.run_comparison'))
    lead = c.LeadRow(lead_id=A, level='component', group='CVE-2099-10001', subject='examplesvc.dll',
                     chips=(c.Chip(channel='documentary', state='supports', text='named in the advisory', ref=ref),
                            c.Chip(channel='code-change', state='not-run', text='no comparison yet')),
                     rank_basis='documentary tier, then name', nav=c.LeadNav(project_revision=0),
                     hooks=('kb.next.run_comparison',))
    issue = e.KbcIssue(code='PT-KBC-SCOPE', message='a finite search scope is required', source_id=None)
    result = e.OperationResult(status='partial', issues=(issue,), warnings=('2 of 24 documents unreadable',))
    return {'SourceDoc': source, 'SourceRef': ref, 'SearchScope': scope, 'Coverage': coverage,
            'ProductScope': product, 'KbCveEdge': edge, 'ComponentHint': hint, 'BuildRow': row, 'BinaryRef': older,
            'PairProposal': pair, 'PairPlan': plan, 'Attempt': attempt, 'AnalystDecision': decision,
            'InvestigationRevision': revision, 'ProjectLink': link, 'ContextReport': context, 'LeadRow': lead,
            'KbcIssue': issue, 'OperationResult': result}


SPECIFIC_INVALID = {
    'SourceDoc': ({'origin': 'https-fetch'}, 'a fetched document needs an https URI and a TLS authenticity'),
    'SearchScope': ({'months': []}, 'selected_months needs at least one month'),
    'Coverage': ({'inspected_ids': ['2099-Mar']}, 'complete_in_scope needs requested == inspected'),
    'ProductScope': ({'mapping': 'verified'}, 'string-derived scopes are never verified'),
    'KbCveEdge': ({'kb': 'KB123'}, 'KB syntax is KB + 4-10 ASCII digits'),
    'ComponentHint': ({'basename': '../evil.dll'}, 'basename must be a lowercase PE basename'),
    'PairProposal': ({'grade': 'X'}, 'grade X needs a hard block'),
    'PairPlan': ({'hosts': ['other.invalid']}, 'hosts must equal the planned request hosts'),
    'InvestigationRevision': ({'parent': None}, 'a later revision needs a parent'),
    'ProjectLink': ({'state': 'stale'}, 'stale needs stale_reasons'),
    'OperationResult': ({'status': 'ok'}, 'an ok result carries no issues'),
}


def build_examples() -> dict:
    out = {}
    for name, record in valid_records().items():
        valid = json.loads(record.model_dump_json())
        invalid = [{'example': valid | {'unexpected_field': 1}, 'reason': 'extra fields are forbidden'}]
        if 'contract' in valid:
            invalid.append({'example': valid | {'contract': 'kbcorrelation/2'},
                            'reason': 'unsupported future contract version'})
        if name in SPECIFIC_INVALID:
            patch, reason = SPECIFIC_INVALID[name]
            invalid.append({'example': valid | patch, 'reason': reason})
        out[name] = {'valid': valid, 'invalid': invalid}
    return out


def render_contract_schemas() -> dict[str, str]:
    from patchtrace.kbcorrelation import contracts, errors
    out = {}
    for name in CONTRACTS:
        model = getattr(errors if name in ERRORS_MODULE else contracts, name)
        schema = model.model_json_schema()
        schema['$id'] = f'https://patchtrace.local/schemas/kbcorrelation/1/{name}.json'
        schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
        out[f'{name}.json'] = json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    return out


def render() -> dict[Path, str]:
    """Every generated file and its exact text (a pure function of the repository contents)."""
    files = {OUT / name: text for name, text in render_contract_schemas().items()}
    files[OUT / 'examples.json'] = json.dumps(build_examples(), indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    return files


def main(argv: list[str]) -> int:
    check = '--check' in argv
    drift = []
    for path, text in render().items():
        if check:
            current = path.read_text(encoding='utf-8') if path.is_file() else None
            if current != text:
                drift.append(str(path.relative_to(ROOT)))
        else:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(text, encoding='utf-8', newline='\n')
    for item in drift:
        print(f'stale: {item}', file=sys.stderr)
    return 1 if drift else 0


if __name__ == '__main__':
    raise SystemExit(main(sys.argv[1:]))
