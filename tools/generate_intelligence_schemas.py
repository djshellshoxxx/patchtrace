"""Regenerate the intelligence/1 artefacts (SPEC-28a/b, csaf-cve-interpretation-engine.md sections B and E).

Run from the repository root:

    PYTHONPATH=src python tools/generate_intelligence_schemas.py          # write
    PYTHONPATH=src python tools/generate_intelligence_schemas.py --check  # exit 1 on drift

Outputs, all deterministic and offline:
- ``docs/schemas/intelligence/<Model>.json``: JSON Schemas of the ``intelligence/1`` contracts;
- ``docs/schemas/intelligence/examples.json``: one valid and several invalid examples per contract, built by
  running the real pipeline over the SYNTHETIC fixtures in ``tests/fixtures/csaf/``;
- ``src/patchtrace/intelligence/csaf/schema_data.py``: the CSAF 2.0 and provider-metadata constraint tables,
  derived from the vendored OASIS schemas (``docs/schemas/intelligence/oasis-csaf-2.0``, hashes pinned).

Kept apart from ``tools/generate_schemas.py``, which another track owns.
"""
from __future__ import annotations

import copy
import hashlib
import json
import pprint
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OASIS = ROOT / 'docs' / 'schemas' / 'intelligence' / 'oasis-csaf-2.0'
OUT = ROOT / 'docs' / 'schemas' / 'intelligence'
SCHEMA_DATA = ROOT / 'src' / 'patchtrace' / 'intelligence' / 'csaf' / 'schema_data.py'
PINNED = {'csaf_json_schema.json': '29c114b35b0a30831f1674f2ab8b3ed9b2890cfeaa63b924ac6ed9d70ef44262',
          'provider_json_schema.json': '0270d0cfadf5202ff83a63502012a407e0e8ec3194a07296f13641c9f5630aba'}
CSAF_ID = 'https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json'
SUPPORTED = frozenset({'type', 'required', 'properties', 'items', 'enum', 'pattern', 'minLength', 'minItems',
                       'uniqueItems', 'minProperties', 'maxProperties', 'format', 'oneOf', '$ref', '$defs'})
ANNOTATIONS = frozenset({'title', 'description', 'examples', 'default', '$comment', '$id', '$schema'})
EXTERNAL = {'https://www.first.org/cvss/cvss-v2.0.json': 'cvss-v2.0',
            'https://www.first.org/cvss/cvss-v3.0.json': 'cvss-v3.0',
            'https://www.first.org/cvss/cvss-v3.1.json': 'cvss-v3.1'}
FORMATS = frozenset({'date-time', 'uri'})
TYPES = frozenset({'object', 'array', 'string', 'boolean', 'number', 'integer'})

CONTRACTS = ('ValidationReport', 'AdvisorySource', 'AdvisoryFacts', 'CVEFact', 'ArtifactIdentity',
             'ApplicabilityReport', 'CweProfile', 'Rule', 'HypothesisSet', 'AnchorSet', 'IntelligenceReport')

NOTICE = '''Copyright © OASIS Open 2022. All Rights Reserved.

All capitalized terms in the following text have the meanings assigned to them in the OASIS Intellectual
Property Rights Policy (the "OASIS IPR Policy"). The full Policy may be found at the OASIS website.

This document and translations of it may be copied and furnished to others, and derivative works that
comment on or otherwise explain it or assist in its implementation may be prepared, copied, published, and
distributed, in whole or in part, without restriction of any kind, provided that the above copyright notice
and this section are included on all such copies and derivative works. However, this document itself may
not be modified in any way, including by removing the copyright notice or references to OASIS, except as
needed for the purpose of developing any document or deliverable produced by an OASIS Technical Committee
(in which case the rules applicable to copyrights, as set forth in the OASIS IPR Policy, must be followed)
or as required to translate it into languages other than English.

The limited permissions granted above are perpetual and will not be revoked by OASIS or its successors or
assigns.

This document and the information contained herein is provided on an "AS IS" basis and OASIS DISCLAIMS ALL
WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION
HEREIN WILL NOT INFRINGE ANY OWNERSHIP RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A
PARTICULAR PURPOSE.'''


def _load_pinned(name: str) -> dict:
    raw = (OASIS / name).read_bytes()
    digest = hashlib.sha256(raw).hexdigest()
    if digest != PINNED[name]:
        raise SystemExit(f'{name}: SHA-256 {digest} does not match the pinned {PINNED[name]}')
    return json.loads(raw)


def _resolve(root: dict, pointer: str) -> dict:
    node = root
    for part in pointer.lstrip('/').split('/'):
        node = node[part.replace('~1', '/').replace('~0', '~')]
    return node


def strip(node: dict, csaf_root: dict | None = None) -> dict:
    """Keep only validation keywords; fail on anything the stdlib interpreter does not support."""
    out: dict = {}
    for key in sorted(node):
        value = node[key]
        if key in ANNOTATIONS:
            continue
        if key not in SUPPORTED:
            raise SystemExit(f'unsupported JSON Schema keyword {key!r}: extend csaf/validate.py first')
        if key in ('$defs', 'properties'):
            out[key] = {name: strip(sub, csaf_root) for name, sub in sorted(value.items())}
        elif key == 'items':
            out[key] = strip(value, csaf_root)
        elif key == 'oneOf':
            out[key] = [strip(sub, csaf_root) for sub in value]
        elif key == '$ref':
            if value.startswith('#/$defs/'):
                out['$ref'] = value
            elif value in EXTERNAL:
                out['$external'] = EXTERNAL[value]
            elif value.startswith(CSAF_ID + '#/') and csaf_root is not None:
                out.update(strip(_resolve(csaf_root, value.split('#', 1)[1]), None))
            else:
                raise SystemExit(f'unsupported $ref {value!r}')
        elif key == 'format':
            if value not in FORMATS:
                raise SystemExit(f'unsupported format {value!r}')
            out[key] = value
        elif key == 'type':
            if value not in TYPES:
                raise SystemExit(f'unsupported type {value!r}')
            out[key] = value
        else:
            out[key] = copy.deepcopy(value)
    return out


def render_schema_data() -> str:
    csaf = _load_pinned('csaf_json_schema.json')
    provider = _load_pinned('provider_json_schema.json')
    csaf_table = strip(csaf)
    provider_table = strip(provider, csaf_root=csaf)
    notice = '\n'.join(('# ' + line).rstrip() for line in NOTICE.splitlines())
    return (
        '"""GENERATED by tools/generate_intelligence_schemas.py from the vendored OASIS CSAF 2.0 schemas; do not edit.\n'
        '\n'
        'Validation-keyword subset (titles, descriptions and examples removed; FIRST CVSS references replaced by\n'
        '``$external`` markers) of ``docs/schemas/intelligence/oasis-csaf-2.0/csaf_json_schema.json`` and\n'
        '``provider_json_schema.json``. The OASIS notice below applies to this derived table.\n'
        '"""\n'
        f'{notice}\n'
        '# ruff: noqa\n'
        '\n'
        f"CSAF_SCHEMA_SHA256 = '{PINNED['csaf_json_schema.json']}'\n"
        f"PROVIDER_SCHEMA_SHA256 = '{PINNED['provider_json_schema.json']}'\n"
        '\n'
        f'CSAF_SCHEMA = {pprint.pformat(csaf_table, width=110, sort_dicts=True)}\n'
        '\n'
        f'PROVIDER_SCHEMA = {pprint.pformat(provider_table, width=110, sort_dicts=True)}\n')


def render_contract_schemas() -> dict[str, str]:
    from patchtrace.intelligence import contracts
    out = {}
    for name in CONTRACTS:
        schema = getattr(contracts, name).model_json_schema()
        schema['$id'] = f'https://patchtrace.local/schemas/intelligence/1/{name}.json'
        schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
        out[f'{name}.json'] = json.dumps(schema, indent=2, sort_keys=True, ensure_ascii=False) + '\n'
    return out


def render_examples() -> str:
    return json.dumps(build_examples(), indent=2, sort_keys=True, ensure_ascii=False) + '\n'


def _valid_records() -> dict:
    """One valid record per contract, produced by the real pipeline from the SYNTHETIC rev1 fixture."""
    from patchtrace.intelligence import anchors, hypotheses, lexicon
    from patchtrace.intelligence.contracts import ArtifactIdentity, IntelligenceReport, SourceSummary
    from patchtrace.intelligence.csaf import applicability, normalize, validate
    raw = (ROOT / 'tests' / 'fixtures' / 'csaf' / 'synthetic-advisory-rev1.json').read_bytes()
    doc, report = validate.load_document(raw)
    facts = normalize.normalize(doc, report, hashlib.sha256(raw).hexdigest())
    source = normalize.make_source(doc, raw, origin='local-import', uri=None, file_name='synthetic-advisory-rev1.json',
                                   retrieved_at='2099-03-01T00:00:00Z')
    cve = 'CVE-2099-10001'
    fact = facts.vulnerability(cve)
    profile = lexicon.classify(fact)
    hyps = hypotheses.hypotheses_for(profile)
    older = ArtifactIdentity(side='older', sha256='dc71b8420acc68418eaebfb8a4848cd2f63626125868e9977f017010c8d30215',
                             facts_state='verified-bytes')
    newer = ArtifactIdentity(side='newer', sha256='4af23bcb773054ad469c57363d50e2b53a6590bfba2286f16a06b4fb1440a168',
                             facts_state='verified-bytes')
    applies = applicability.resolve(cve, [facts], older, newer)
    hints = anchors.anchors_for(cve, [facts], (older, newer), hyps)
    summary = SourceSummary(source=source, facts_id=facts.facts_id, superseded=False, cves=facts.cves(),
                            validation_warnings=len(report.warnings))
    full = IntelligenceReport(cve=cve, sources=(summary,), facts=(fact,), applicability=applies, cwe_profile=profile,
                              hypotheses=hyps, anchors=hints,
                              limitations=('SYNTHETIC example generated from tests/fixtures/csaf',))
    return {'ValidationReport': report, 'AdvisorySource': source, 'AdvisoryFacts': facts, 'CVEFact': fact,
            'ArtifactIdentity': older, 'ApplicabilityReport': applies, 'CweProfile': profile,
            'Rule': hypotheses.RULES[0], 'HypothesisSet': hyps, 'AnchorSet': hints, 'IntelligenceReport': full}


SPECIFIC_INVALID = {
    'AdvisorySource': ({'uri': 'https://example.invalid/x.json'}, 'a local import never carries a URI'),
    'ArtifactIdentity': ({'facts_state': 'record-only', 'file_version': '1.2.3.4'},
                         'bytes-derived identity facts require verified bytes'),
    'CweProfile': ({'status': 'vague'}, 'vague text never carries a confident classification'),
    'CVEFact': ({'assessment': 'verified'}, 'an advisory fact is a claim, never a verification'),
    'HypothesisSet': ({'hypotheses': [], 'unknowns': []}, 'an empty hypothesis set must state an explicit unknown'),
}


def build_examples() -> dict:
    out = {}
    for name, record in _valid_records().items():
        valid = json.loads(record.model_dump_json())
        invalid = [{'example': valid | {'unexpected_field': 1}, 'reason': 'extra fields are forbidden'},
                   {'example': valid | {'contract': 'intelligence/2'}, 'reason': 'unsupported future contract version'}]
        if name in SPECIFIC_INVALID:
            patch, reason = SPECIFIC_INVALID[name]
            invalid.append({'example': valid | patch, 'reason': reason})
        out[name] = {'valid': valid, 'invalid': invalid}
    return out


def render() -> dict[Path, str]:
    """Every generated file and its exact text (a pure function of the repository contents)."""
    files = {SCHEMA_DATA: render_schema_data()}
    files.update({OUT / name: text for name, text in render_contract_schemas().items()})
    files[OUT / 'examples.json'] = render_examples()
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
