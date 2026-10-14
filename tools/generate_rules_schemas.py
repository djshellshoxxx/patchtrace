"""Regenerate the yara-rules/1 artefacts (YRX-integration-plan section 7).

Run from the repository root:

    PYTHONPATH=src python tools/generate_rules_schemas.py          # write
    PYTHONPATH=src python tools/generate_rules_schemas.py --check  # exit 1 on drift

Outputs, deterministic and offline, in ``docs/schemas/rules/``: one JSON Schema per record plus ``examples.json`` (several
valid and several invalid examples per record; every invalid one names the validator message it must trigger). All data
is SYNTHETIC (Example OS, far-future dates, made-up hashes); nothing here describes a real build.
"""
from __future__ import annotations

import copy
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
OUT = ROOT / 'docs' / 'schemas' / 'rules'

CONTRACTS = ('EngineStamp', 'FunctionRef', 'PairSource', 'CallPin', 'BytesFeature', 'StringFeature', 'ImportFeature',
             'ApiRef', 'CapabilityFeature', 'Gate', 'RuleCandidate', 'RuleDecision', 'RuleVersion', 'TargetRef',
             'CellResult', 'RunRule', 'MatrixRun', 'ExportRecord', 'WorkerRule', 'WorkerTarget', 'WorkerLimits',
             'WorkerRequest', 'Diagnostic', 'LintResult', 'WorkerError', 'WorkerResult')
# Records that are stored or exchanged on their own carry a `contract` constant; the rest only live inside those.
STANDALONE = {'RuleCandidate': 'yara-rules/1', 'RuleDecision': 'yara-rules/1', 'RuleVersion': 'yara-rules/1',
              'MatrixRun': 'yara-rules/1', 'ExportRecord': 'yara-rules/1', 'WorkerRequest': 'rules-worker/1',
              'WorkerResult': 'rules-worker/1'}

A, B, C, D = 'a' * 64, 'b' * 64, 'c' * 64, 'd' * 64
LINEAGE = '0123456789ab' + 'c' * 52
CANDIDATE, DECISION, VERSION1, VERSION2 = '1' * 64, '2' * 64, '3' * 64, '4' * 64
STAMP = '2099-03-01T00:00:00Z'
PATTERN = '48 83 EC 28 31 C9 BA 01 00 00 00 90 48 FF 15 ?? ?? ?? ?? 48 83 C4 28 C3'
STATEMENT = 'A match means a file contains this pattern. It does not show whether the file is affected by a flaw.'


def example_rule_text(side: str = 'older', version: int = 1) -> str:
    """A rule in exactly the layout of `yara_x.Formatter` (aligned `=`, `for ... in X:` and `a..b` without spaces)."""
    meta = [('patchtrace_rule_id', f'"{LINEAGE[:12]}.v{version}"'), ('patchtrace_version', str(version)),
            ('patchtrace_project_id', '"project-1"'), ('older_sha256', f'"{A}"'), ('newer_sha256', f'"{B}"'),
            ('side', f'"{side}"'), ('change', '"removed"'), ('function_older', '"0x104d"'),
            ('statement', f'"{STATEMENT}"')]
    width = max(len(key) for key, _ in meta)
    lines = ['import "pe"', '', f'rule PT_{LINEAGE[:12]}_{side}: patchtrace {side}_side {{', '  meta:']
    lines += [f'    {key.ljust(width)} = {value}' for key, value in meta]
    lines += ['', '  strings:', '    $b = { ' + PATTERN + ' }', '', '  condition:',
              '    uint16(0) == 0x5A4D and pe.is_pe and pe.machine == pe.MACHINE_AMD64 and '
              'for any s in pe.sections: (s.characteristics & pe.SECTION_MEM_EXECUTE != 0 and '
              '$b in (s.raw_data_offset..s.raw_data_offset + s.raw_data_size)) and '
              'pe.imports("KERNEL32.dll", "TerminateProcess")', '}', '']
    return '\n'.join(lines)


def valid_records() -> dict:
    """Valid SYNTHETIC records per contract (a list each), built from the real models so they are valid by construction."""
    from patchtrace.rules import contracts as c
    from patchtrace.rules.limits import DEFAULT_LIMITS

    stamp = c.EngineStamp(version='1.21.0', version_source='metadata', decoder='iced-x86', decoder_version='1.21.0')
    scan_only = c.EngineStamp(version='1.21.0', version_source='pin')
    removed = c.FunctionRef(rva=0x104d, size=24, extent='pdata')
    leaf = c.FunctionRef(name='example_leaf', rva=0x2000, extent='unknown')
    modified_old = c.FunctionRef(rva=0x104d, size=38, extent='unified-ir')
    modified_new = c.FunctionRef(rva=0x108d, size=38, extent='unified-ir')
    pair = c.PairSource(project_id='project-1', revision=3, run_id='run-1', older_sha256=A, newer_sha256=B,
                        match_id='match-1', category='removed', review='accepted', materiality='material',
                        analyst_confirmed_material=False, finding_id='finding-1', older=removed)
    unvetted_pair = c.PairSource(project_id='project-1', revision=3, run_id='run-1', older_sha256=A, newer_sha256=B,
                                 match_id='match-2', category='modified', review='accepted', materiality='unknown',
                                 analyst_confirmed_material=True, cwe='CWE-20', older=modified_old,
                                 newer=modified_new)
    pin = c.CallPin(disp_offset=15, end_offset=19, dll='KERNEL32.dll', name='TerminateProcess')
    bytes_feature = c.BytesFeature(included=True, side='older', window_rva=0x104d, length=24, pattern=PATTERN,
                                   literal=20, longest_run=15, mask=('rip-disp',), mask_source='iced-x86',
                                   pins=(pin,), source_hits=1, other_hits=0, separation='older-only')
    string = c.StringFeature(included=False, side='newer', value_sha256=C, length=8, text=r'Example\x00',
                             encoding='ascii', offset=0x2210, evidence_run_id='tool-run-1', linked_by='file-level',
                             separation='newer-only')
    import_feature = c.ImportFeature(included=True, dll='KERNEL32.dll', name='TerminateProcess', origin='pe-imports',
                                     separation='older-only')
    ordinal_import = c.ImportFeature(included=False, dll='EXAMPLE.dll', ordinal=12, delay=True, origin='pe-imports',
                                     separation='unknown')
    api = c.ApiRef(dll='KERNEL32.dll', name='TerminateProcess')
    capability = c.CapabilityFeature(included=False, rule_id='terminate process',
                                     namespace='host-interaction/process/terminate',
                                     classification='removed-with-code', api_gates=(api,), separation='older-only')
    gates = (c.Gate(gate_id='elig', state='pass', measured='material', detail='Change reviewed as material'),
             c.Gate(gate_id='len', state='pass', measured=20, detail='20 literal bytes, longest run 15'),
             c.Gate(gate_id='wild', state='pass', measured=16, detail='4 of 24 bytes are wildcards'),
             c.Gate(gate_id='uniq', state='pass', measured=1),
             c.Gate(gate_id='sep', state='pass', measured=0),
             c.Gate(gate_id='compile', state='pass', measured=0, detail='no warnings'),
             c.Gate(gate_id='secret', state='pass', measured=0),
             c.Gate(gate_id='dist', state='unknown', detail='toolchain not checked'))
    text, text_hash = example_rule_text(), c.rule_text_sha256(example_rule_text())
    candidate = c.RuleCandidate(candidate_id=CANDIDATE, lineage_id=LINEAGE, direction='older', source=pair,
                                features=(bytes_feature, import_feature, capability, string),
                                rule_name=c.rule_name_for(LINEAGE, 'older'), rule_text=text, rule_sha256=text_hash,
                                gates=gates, engine=stamp, unvetted=False)
    accept = c.RuleDecision(decision_id=DECISION, candidate_id=CANDIDATE, action='accept',
                            analyst_label='Example: terminate process removed', note='SYNTHETIC example',
                            cve=('CVE-2099-10001',), kb=('KB5099001',), cwe=('CWE-404',), decided_at=STAMP)
    reject = c.RuleDecision(decision_id=D, candidate_id=CANDIDATE, action='reject', decided_at=STAMP)
    version1 = c.RuleVersion(version_id=VERSION1, lineage_id=LINEAGE, version=1, candidate_id=CANDIDATE,
                             decision_id=DECISION, rule_text=text, rule_sha256=text_hash, source=pair, engine=stamp,
                             created_at=STAMP)
    text2 = example_rule_text(version=2)
    version2 = c.RuleVersion(version_id=VERSION2, lineage_id=LINEAGE, version=2, supersedes=VERSION1,
                             candidate_id=D, decision_id=D, rule_text=text2, rule_sha256=c.rule_text_sha256(text2),
                             source=pair, engine=stamp, created_at=STAMP)
    older = c.TargetRef(target_id='t1', label='older.dll', role='older-anchor', sha256=A, size=4096, ordinal=1,
                        expect='hit', file_version='10.0.26100.5000', kb='KB5098000')
    newer = c.TargetRef(target_id='t2', label='newer.dll', role='series', sha256=B, size=4096, ordinal=2,
                        expect='no-hit', advisory_says='fixed', file_version='10.0.26100.5001', kb='KB5099001',
                        toolchain_flag='none')
    clean = c.TargetRef(target_id='t3', label='clean1.dll', role='clean', sha256=C, size=2048, expect='no-hit')
    cells = (c.CellResult(state='hit', hits=1, offsets=(589,), rvas=(0x104d,), elapsed_ms=3, verdict='as-expected'),
             c.CellResult(state='no-hit', hits=0, elapsed_ms=2, verdict='as-expected'),
             c.CellResult(state='not-scanned', reason='not-pe'))
    matrix = c.MatrixRun(run_id='run-test-1', cache_key=D, engine=scan_only, status='complete',
                         rules=(c.RunRule(version_id=VERSION1, rule_sha256=text_hash),),
                         targets=(older, newer, clean), cells=cells, limits=DEFAULT_LIMITS.as_dict(),
                         anomalies=('1 file was not a PE image',), finished_at=STAMP)
    export = c.ExportRecord(export_id=A, version_id=VERSION1, basename='example-rule.yar', sha256=B,
                            exported_at=STAMP, warnings=('not-tested',))
    wrule = c.WorkerRule(name=VERSION1, text=text)
    wtarget = c.WorkerTarget(target_id='t1', path='/example/older.bin', sha256=A, size=4096)
    wlimits = c.WorkerLimits()
    result_path = '/example/scratch/out.json'
    probe_request = c.WorkerRequest(op='probe', result=result_path)
    lint_request = c.WorkerRequest(op='lint', rules=(wrule,), result=result_path)
    scan_request = c.WorkerRequest(op='scan', rules=(wrule,), targets=(wtarget,), limits=wlimits, result=result_path)
    warning = c.Diagnostic(code='text_as_hex', title='hex pattern could be written as text literal', line=14, column=5)
    failure = c.Diagnostic(code='E018', title='slow pattern', line=14, column=5)
    lint_ok = c.LintResult(name=VERSION1, ok=True, warnings=(warning,), identifiers=(f'PT_{LINEAGE[:12]}_older',),
                           imports=('pe',), patterns=1, formatter_stable=True)
    lint_bad = c.LintResult(name=VERSION2, ok=False, errors=(failure,))
    error = c.WorkerError(code='PT-RULE-UNAVAILABLE', message='The rule engine is not available', reason='engine-missing')
    return {
        'EngineStamp': [stamp, scan_only], 'FunctionRef': [removed, leaf], 'PairSource': [pair, unvetted_pair],
        'CallPin': [pin], 'BytesFeature': [bytes_feature], 'StringFeature': [string],
        'ImportFeature': [import_feature, ordinal_import], 'ApiRef': [api], 'CapabilityFeature': [capability],
        'Gate': list(gates[:1] + gates[-1:]), 'RuleCandidate': [candidate], 'RuleDecision': [accept, reject],
        'RuleVersion': [version1, version2], 'TargetRef': [older, newer, clean],
        'CellResult': [*cells, c.CellResult(state='timeout', elapsed_ms=30000),
                       c.CellResult(state='error', reason='scan-error')],
        'RunRule': [c.RunRule(version_id=VERSION1, rule_sha256=text_hash)], 'MatrixRun': [matrix],
        'ExportRecord': [export], 'WorkerRule': [wrule], 'WorkerTarget': [wtarget], 'WorkerLimits': [wlimits],
        'WorkerRequest': [probe_request, lint_request, scan_request], 'Diagnostic': [warning, failure],
        'LintResult': [lint_ok, lint_bad], 'WorkerError': [error],
        'WorkerResult': [
            c.WorkerResult(op='probe', kind='ok', engine=stamp, modules=('hash', 'math', 'pe')),
            c.WorkerResult(op='scan', kind='ok', engine=scan_only, lint=(lint_ok,),
                           cells=(c.CellResult(state='hit', hits=1, offsets=(589,), rvas=(0x104d,), elapsed_ms=3),)),
            c.WorkerResult(op='lint', kind='error', error=error)]}


def _set(path: str, value):
    """Mutator: set a dotted path (list indexes are numbers) in an example document."""
    def mutate(doc):
        node = doc
        *head, last = path.split('.')
        for part in head:
            node = node[int(part)] if isinstance(node, list) else node[part]
        node[int(last) if isinstance(node, list) else last] = value
    return mutate


def _drop(path: str):
    def mutate(doc):
        node = doc
        *head, last = path.split('.')
        for part in head:
            node = node[int(part)] if isinstance(node, list) else node[part]
        del node[last]
    return mutate


# record -> (index of the valid example it mutates, mutator, reason, substring the validation error must contain)
SPECIFIC_INVALID = {
    'EngineStamp': [(0, _set('decoder_version', None), 'a decoder has a version', 'a decoder has a version'),
                    (0, _set('version', '1.21.0 '), 'version text is a token', 'string_pattern_mismatch')],
    'FunctionRef': [(0, _set('extent', 'unknown'), 'a size needs a verified extent', 'a size needs a verified extent'),
                    (1, _set('size', 24), 'an unknown extent has no size', 'a size needs a verified extent')],
    'PairSource': [(0, _set('older', None), 'a removed pair has its older function', 'exactly the functions'),
                   (0, _set('newer_sha256', A), 'the two builds differ', 'the older and newer builds must differ'),
                   (0, _set('review', 'unreviewed'), 'only accepted pairs', 'literal_error')],
    'CallPin': [(0, _set('end_offset', 17), 'a 4-byte displacement fits before the end',
                 'must end at or before the instruction end')],
    'BytesFeature': [
        (0, _set('literal', 21), 'metrics are the pattern\'s own', 'must be the pattern'),
        (0, _set('mask', []), 'wildcards need a mask kind', 'wildcards need the mask kinds'),
        (0, _set('pins.0.disp_offset', 14), 'a pinned displacement is wildcarded', 'must be wildcarded'),
        (0, _set('other_hits', 2), 'a window found in the other build is not a separator', 'separation must be'),
        (0, _set('pattern', '48 83'), 'a window is at least 16 bytes', 'string_pattern_mismatch')],
    'StringFeature': [
        (0, _set('text', 'say "hi"'), 'a bare quote would break out of the string', 'string_pattern_mismatch'),
        (0, _set('text', 'back\\'), 'a trailing backslash would escape the quote', 'string_pattern_mismatch'),
        (0, _set('length', 3), 'length is the escaped text\'s byte count', 'number of bytes'),
        (0, _set('separation', 'older-only'), 'a string present in the newer build is not older-only',
         'cannot exist only in the other build')],
    'ImportFeature': [(0, _set('ordinal', 3), 'name and ordinal are exclusive', 'exactly one of name and ordinal'),
                      (0, _drop('name'), 'an import has a name or an ordinal', 'exactly one of name and ordinal')],
    'CapabilityFeature': [(0, _set('separation', 'newer-only'), 'the classification fixes the side',
                           'removed-with-code means older-only'),
                          (0, _set('classification', 'newly-detectable'), 'only localized changes', 'literal_error')],
    'Gate': [(0, _set('gate_id', 'score'), 'gates are a closed list', 'literal_error'),
             (0, _set('measured', 1.5), 'a measured number is an integer', 'int_type')],
    'RuleCandidate': [
        (0, _set('rule_sha256', A), 'the hash is of the text', 'not the hash of rule_text'),
        (0, _set('rule_name', 'PT_ffffffffffff_older'), 'the name derives from the lineage', 'rule_name must be'),
        (0, _set('direction', 'newer'), 'a removed pair has no newer function', 'needs a newer function'),
        (0, _set('features.0.separation', 'both-sides'), 'delta, not inventory', 'separation must be'),
        (0, _set('gates', [{'gate_id': 'sep', 'state': 'pass'}, {'gate_id': 'len', 'state': 'pass'}]),
         'gates are in canonical order', 'canonical order'),
        (0, _set('unvetted', True), 'unvetted means confirmed by the analyst only', 'unvetted is exactly'),
        (0, _set('rule_text', example_rule_text().replace('\n', '\r\n')), 'rule text is LF-only ASCII',
         'LF line ends only')],
    'RuleDecision': [(0, _set('analyst_label', None), 'accepting needs a label', 'needs a label'),
                     (1, _set('analyst_label', 'late label'), 'a label belongs to accept', 'belong to an accept'),
                     (0, _set('analyst_label', 'x‮y'), 'a bidi override is refused', 'bidirectional'),
                     (0, _set('cve', ['CVE-2099-1']), 'advisory ids are validated', 'string_pattern_mismatch')],
    'RuleVersion': [(1, _set('supersedes', None), 'a later version supersedes its predecessor', 'supersedes'),
                    (0, _set('supersedes', A), 'version 1 supersedes nothing', 'supersedes'),
                    (0, _set('lineage_id', D), 'the text belongs to the lineage', 'rule of this lineage')],
    'TargetRef': [(0, _set('role', 'clean'), 'a clean file has no ordinal', 'no series ordinal'),
                  (2, _set('role', 'series'), 'a series build has an ordinal', 'has an ordinal'),
                  (0, _set('label', 'a\nb'), 'a label is one line', 'single line')],
    'CellResult': [(0, _set('hits', 0), 'a hit has a match', 'at least one match'),
                   (1, _set('hits', None), 'no-hit means zero matches', 'no-hit means zero'),
                   (2, _set('hits', 0), 'an unscanned file has no hit count', 'no hit count'),
                   (2, _set('reason', 'because'), 'not-scanned reasons are a closed list', 'one reason'),
                   (0, _set('offsets', [589, 589]), 'offsets ascend', 'strictly ascending'),
                   (3, _set('verdict', 'as-expected'), 'a timeout is never scored', 'never scored')],
    'RunRule': [(0, _set('version_id', 'xyz'), 'ids are SHA-256 hex', 'string_pattern_mismatch')],
    'MatrixRun': [(0, _set('cells', []), 'cells are targets x rules', 'targets x rules'),
                  (0, _set('targets.1.target_id', 't1'), 'target ids are unique', 'must be unique'),
                  (0, _set('status', 'verified'), 'status is a closed list', 'literal_error')],
    'ExportRecord': [(0, _set('basename', 'dir/rule.yar'), 'a basename has no path', 'string_pattern_mismatch'),
                     (0, _set('warnings', ['b', 'a']), 'warnings are sorted', 'sorted and unique')],
    'WorkerRule': [(0, _set('text', 'rule x { condition: true }é'), 'rule text is ASCII', 'printable ASCII')],
    'WorkerTarget': [(0, _set('sha256', 'ABC'), 'hashes are lower-case hex', 'string_pattern_mismatch'),
                     (0, _set('path', ''), 'a path is not empty', 'string_too_short')],
    'WorkerLimits': [(0, _set('target_timeout_s', 0), 'a timeout is at least one second', 'greater_than_equal'),
                     (0, _set('memory_bytes', 1), 'the memory cap leaves room to start', 'greater_than_equal')],
    'WorkerRequest': [(0, _set('op', 'execute'), 'ops are a closed list', 'literal_error'),
                      (1, _set('targets', [{'target_id': 't1', 'path': '/x', 'size': 1}]),
                       'a lint request has no targets', 'carries rules and no targets'),
                      (2, _set('rules', []), 'a scan request needs rules', 'carries rules and targets'),
                      (2, _set('targets.0.target_id', 'a b'), 'target ids are keys', 'string_pattern_mismatch')],
    'Diagnostic': [(0, _set('title', 'line\nbreak'), 'a title is one line', 'single line'),
                   (0, _set('line', 0), 'lines start at 1', 'greater_than_equal')],
    'LintResult': [(0, _set('errors', [{'code': 'E018', 'title': 'slow pattern'}]), 'ok means no errors',
                    'ok means no errors'),
                   (1, _set('formatter_stable', True), 'only a compiled rule is stable', 'only a rule that compiled')],
    'WorkerError': [(0, _set('code', 'PT-RULE-OTHER'), 'codes are a closed list', 'literal_error')],
    'WorkerResult': [(0, _set('lint', [{'name': 'x', 'ok': True}]), 'a probe carries its own sections',
                      'exactly its own sections'),
                     (1, _set('cells.0.verdict', 'as-expected'), 'the worker scores nothing', 'scores nothing'),
                     (1, _set('kind', 'error'), 'an error result carries the error alone', 'error alone'),
                     (2, _set('engine', {'version': '1.21.0', 'version_source': 'pin'}),
                      'an error result has no engine', 'error alone')]}


def build_examples() -> dict:
    out = {}
    for name, records in valid_records().items():
        valid = [json.loads(r.model_dump_json()) for r in records]
        invalid = [{'example': valid[0] | {'unexpected_field': 1}, 'reason': 'extra fields are forbidden',
                    'match': 'extra_forbidden'}]
        if name in STANDALONE:
            invalid.append({'example': valid[0] | {'contract': 'yara-rules/2'},
                            'reason': 'unsupported future contract version', 'match': 'literal_error'})
        for index, mutate, reason, match in SPECIFIC_INVALID.get(name, ()):
            doc = copy.deepcopy(valid[index])
            mutate(doc)
            invalid.append({'example': doc, 'reason': reason, 'match': match})
        out[name] = {'valid': valid, 'invalid': invalid}
    return out


def models() -> dict:
    from patchtrace.rules import contracts
    return {name: getattr(contracts, name) for name in CONTRACTS}


def render_contract_schemas() -> dict[str, str]:
    out = {}
    for name, model in models().items():
        schema = model.model_json_schema()
        schema['$id'] = f'https://patchtrace.local/schemas/rules/1/{name}.json'
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
