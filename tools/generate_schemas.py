"""Regenerate versioned public schemas; run from repository root."""
import json
from pathlib import Path

from patchtrace import models

NAMES = ['Artifact', 'ComparisonProject', 'AnalysisRun', 'BackendCapabilities',
         'FunctionRecord', 'FunctionMatch', 'DiffHunk', 'EvidenceReference',
         'AnalysisContext', 'InterpretationRun', 'Finding', 'Hypothesis',
         'AnalystAnnotation', 'JobEvent', 'ExportManifest']
root = Path('docs/schemas')
root.mkdir(parents=True, exist_ok=True)
for name in NAMES:
    schema = getattr(models, name).model_json_schema()
    schema['$id'] = f'https://patchtrace.local/schemas/v1/{name}.json'
    schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
    (root / f'{name}.json').write_text(json.dumps(schema, indent=2) + '\n', encoding='utf-8')

# SPEC-07 enrichment/1 records. PatchTrace-authored; not the supplied Phase 2 schema (see spec §0).
from patchtrace.enrichment import contracts  # noqa: E402

ENRICHMENT = ['SourceLocation', 'StageResult', 'ChangeSignal', 'DetectorOutcome', 'SignalSet', 'RankingConfig',
              'GroupSubtotal', 'RankingEntry', 'RankingResult', 'FeatureSite', 'FeatureTransition', 'CveSnapshot',
              'ContextContribution', 'ContextualEntry', 'ContextualRanking', 'CacheManifest', 'PipelineStatus']
enrichment_root = root / 'enrichment'
enrichment_root.mkdir(exist_ok=True)
for name in ENRICHMENT:
    schema = getattr(contracts, name).model_json_schema()
    schema['$id'] = f'https://patchtrace.local/schemas/enrichment/1/{name}.json'
    schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
    (enrichment_root / f'{name}.json').write_text(json.dumps(schema, indent=2) + '\n', encoding='utf-8')

# SPEC-07 §12 analysis profile files (desktop settings directory, never in a project).
from patchtrace.enrichment.profiles import AnalysisProfile  # noqa: E402

profile_schema = AnalysisProfile.model_json_schema()
profile_schema['$id'] = 'https://patchtrace.local/schemas/profile/1/AnalysisProfile.json'
profile_schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
(root / 'profile').mkdir(exist_ok=True)
(root / 'profile' / 'AnalysisProfile.json').write_text(json.dumps(profile_schema, indent=2) + '\n', encoding='utf-8')

# SPEC-28 secondary/2 match sets and engine-run/1 attempt records.
from patchtrace.secondary.contracts import SecondaryMatchSet  # noqa: E402
from patchtrace.secondary.runs import EngineRun  # noqa: E402

(root / 'secondary').mkdir(exist_ok=True)
for model, ident in ((SecondaryMatchSet, 'secondary/2'), (EngineRun, 'engine-run/1')):
    schema = model.model_json_schema()
    schema['$id'] = f'https://patchtrace.local/schemas/{ident}/{model.__name__}.json'
    schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
    (root / 'secondary' / f'{model.__name__}.json').write_text(json.dumps(schema, indent=2) + '\n', encoding='utf-8')

# SPEC-31 unified-engine contracts (S0a): schemas plus synthetic valid/invalid examples, LF on every OS.
import hashlib  # noqa: E402

from patchtrace.unified import contracts as uc  # noqa: E402
from patchtrace.unified import keys as uk  # noqa: E402

unified_root = root / 'unified'
(unified_root / 'examples').mkdir(parents=True, exist_ok=True)
for model, ident in uc.SCHEMA_MODELS:
    schema = model.model_json_schema()
    schema['$id'] = f'https://patchtrace.local/schemas/{ident}/{model.__name__}.json'
    schema['$schema'] = 'https://json-schema.org/draft/2020-12/schema'
    (unified_root / f'{model.__name__}.json').write_text(json.dumps(schema, indent=2, sort_keys=True) + '\n',
                                                         encoding='utf-8', newline='\n')


def _h(tag: str) -> str:
    return hashlib.sha256(f'example-{tag}'.encode()).hexdigest()


_OLD, _NEW = _h('older'), _h('newer')
_CH = [[c, 'equal'] for c in uc.CHANNELS]
_ROW = {'contract': 'unified-match/1', 'row_id': uk.row_id(_OLD, _NEW, [4096], [4368]),
        'older': [{'rva': 4096, 'name': 'ParseHeader', 'kind': 'function'}],
        'newer': [{'rva': 4368, 'name': 'ParseHeader', 'kind': 'function'}], 'decision': 'matched',
        'support': [{'component': 'K1', 'tier': 'A', 'atom_index': 0}, {'component': 'K2', 'tier': 'B', 'atom_index': 1}],
        'contest': None,
        'atoms': [{'source': 'ghidriff', 'step': 'SymbolsHash', 'tier': 'A', 'cardinality': '1:1', 'cls': 'E-NAME',
                   'older_rva': 4096, 'newer_rva': 4368, 'native': [], 'ref': 'm-17'},
                  {'source': 'pt-bytes', 'step': 'P06-operand-class', 'tier': 'B', 'cardinality': '1:1',
                   'cls': 'E-BODY', 'older_rva': 4096, 'newer_rva': 4368, 'native': [], 'ref': None}],
        'ghidriff_match_id': 'm-17', 'materiality': 'material', 'change_classes': ['constant'],
        'flags': ['pdata-confirmed'], 'hints': []}
_FACTS = {'contract': 'change-facts/1', 'row_id': _ROW['row_id'], 'verdict': 'material', 'proof': None,
          'second_channel': 'C6',
          'channels': [[c, 'differs' if c in ('C0', 'C1', 'C2', 'C5', 'C6') else s] for c, s in _CH],
          'targets': [3, 0, 0], 'eh': 'equal', 'deltas_omitted': 0, 'limits_hit': [],
          'deltas': [{'cls': 'constant', 'channel': 'C2', 'older_rva': 4130, 'newer_rva': 4402,
                      'old': 'cmp esi, 0x100', 'new': 'cmp esi, 0x200'}]}
_COUNTS = {'decisions': {'matched': 1, 'tentative': 0, 'candidate': 0, 'contested': 0, 'ambiguous': 0,
                         'older_only': 0, 'newer_only': 0, 'unknown': 0},
           'materiality': {'unchanged': 0, 'cosmetic': 0, 'material': 1, 'review': 0, 'unknown': 0,
                           'not_applicable': 0}}
_SOURCES = [{'source': 'ghidriff', 'entry_id': 'run-1', 'file_sha256': _h('raw'), 'version': '1.0.0'}]
_INPUTS = uc.ResultKeyInputs(older_sha256=_OLD, newer_sha256=_NEW, ghidriff_raw_sha256=_h('raw'),
                             ir_older_digest=None, ir_newer_digest=None,
                             sources=tuple(uc.SourceRef(**s) for s in _SOURCES), manual_digest=uk.manual_digest([]),
                             config_digest=_h('config'))
_RID = uk.result_key(_INPUTS)
_MANIFEST = {'contract': 'unified-result/1', 'result_id': _RID, 'older_sha256': _OLD, 'newer_sha256': _NEW,
             'orientation': 'older->newer', 'ghidriff_run_id': 'run-1', 'ghidriff_raw_sha256': _h('raw'),
             'ir_older': None, 'ir_newer': None, 'sources': _SOURCES, 'manual_digest': _INPUTS.manual_digest,
             'config_digest': _h('config'), 'engine_version': 'ude/1', 'status': 'complete', 'limitations': [],
             'counts': _COUNTS, 'created_utc': '2026-10-14T12:00:00+00:00',
             'parts': [{'name': 'facts.jsonl.gz', 'sha256': _h('facts'), 'bytes': 400, 'records': 1},
                       {'name': 'rows.jsonl.gz', 'sha256': _h('rows'), 'bytes': 900, 'records': 1}]}
_RUN = {'contract': 'unified-run/1', 'run_id': uk.unified_run_id(_RID, '2026-10-14T12:00:00+00:00'),
        'result_id': _RID, 'status': 'ok', 'error_code': None, 'peak_rss_bytes': 104857600,
        'stages': [{'stage': 'match', 'status': 'ok', 'duration_ms': 1200, 'reason': None}],
        'provenance': {'worker': 'in-process'}, 'stderr_tail': '', 'started_utc': '2026-10-14T12:00:00+00:00',
        'duration_ms': 1500}
_PRODUCER = {'mode': 'gzf', 'ghidra': '12.0.4', 'pyghidra': '3.0.2', 'java': '21', 'python': '3.12.10',
             'script_sha256': _h('script'), 'analysis_options_digest': _h('options')}
_IR = {'contract': 'program-ir/1', 'ir_key': _h('ir'), 'content_digest': _h('content'), 'artifact_sha256': _OLD,
       'program_sha256': _OLD, 'image_base': 5368709120, 'size_of_image': 1048576,
       'producer': {'kind': 'ghidra', **_PRODUCER, 'gzf_sha256': _h('gzf'), 'symbols': 'none'},
       'ingest_version': 'ir-ingest/1', 'norm_version': 'norm/1',
       'counts': {'functions': 1210, 'blocks': 18833, 'instructions': 201544, 'call_edges': 7120, 'strings': 904,
                  'consts': 2210, 'refs': 30411, 'thunks': 88, 'imports': 312, 'pdata_confirmed': 1004,
                  'mask_unlocated': 0}, 'limits_hit': [], 'warnings': [], 'file_sha256': _h('file'),
       'created_utc': '2026-10-14T12:00:00+00:00'}
_REQUEST = {'contract': 'ir-extract-request/1', 'side': 'older', 'artifact_path': '/work/pt-ir-1/input/older.bin',
            'artifact_sha256': _OLD, 'mode': 'gzf', 'gzf_path': '/work/pt-ir-1/input/older.gzf',
            'gzf_sha256': _h('gzf'), 'out_dir': '/work/pt-ir-1/out', 'work_dir': '/work/pt-ir-1/ghidra',
            'max_heap_mb': 4096, 'analysis_options': {}, 'limits': {'l01_functions_per_side': 250000},
            'decompile_rvas': []}
_HEADER = {'type': 'header', 'contract': 'ir-extract/1', 'artifact_sha256': _OLD, 'program_sha256': _OLD,
           'image_base': 5368709120, 'size_of_image': 1048576, 'language': 'x86:LE:64:default',
           'compiler': 'windows', 'producer': {**_PRODUCER, 'analyzed': True, 'symbols': 'none'}}
_FOOTER = {'type': 'footer', 'functions': 1210, 'instructions': 201544, 'status': 'complete', 'warnings': []}
_POINTER = {'contract': 'unified-result-ptr/1', 'result_id': _RID,
            'relative_dir': f'runs/run-1/unified/results/{_RID[:16]}', 'manifest_sha256': _h('manifest'),
            'status': 'complete', 'counts': _COUNTS, 'config_digest': _h('config')}
# S0a-FIX: /2 adds the pair identity (02 s9.1); the /1 example above stays as the version-gated legacy reader's input.
_POINTER2 = {**_POINTER, 'contract': 'unified-result-ptr/2', 'older_sha256': _OLD, 'newer_sha256': _NEW}


def _mut(doc: dict, path: tuple, value=None, *, drop: bool = False) -> dict:
    out = json.loads(json.dumps(doc))
    target = out
    for key in path[:-1]:
        target = target[key]
    if drop:
        del target[path[-1]]
    else:
        target[path[-1]] = value
    return out


# name -> (model, document, expected error text for invalid examples). 02 s8 invalid list first.
UNIFIED_EXAMPLES = {
    'valid-UnifiedMatch-matched.json': ('UnifiedMatch', _ROW, None),
    'valid-ChangeFacts-material.json': ('ChangeFacts', _FACTS, None),
    'valid-ChangeFacts-cosmetic-pseudo.json': ('ChangeFacts', {**_FACTS, 'verdict': 'cosmetic', 'proof': 'COS-PSEUDO/1',
                                                               'second_channel': None, 'channels': _CH, 'deltas': []},
                                               None),
    'valid-UnifiedResultManifest.json': ('UnifiedResultManifest', _MANIFEST, None),
    'valid-UnifiedResultPointer.json': ('UnifiedResultPointer', _POINTER, None),
    'valid-UnifiedResultPointerV2.json': ('UnifiedResultPointerV2', _POINTER2, None),
    'valid-UnifiedRun-ok.json': ('UnifiedRun', _RUN, None),
    'valid-ProgramIrManifest.json': ('ProgramIrManifest', _IR, None),
    'valid-ExtractRequest-gzf.json': ('ExtractRequest', _REQUEST, None),
    'valid-IrExtractHeader.json': ('IrExtractHeader', _HEADER, None),
    'valid-IrExtractFooter.json': ('IrExtractFooter', _FOOTER, None),
    'invalid-UnifiedMatch-decision-removed.json': ('UnifiedMatch', _mut(_ROW, ('decision',), 'removed'), 'decision'),
    'invalid-ChangeFacts-unchanged-without-proof.json': (
        'ChangeFacts', {**_FACTS, 'verdict': 'unchanged', 'second_channel': None, 'channels': _CH, 'deltas': []},
        'proof is required'),
    'invalid-ChangeFacts-cosmetic-without-proof.json': (
        'ChangeFacts', {**_FACTS, 'verdict': 'cosmetic', 'second_channel': None, 'channels': _CH, 'deltas': []},
        'proof is required'),
    'invalid-ChangeFacts-material-without-second-channel.json': (
        'ChangeFacts', _mut(_FACTS, ('second_channel',), None), 'second channel is required'),
    'invalid-UnifiedMatch-tier-a-non-exclusive.json': (
        'UnifiedMatch', _mut(_ROW, ('atoms', 0, 'cardinality'), 'non-exclusive'), 'non-exclusive'),
    'invalid-UnifiedMatch-atom-without-cls.json': ('UnifiedMatch', _mut(_ROW, ('atoms', 0, 'cls'), drop=True), 'cls'),
    'invalid-UnifiedMatch-negative-rva.json': ('UnifiedMatch', _mut(_ROW, ('atoms', 0, 'older_rva'), -1),
                                               'older_rva'),
    'invalid-UnifiedResultManifest-counts-unknown-key.json': (
        'UnifiedResultManifest', _mut(_MANIFEST, ('counts', 'decisions', 'removed'), 0), 'removed'),
    'invalid-ChangeFacts-cosmetic-with-semantic-delta.json': (
        'ChangeFacts', {**_FACTS, 'verdict': 'cosmetic', 'proof': 'COS-PSEUDO/1', 'second_channel': None,
                        'channels': _CH}, 'no semantic delta'),
    'invalid-ChangeFacts-material-anchored-in-bytes-group.json': (
        'ChangeFacts', _mut(_FACTS, ('second_channel',), 'C5'), 'anchored second channel'),
    'invalid-UnifiedRun-ok-without-result.json': ('UnifiedRun', _mut(_RUN, ('result_id',), None), 'needs a result'),
    'invalid-UnifiedResultPointer-dir-mismatch.json': (
        'UnifiedResultPointer', _mut(_POINTER, ('relative_dir',), 'runs/run-1/unified/results/0000000000000000'),
        'relative_dir'),
    'invalid-UnifiedResultPointerV2-without-pair.json': (
        'UnifiedResultPointerV2', _mut(_POINTER2, ('newer_sha256',), drop=True), 'newer_sha256'),
    'invalid-ExtractRequest-relative-path.json': ('ExtractRequest', _mut(_REQUEST, ('out_dir',), 'out'), 'absolute'),
    'invalid-IrExtractHeader-unknown-key.json': ('IrExtractHeader', _mut(_HEADER, ('extra',), 1), 'extra'),
}
index = {}
for name, (model_name, doc, expect) in UNIFIED_EXAMPLES.items():
    (unified_root / 'examples' / name).write_text(json.dumps(doc, indent=2, sort_keys=True) + '\n', encoding='utf-8',
                                                  newline='\n')
    index[name] = {'model': model_name, 'valid': expect is None, 'expect': expect}
(unified_root / 'examples' / 'index.json').write_text(json.dumps(index, indent=2, sort_keys=True) + '\n',
                                                      encoding='utf-8', newline='\n')
