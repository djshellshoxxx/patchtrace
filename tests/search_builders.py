"""Synthetic project builders for the WB1 source and build tests. Every name, string and hash is invented; PE
files come from `pe_builder` (bytes only, never executed). No Microsoft binary, PDB or Winbindex label."""
from __future__ import annotations

import hashlib
import json
import random
from pathlib import Path
from types import SimpleNamespace

from pe_builder import PeSpec, SectionSpec, build_pe

from patchtrace.models import (
    AnalysisContext,
    AnalysisRun,
    AnalystAnnotation,
    Artifact,
    ComparisonProject,
    Finding,
    FunctionMatch,
    FunctionRecord,
    Hypothesis,
    InterpretationRun,
)

RUN = 'run-1'
PROJECT_ID = 'project-search-1'
SECRET_STRING = 'password=hunter2hunter2'
RAW_STRINGS = {'added': ['Contoso\\Config', 'CheckLength failed', SECRET_STRING], 'deleted': ['Legacy path', 'CheckLength failed']}
RAW_SYMBOLS = {'added': ['CheckLength'], 'deleted': ['OldHelper']}
SOURCES = {
    'older': 'int FormatLine(int v) {\n    return ProbeForRead(v);\n}',
    'newer': 'int FormatLine(int v) {\n    return CheckLength(v) && ProbeForRead(v);\n}',
}


def _write(path: Path, data: bytes) -> str:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return hashlib.sha256(data).hexdigest()


def _artifact(root: Path, side: str, imports: dict, exports) -> Artifact:
    pe = build_pe(PeSpec(kind='dll', sections=[SectionSpec('.text'), SectionSpec('.rdata')], imports=imports,
                         exports=exports, rsds=(b'\x01' * 16, 1, f'C:\\build\\{side}\\synthetic.pdb')))
    relative = f'artifacts/{side}/synthetic.dll'
    return Artifact(id=f'art-{side}', side=side, name='synthetic.dll', sha256=_write(root / relative, pe),
                    size=len(pe), relative_path=relative)


def _function(side: str, fid: str, name: str, address: str, code: str | None = None, **extra) -> FunctionRecord:
    return FunctionRecord(id=fid, artifact_id=f'art-{side}', run_id=RUN, name=name, address=address,
                          address_space='virtual', code=code, **extra)


def _matches() -> list[FunctionMatch]:
    modified = FunctionMatch(
        id='m-mod', run_id=RUN, category='modified', quality='high',
        older=[_function('older', 'f-old-fmt', 'FormatLine', '140001600', SOURCES['older'], callees=['ProbeForRead'],
                         metadata={'sig': 'int FormatLine(int v)', 'upstream_name': 'FUN_140001600'})],
        newer=[_function('newer', 'f-new-fmt', 'FormatLine', '140001740', SOURCES['newer'],
                         callees=['CheckLength', 'ProbeForRead'], metadata={'sig': 'int FormatLine(int v)'})])
    added = FunctionMatch(id='m-add', run_id=RUN, category='added',
                          newer=[_function('newer', 'f-new-chk', 'CheckLength', '140001f00', 'int CheckLength(int n) {\n    return n;\n}'),
                                 _function('newer', 'f-new-auto', 'FUN_140002000', '140002000')])
    removed = FunctionMatch(id='m-rem', run_id=RUN, category='removed',
                            older=[_function('older', 'f-old-helper', 'RtlCopyMemoryHelper', '140001900')])
    same = FunctionMatch(id='m-same', run_id=RUN, category='unchanged',
                         older=[_function('older', 'f-old-same', 'MainLoop', '140001100', 'void MainLoop(void) {}')],
                         newer=[_function('newer', 'f-new-same', 'MainLoop', '140001100', 'void MainLoop(void) {}')])
    return [modified, added, removed, same]


def _interpretation(revision: int) -> InterpretationRun:
    context = AnalysisContext(id='ctx-1', project_id=PROJECT_ID, revision=revision, match_ids=['m-mod'], evidence=[],
                              digest='d' * 64, token_estimate=1, payload='{}')
    finding = Finding(id='fnd-1', context_id='ctx-1', match_ids=['m-mod'], summary='Added length validation',
                      fix_purpose='Bounds check before the copy', category='security-fix', cwe='CWE-787',
                      hypothesis=Hypothesis(explanation='A missing check allowed an overflow'),
                      analyst_conclusion='Confirmed: out-of-bounds write fixed')
    return InterpretationRun(id='int-1', context=context, provider='fake', model='fake-1', status='completed',
                             findings=[finding])


def _notes() -> list[AnalystAnnotation]:
    return [AnalystAnnotation(id='n-1', target_id='m-mod', kind='note', text='Looks like a bounds check'),
            AnalystAnnotation(id='n-2', target_id='m-add', kind='bookmark', text='Revisit CheckLength callers'),
            AnalystAnnotation(id='n-3', target_id='m-mod', kind='validation', text='{"json": true}')]


def make_service(root: Path, *, seed: int | None = None, raw: dict | None = None, completed: bool = True):
    """A `ProjectService` stand-in (`.project`, `.root`) over files written under `root`. `seed` permutes every
    list the sources read, to prove order independence; `raw` replaces the raw JSON document."""
    older = _artifact(root, 'older', {'KERNEL32.dll': ['CreateFileW', 'ReadFile']}, ('synthetic.dll', ['ExportedApi']))
    newer = _artifact(root, 'newer', {'KERNEL32.dll': ['CreateFileW', 'ReadFile', 'WriteFile']},
                      ('synthetic.dll', ['ExportedApi', 'NewExport']))
    document = raw if raw is not None else {'strings': RAW_STRINGS, 'symbols': RAW_SYMBOLS,
                                            'functions': {'added': [], 'deleted': [], 'modified': []}}
    raw_path = f'runs/{RUN}/raw/synthetic.ghidriff.json'
    sha = _write(root / raw_path, json.dumps(document, sort_keys=True).encode('utf-8'))
    run = AnalysisRun(id=RUN, status='completed' if completed else 'failed', raw_path=raw_path,
                      raw_sha256=sha if completed else None)
    matches, notes = _matches(), _notes()
    if seed is not None:
        rng = random.Random(seed)
        for items in (matches, notes):
            rng.shuffle(items)
        for match in matches:
            rng.shuffle(match.older)
            rng.shuffle(match.newer)
    project = ComparisonProject(id=PROJECT_ID, name='synthetic', artifacts=[older, newer], runs=[run],
                                matches=matches, annotations=notes, revision=3,
                                interpretations=[_interpretation(3)])
    return SimpleNamespace(project=project, root=root)
