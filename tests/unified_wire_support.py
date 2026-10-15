"""Test support for the SPEC-31 wiring tests: ProgramIR sidecars for the two artifacts of a synthetic project, built from
hand-assembled x86-64 through the REAL ingest and placed with the real `place_ir` (so `make_plan` finds them the way it
finds the output of a real extraction). The functions mirror the synthetic Ghidriff document of
`unified_s0_fixtures.patch_document`: a call is added to `read_item`, `get_version` changes a constant, `format_name`
and `keep_same` only move, `debug_dump` is deleted and `report_invalid_index` is added. Synthetic: never live evidence."""
from __future__ import annotations

import json
import tempfile
from pathlib import Path

from unified_extract_builder import footer, header, write_jsonl
from unified_facts_builder import BASE, function

from patchtrace.unified.ir.ingest import ExpectedSide, ingest
from patchtrace.unified.ir.pe_tables import PeTables, Section
from patchtrace.unified.ir.place import place_ir

SIZE = 0x2000                                    # SizeOfImage of `patchtrace.sample.synthetic_pe`
SYM_OLD = {'helper': 0x1100}
SYM_NEW = {'helper': 0x1180, 'report_invalid_index': 0x1800}
READ_ITEM = [('mov_ri', 'EAX', 1), ('cmp_ri', 'ECX', 6), ('jcc', 'A', 'done'), ('add_ri', 'EAX', 3), ('label', 'done'),
             ('mov_rr', 'EDX', 'EAX'), ('ret',)]
FORMAT_NAME = [('mov_ri', 'EAX', 0x41), ('add_ri', 'EAX', 9), ('xor_rr', 'ECX', 'ECX'), ('test_rr', 'EAX', 'EAX'),
               ('mov_rr', 'EDX', 'EAX'), ('ret',)]
KEEP_SAME = [('mov_ri', 'EAX', 0x77), ('sub_ri', 'EAX', 5), ('mov_rr', 'ECX', 'EAX'), ('xor_rr', 'EDX', 'EDX'),
             ('test_rr', 'ECX', 'ECX'), ('ret',)]
DEBUG_DUMP = [('mov_ri', 'EAX', 0x55), ('add_ri', 'EAX', 2), ('mov_rr', 'ECX', 'EAX'), ('sub_ri', 'ECX', 1),
              ('test_rr', 'ECX', 'ECX'), ('ret',)]


def get_version(value: int) -> list:
    return [('mov_ri', 'EAX', value), ('mov_rr', 'ECX', 'EAX'), ('add_ri', 'ECX', 4), ('sub_ri', 'ECX', 2),
            ('test_rr', 'EAX', 'EAX'), ('ret',)]


def old_functions() -> list[dict]:
    sym = SYM_OLD
    return [function(0x1000, READ_ITEM, name='read_item', sym=sym),
            function(0x1200, FORMAT_NAME, name='format_name', sym=sym),
            function(0x1300, KEEP_SAME, name='keep_same', sym=sym),
            function(0x1400, DEBUG_DUMP, name='debug_dump', sym=sym),
            function(0x1600, get_version(1), name='get_version', sym=sym)]


def new_functions(keep_same: int = 0x77) -> list[dict]:
    """`keep_same` only moves unless its constant changes (a constant-only edit that Ghidriff never examines)."""
    sym = SYM_NEW
    patched = READ_ITEM[:3] + [('call', 'report_invalid_index')] + READ_ITEM[3:]
    return [function(0x1080, patched, name='read_item', sym=sym),
            function(0x1280, FORMAT_NAME, name='format_name', sym=sym),
            function(0x1380, [('mov_ri', 'EAX', keep_same), *KEEP_SAME[1:]], name='keep_same', sym=sym),
            function(0x1700, get_version(2), name='get_version', sym=sym),
            function(0x1800, [('mov_ri', 'EAX', 0x99), ('ret',)], name='report_invalid_index', sym=sym)]


def pe_tables() -> PeTables:
    return PeTables(image_base=BASE, size_of_image=SIZE, sections=(Section('.text', 0x1000, 0x2000, True),))


def artifacts(service) -> dict[str, str]:
    return {a.side: a.sha256 for a in service.project.artifacts}


def place(service, side: str, functions: list[dict], *, mode: str = 'analyze', script: str = 'cd' * 32,
          options: str = 'ef' * 32, sha: str | None = None, size: int = SIZE, created: str | None = None,
          scratch: Path | None = None) -> Path:
    """Ingest `functions` for one side of the project and place the sidecar below its run; returns the directory."""
    sha = sha or artifacts(service)[side]
    work = Path(tempfile.mkdtemp(prefix=f'wire-{side}-', dir=scratch))
    n_insn = sum(len(f['insns']) for f in functions)
    document = write_jsonl(work / 'ir.jsonl', [header(sha, mode=mode, size=size, script=script, options=options),
                                               *functions, footer(len(functions), n_insn)])
    out = work / 'out'
    out.mkdir()
    tables = pe_tables()
    tables.size_of_image = size
    expect = ExpectedSide(side, sha, tables, mode=mode, analysis_options_digest=options, script_sha256=script)
    built = ingest(document, expect, out_dir=out, created_utc=created)
    return place_ir(service.root, service.project.runs[-1].id, built.directory)


def place_pair(service, *, scratch: Path | None = None, keep_same: int = 0x77, **kw) -> tuple[Path, Path]:
    return (place(service, 'older', old_functions(), scratch=scratch, **kw),
            place(service, 'newer', new_functions(keep_same), scratch=scratch, **kw))


# --- a fake Ghidra for the on-demand decompile (S3b) --------------------------------------------------------------------

FAKE_DECOMPILER = '''
import json, sys, time
from pathlib import Path
args = sys.argv[1:]
request = json.loads(Path(args[5]).read_text(encoding='utf-8'))
out = Path(request['out_dir'])
print(json.dumps({'probe': {'ghidra': '12.0.4', 'pyghidra': '3.0.2', 'java': '21.0.1', 'python': '3.12.1',
                            'script_sha256': 'f' * 64}}), flush=True)
TEXTS = json.loads(@TEXTS@)
SLOW = @SLOW@
if SLOW:
    time.sleep(SLOW)
side = request['side']
lines = []
for rva in request['decompile_rvas']:
    code = TEXTS.get(side, {}).get(str(rva))
    lines.append(json.dumps({'side': side, 'rva': rva, 'status': 'ok' if code is not None else 'failed',
                             'code': code}))
(out / 'decomp.jsonl').write_text(chr(10).join(lines) + chr(10), encoding='utf-8')
'''


def keep_same_text(value: str) -> str:
    return f'\nint keep_same(void)\n\n{{\n  return {value};\n}}\n\n'


def fake_backend(directory: Path, texts: dict, *, slow: float = 0.0):
    """A `BackendConfig` whose interpreter is a fake that answers a `decompile` request with `texts`
    (`{"older": {rva: C text}, "newer": {...}}`; an RVA without a text is a `failed` function)."""
    from fake_exe import make_fake_exe

    from patchtrace.backend import BackendConfig
    ghidra = Path(directory) / 'ghidra-install'
    (ghidra / 'Ghidra').mkdir(parents=True, exist_ok=True)
    (ghidra / 'Ghidra' / 'application.properties').write_text('application.version=12.0.4\n', encoding='utf-8')
    encoded = json.dumps({side: {str(rva): text for rva, text in table.items()} for side, table in texts.items()})
    source = FAKE_DECOMPILER.replace('@TEXTS@', repr(encoded)).replace('@SLOW@', repr(slow))
    fake = make_fake_exe(Path(directory) / 'bin', 'fakepython', source)
    return BackendConfig(python_executable=str(fake), ghidra_dir=str(ghidra))


def place_gzfs(service, content: bytes = b'gzf') -> dict[str, Path]:
    """The two retained programs of the run (`runs/<run>/unified/gzf/<side>.gzf`, where `retain_gzfs` puts them)."""
    directory = service.root / 'runs' / service.project.runs[-1].id / 'unified' / 'gzf'
    directory.mkdir(parents=True, exist_ok=True)
    paths = {side: directory / f'{side}.gzf' for side in ('older', 'newer')}
    for side, path in paths.items():
        path.write_bytes(content + side.encode())
    return paths
