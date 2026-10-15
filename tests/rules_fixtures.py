"""Shared fixtures of the rules tests (R3, R4): SYNTHETIC images and the recorded tool goldens, fake ports, a reference
rule renderer and an in-process pair checker. Bytes only, NEVER executed; no Microsoft binary is involved.

The images are the deterministic pairs of `tests/test_intel_tools_pe.py` (their SHA-256 values are pinned by the goldens
in `tests/fixtures/intel_tools/`). The tool deltas are computed from the recorded REAL capa 9.4.0 and FLOSS 3.1.1 output,
exactly as the SPEC-29 tests do; no tool runs here.

The sizes of the functions come from the builder's own layout (label to label). The images carry no `.pdata`, so a
`FunctionRef(extent='pdata')` built here is the fixture's assertion of what exception data would say; the tests that
need a real `.pdata` build their own image.

`render_rule` is a REFERENCE renderer of the plan's grammar, kept as an oracle: production code and the tests use
`rules/synth.py` (`candidates.synth_renderer`), and the synergy test compares the two.
"""
from __future__ import annotations

import functools
from collections.abc import Mapping
from dataclasses import dataclass
from pathlib import Path

from intel_tools_support import golden, image_getter
from test_intel_tools_pe import KERNEL32, MSVC_RICH, Asm, Rdata, _image

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.intelligence.tools import capa, delta, floss
from patchtrace.intelligence.tools.common import DEFAULT_LIMITS, ToolEvidenceSet, ToolManifest, ToolRun
from patchtrace.intelligence.tools.delta import ToolDelta
from patchtrace.intelligence.tools.normalize import FunctionPairing
from patchtrace.pe_overview import PeOverview, inspect_pe
from patchtrace.pe_overview.tables import PeTables
from patchtrace.rules.candidates import PairCheck, RuleSpec
from patchtrace.rules.contracts import (
    BytesFeature,
    CapabilityFeature,
    FunctionRef,
    ImportFeature,
    PairSource,
    StringFeature,
    WorkerRule,
)
from patchtrace.rules.errors import RuleError
from patchtrace.rules.ports import (
    CapabilityChannel,
    Coverage,
    DecodedInstruction,
    ImportTable,
    MaskSpan,
    StringChannel,
)

SIDES = ('older', 'newer')
BASE = 0x140000000
STATEMENT = 'A match means a file contains this pattern. It does not show whether the file is affected by a flaw.'
PROJECT = 'project-1'
COMPLETE = Coverage('complete', 'complete')
UNAVAILABLE = Coverage('unavailable', 'unavailable')


# --- builds ----------------------------------------------------------------------------------------------------------

@dataclass(frozen=True)
class Build:
    """One side of a synthetic pair, opened as a verified artifact."""
    side: str
    data: bytes
    sha256: str
    reader: VerifiedArtifactReader
    overview: PeOverview
    copy: object
    pe_map: object


class Bench:
    """Opens the named synthetic pairs under `tmp_path` once each; `close` releases the readers."""

    def __init__(self, tmp_path: Path):
        self._get, self._close = image_getter(tmp_path)

    def build(self, pair: str, side: str) -> Build:
        copy, reader, pe_map = self._get(pair, side)
        data = reader.read(0, reader.size)
        return Build(side, data, reader.sha256, reader, inspect_pe(reader), copy, pe_map)

    def close(self) -> None:
        self._close()


def pair_source(older: Build | None, newer: Build | None, *, category: str, older_function: FunctionRef | None,
                newer_function: FunctionRef | None, materiality: str = 'material', confirmed: bool = False,
                match_id: str = 'match-1') -> PairSource:
    return PairSource(project_id=PROJECT, revision=1, run_id='run-1', older_sha256=older.sha256,
                      newer_sha256=newer.sha256, match_id=match_id, category=category, review='accepted',
                      materiality=materiality, analyst_confirmed_material=confirmed, older=older_function,
                      newer=newer_function)


def function(rva: int, size: int) -> FunctionRef:
    return FunctionRef(rva=rva, size=size, extent='pdata')


# The changed functions of the capa-api pair (RVAs and sizes from the builder's layout; see tests/test_intel_tools_pe.py).
CAPA_FUNCTIONS = {'term': (0x104d, 24), 'log-older': (0x108b, 3), 'log-newer': (0x1096, 38), 'env': (0x1030, 35)}


def capa_pair(bench: Bench, which: str, *, match_id: str | None = None, **kw) -> PairSource:
    """The accepted pair of one changed function of the `capa-api` images: `term` (removed), `log` (modified) or `env`
    (added)."""
    older, newer = bench.build('capa-api', 'older'), bench.build('capa-api', 'newer')
    fn = {name: function(*CAPA_FUNCTIONS[name]) for name in CAPA_FUNCTIONS}
    spec = {'term': ('removed', fn['term'], None), 'log': ('modified', fn['log-older'], fn['log-newer']),
            'env': ('added', None, fn['env'])}[which]
    return pair_source(older, newer, category=spec[0], older_function=spec[1], newer_function=spec[2],
                       match_id=match_id or f'match-{which}', **kw)


def strings_pair(bench: Bench, *, match_id: str = 'match-strings', **kw) -> PairSource:
    """`main` of the `floss-static` images (the only function; 63 bytes on both sides)."""
    older, newer = bench.build('floss-static', 'older'), bench.build('floss-static', 'newer')
    return pair_source(older, newer, category='modified', older_function=function(0x1000, 63),
                       newer_function=function(0x1000, 63), match_id=match_id, **kw)


# --- recorded tool output --------------------------------------------------------------------------------------------

def _run(engine: str, evidence: ToolEvidenceSet, manifest: ToolManifest, profile: str) -> ToolRun:
    return ToolRun(run_id=evidence.run_id, engine=engine, side=evidence.side,
                   input_artifact_hash=evidence.artifact_sha256, config_digest='d' * 64, cache_key=evidence.cache_key,
                   started_at='2026-10-14T00:00:00+00:00', elapsed=1, status='ok',
                   evidence_count=evidence.evidence_count(), profile=profile, manifest=manifest)


class _Fn:
    def __init__(self, address: str):
        self.id, self.address, self.address_space = f'fn-{address}', address, 'virtual'


class _Match:
    def __init__(self, category: str, older=(), newer=()):
        self.category, self.older, self.newer = category, [_Fn(a) for a in older], [_Fn(a) for a in newer]


@dataclass(frozen=True)
class CapaWorld:
    delta: ToolDelta
    evidence: Mapping[str, ToolEvidenceSet]
    raw: Mapping[str, bytes]


def capa_world(bench: Bench) -> CapaWorld:
    """The capa delta of the `capa-api` pair with the function pairing a Ghidriff run would give: `env` added, `log`
    modified, `term` removed, `main` modified, `host`, `dyn` and `xor` unchanged."""
    sets, raw = {}, {}
    for side in SIDES:
        build = bench.build('capa-api', side)
        raw[side] = golden(f'capa/capa-api-{side}.json')
        sets[side] = capa.parse(raw[side], capa.ParseContext(f'run-{side}', side, build.copy, 'c' * 64, 'd' * 64,
                                                             build.pe_map, DEFAULT_LIMITS['capa']))
    manifest = ToolManifest(engine='capa', version='9.4.0', executable_sha256='e' * 64, license='Apache-2.0',
                            rules_source='embedded', supported=True)
    pairing = FunctionPairing.from_project(
        [_Match('added', newer=['140001030']), _Match('modified', ['14000108b'], ['140001096']),
         _Match('removed', older=['14000104d']), _Match('modified', ['140001000'], ['140001000'])],
        {'address_matches': {'140001030': [['140001053', ['SymbolsHash']]],
                             '140001065': [['140001070', ['SymbolsHash']]],
                             '14000108e': [['1400010bc', ['SymbolsHash']]]}},
        older_base=BASE, newer_base=BASE)
    result = delta.compute(_run('capa', sets['older'], manifest, 'basic'), sets['older'],
                           _run('capa', sets['newer'], manifest, 'basic'), sets['newer'], pairing=pairing)
    return CapaWorld(result, sets, raw)


def floss_delta(bench: Bench) -> ToolDelta:
    """The FLOSS static-string delta of the `floss-static` pair (one string added, one removed, the rest unchanged)."""
    sets = {}
    for side in SIDES:
        build = bench.build('floss-static', side)
        ctx = floss.ParseContext(f'r-{side}', side, build.copy, 'c' * 64, 'd' * 64, build.pe_map, build.reader,
                                 DEFAULT_LIMITS['floss'], False)
        sets[side] = floss.parse(golden(f'floss/floss-static-{side}.static.json'), ctx)
    manifest = ToolManifest(engine='floss', version='3.1.1', executable_sha256='e' * 64, license='Apache-2.0',
                            rules_source='embedded', supported=True)
    return delta.compute(_run('floss', sets['older'], manifest, 'context'), sets['older'],
                         _run('floss', sets['newer'], manifest, 'context'), sets['newer'])


# --- fake ports ------------------------------------------------------------------------------------------------------

class FakeStrings:
    def __init__(self, items=(), coverage: Coverage = COMPLETE):
        self.channel = StringChannel(coverage, tuple(items))

    def strings(self, pair):
        return self.channel


class FakeCapabilities:
    def __init__(self, items=(), coverage: Coverage = COMPLETE):
        self.channel = CapabilityChannel(coverage, tuple(items))

    def capabilities(self, pair):
        return self.channel


class FakeImports:
    def __init__(self, older: ImportTable | None, newer: ImportTable | None):
        self._tables = {'older': older, 'newer': newer}

    def imports(self, pair, side):
        return self._tables[side]


# --- reference renderer ----------------------------------------------------------------------------------------------

GATE = 'uint16(0) == 0x5A4D and pe.is_pe and pe.machine == pe.MACHINE_AMD64'


def _quote(value: str) -> str:
    return '"' + value + '"'


def _meta_lines(spec: RuleSpec) -> list[str]:
    pair = spec.source
    meta = [('patchtrace_rule_id', _quote(f'{spec.lineage_id[:12]}.v{spec.version}')),
            ('patchtrace_version', str(spec.version)), ('patchtrace_project_id', _quote(pair.project_id)),
            ('older_sha256', _quote(pair.older_sha256)), ('newer_sha256', _quote(pair.newer_sha256)),
            ('side', _quote(spec.direction)), ('change', _quote(pair.category))]
    if pair.older is not None:
        meta.append(('function_older', _quote(f'0x{pair.older.rva:x}')))
    if pair.newer is not None:
        meta.append(('function_newer', _quote(f'0x{pair.newer.rva:x}')))
    rules = [f.rule_id for f in spec.features if isinstance(f, CapabilityFeature)]
    if rules:
        meta.append(('capability', _quote('; '.join(rules))))
    meta.append(('statement', _quote(STATEMENT)))
    width = max(len(key) for key, _ in meta)
    return [f'    {key.ljust(width)} = {value}' for key, value in meta]


EXECUTABLE = ('for any s in pe.sections: (s.characteristics & pe.SECTION_MEM_EXECUTE != 0 and '
              '$b in (s.raw_data_offset..s.raw_data_offset + s.raw_data_size))')


def _pin(pin) -> str:
    """The window's call goes through THIS import: at one of the first eight matches of `$b`, the RVA the call's
    displacement leads to (RVA of the instruction's end + the displacement) is the IAT slot of the named import.
    The bounded range keeps the compiler from flagging a slow loop."""
    section = 'pe.sections[pe.section_index(@b[i])]'
    end = f'{section}.virtual_address + @b[i] + {pin.end_offset} - {section}.raw_data_offset'
    return (f'for any i in (1..8): (i <= #b and for any d in pe.import_details: '
            f'(d.library_name iequals {_quote(pin.dll)} and for any f in d.functions: '
            f'(f.name == {_quote(pin.name)} and f.rva == {end} + int32(@b[i] + {pin.disp_offset}))))')


def render_rule(spec: RuleSpec) -> str:
    """The grammar of the plan for byte windows (with call pins), strings, imports and capabilities, in the layout of
    `yara_x.Formatter`. Evidence text is already escaped by the feature, so it is written between quotes unchanged."""
    windows = [f for f in spec.features if isinstance(f, BytesFeature)][:1]   # grammar yrx-gen/1: one hex pattern
    texts = [f for f in spec.features if isinstance(f, StringFeature)]
    modifier = {'ascii': 'ascii', 'wide': 'wide', 'ascii-wide': 'ascii wide'}
    patterns = [('$b', f'{{ {w.pattern} }}') for w in windows]
    patterns += [(f'$t{i}', f'"{f.text}" {modifier[f.encoding]}') for i, f in enumerate(texts, 1)]
    width = max((len(name) for name, _ in patterns), default=0)
    pattern_lines = [f'    {name.ljust(width)} = {body}' for name, body in patterns]
    conditions = [GATE, *([EXECUTABLE] if windows else []), *(f'$t{i}' for i in range(1, len(texts) + 1))]
    for feature in spec.features:
        if isinstance(feature, ImportFeature):
            what = _quote(feature.name) if feature.name is not None else str(feature.ordinal)
            conditions.append(f'pe.imports({_quote(feature.dll)}, {what})')
    conditions += [_pin(pin) for w in windows for pin in w.pins]
    side = f'{spec.direction}_side'
    lines = ['import "pe"', '', f'rule {spec.rule_name}: patchtrace {side} {{', '  meta:', *_meta_lines(spec), '']
    if pattern_lines:
        lines += ['  strings:', *pattern_lines, '']
    lines += ['  condition:', '    ' + ' and '.join(conditions), '}', '']
    return '\n'.join(lines)


# --- in-process pair checker -----------------------------------------------------------------------------------------

def engine_checker(builds: Mapping[str, bytes]):
    """A `PairChecker` that calls the REAL engine in this process (the parent never does this in production; tests may,
    as the R2 tests do). `builds` maps a side to the bytes of that build."""
    from patchtrace.rules import engine

    def check(name: str, text: str, pair: PairSource, direction: str) -> PairCheck:
        rules = engine.RuleSet.compile((WorkerRule(name=name, text=text),))
        other = 'newer' if direction == 'older' else 'older'
        return PairCheck(engine.stamp(), rules.lint[0], rules.scan(builds[direction])[0],
                         rules.scan(builds[other])[0])
    return check


# --- the byte channel: a stand-in decoder, builds as images, the synergy images --------------------------------------

class SubsetDecoder:
    """A `MaskSource` for exactly the x86-64 forms the synthetic fixtures use, standing in for iced-x86 where it is not
    installed or pinned: REX, `op r/m` (ModRM, SIB, disp8/32, RIP-relative), group 1 with imm8/imm32, `mov r, imm32/64`,
    `FF /0 /2 /4`, `E8`, `E9`, `EB`, `7x`, `0F 8x`, `C3`, `CC`, `90`, push/pop. Anything else is `PT-RULE-DECODE`.
    It follows the `MaskSource` contract (a RIP-relative displacement is `rip-disp`, a branch displacement is `branch-ext`
    when its target leaves the body) and `tests/test_rules_masks.py` compares it with the real decoder whenever that is
    installed. The contract only names `iced-x86` and `unified-ir`, so `name` carries the real decoder's label and
    `version` says what this is."""
    name = 'iced-x86'
    version = 'standin'
    _MODRM = frozenset({0x01, 0x09, 0x21, 0x29, 0x31, 0x39, 0x85, 0x89, 0x8B, 0x8D})
    _FLOW = {0xE8: 'call', 0xE9: 'branch', 0xEB: 'branch', 0xC3: 'return', 0xCC: 'other'}

    def decode(self, code: bytes, rva: int) -> tuple[DecodedInstruction, ...]:
        out, position = [], 0
        try:
            while position < len(code):
                out.append(self._one(code, position, rva))
                position += out[-1].size
        except (IndexError, KeyError):
            raise RuleError('PT-RULE-DECODE', 'The stand-in decoder cannot read these bytes', reason='standin') from None
        return tuple(out)

    @staticmethod
    def _modrm(code: bytes, pos: int) -> tuple[int, int | None]:
        """(position after the operand bytes, position of a RIP-relative displacement or None)."""
        mod, rm = code[pos] >> 6, code[pos] & 7
        pos += 1
        if mod == 3:
            return pos, None
        if rm == 4:
            base = code[pos] & 7
            pos += 1
            if mod == 0 and base == 5:
                return pos + 4, None
        elif mod == 0 and rm == 5:
            return pos + 4, pos
        return pos + {0: 0, 1: 1, 2: 4}[mod], None

    def _one(self, code: bytes, start: int, rva: int) -> DecodedInstruction:
        pos, rex = start, 0
        if 0x40 <= code[pos] <= 0x4F:
            rex, pos = code[pos], pos + 1
        op, pos = code[pos], pos + 1
        flow, rip, immediate, relative = self._FLOW.get(op, 'next'), None, 0, 0
        if op in self._MODRM or op in (0x80, 0x81, 0x83, 0xC7, 0xFF):
            if op == 0xFF:
                flow = {2: 'indirect-call', 4: 'indirect-branch'}.get((code[pos] >> 3) & 7, 'next')
            pos, rip = self._modrm(code, pos)
            immediate = {0x80: 1, 0x83: 1, 0x81: 4, 0xC7: 4}.get(op, 0)
        elif 0xB8 <= op <= 0xBF:
            immediate = 8 if rex & 8 else 4
        elif op in (0xE8, 0xE9):
            relative = 4
        elif op == 0xEB or 0x70 <= op <= 0x7F:
            relative, flow = 1, 'branch' if op == 0xEB else 'conditional'
        elif op == 0x0F and 0x80 <= code[pos] <= 0x8F:
            relative, flow, pos = 4, 'conditional', pos + 1
        elif op not in (0xC3, 0xCC, 0x90) and not 0x50 <= op <= 0x5F:
            raise KeyError(op)
        field, pos = pos, pos + max(immediate, relative)
        if pos > len(code):
            raise IndexError(pos)
        spans, target = [], None
        if rip is not None:
            spans.append(MaskSpan(rip - start, 4, 'rip-disp'))
            target = rva + pos + int.from_bytes(code[rip:rip + 4], 'little', signed=True)
        elif relative:
            target = rva + pos + int.from_bytes(code[field:field + relative], 'little', signed=True)
            if not rva <= target < rva + len(code):
                spans.append(MaskSpan(field - start, relative, 'branch-ext'))
        in_range = target is not None and 0 <= target < 2**32
        return DecodedInstruction(start, pos - start, flow, tuple(spans), target if in_range else None)


def tables_of(bench: Bench, pair: str) -> dict[str, PeTables]:
    """The two builds of a synthetic pair as `BuildImage`s."""
    out = {}
    for side in SIDES:
        build = bench.build(pair, side)
        out[side] = PeTables(build.reader, build.overview)
    return out


def _la(asm: Asm, rd: Rdata) -> None:
    """`term`'s code with `CloseHandle` instead of `TerminateProcess`: the same masked shape, another API."""
    asm.label('la')
    asm.prologue()
    asm.raw(b'\x48\xc7\xc1\xff\xff\xff\xff\x31\xd2')   # mov rcx,-1; xor edx,edx
    asm.call_iat(rd.iat['CloseHandle'])
    asm.epilogue()


def _imp(asm: Asm, rd: Rdata) -> None:
    """Uses `TerminateProcess` in code that is not `term`'s."""
    asm.label('imp')
    asm.prologue()
    asm.raw(b'\x31\xc9\xba\x01\x00\x00\x00')           # xor ecx,ecx; mov edx,1
    asm.call_iat(rd.iat['TerminateProcess'])
    asm.epilogue()


def _main_calling(*names: str):
    def emit(asm: Asm, rd: Rdata) -> None:
        asm.label('main')
        asm.prologue()
        for name in names:
            asm.call(name)
        asm.raw(b'\x48\x83\xc4\x28\x31\xc0\xc3')       # add rsp,0x28; xor eax,eax; ret
        if 'la' in names:
            _la(asm, rd)
        if 'imp' in names:
            _imp(asm, rd)
    return emit


@functools.cache
def new_images() -> dict[str, bytes]:
    """LA (the shape of `term`, a different API), IMP (the import, other code) and BOTH (LA's function and IMP's code)."""
    def build(names: tuple[str, ...], imports: list[str]) -> bytes:
        return _image(_main_calling(*names), {KERNEL32: imports}, {}, rich=MSVC_RICH)
    return {'LA': build(('la',), ['CloseHandle']), 'IMP': build(('imp',), ['TerminateProcess']),
            'BOTH': build(('la', 'imp'), ['CloseHandle', 'TerminateProcess'])}


def synergy_builds(bench: Bench) -> dict[str, bytes]:
    """The builds of the plan's section 5 grid, by name: V1 (capa-api older), V1r (capa-control newer: V1's code rebuilt
    0x40 further on), V1t (diec-toolchain newer: V1's code, GNU-style layout), V2 (capa-api newer), the three new images
    and four clean files."""
    series = {'V1': ('capa-api', 'older'), 'V1r': ('capa-control', 'newer'), 'V1t': ('diec-toolchain', 'newer'),
              'V2': ('capa-api', 'newer')}
    clean = {'clean-1': ('floss-static', 'older'), 'clean-2': ('floss-static', 'newer'),
             'clean-3': ('floss-decode', 'older'), 'clean-4': ('floss-decode', 'newer')}
    return {**{name: bench.build(*key).data for name, key in series.items()}, **new_images(),
            **{name: bench.build(*key).data for name, key in clean.items()}}
