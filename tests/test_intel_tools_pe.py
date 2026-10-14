"""SYNTHETIC Windows x64 PE fixtures for the SPEC-29 tool adapters (capa, FLOSS, diec). Bytes only, NEVER executed.

Each pair (`older`, `newer`) has controlled changes plus unchanged controls, so real tool output on these exact bytes
(tests/fixtures/intel_tools/, provenance in manifest.json) and the live check can be compared deterministically.
The images are hand-assembled PE32+ AMD64 console programs: a real import table, RIP-relative IAT calls, strings
in `.rdata`, an optional XOR decode loop and an optional Rich header. They are test inputs, not real software, and
no result obtained on them is evidence about real binaries.

Pairs:
- capa-api: older {hostname, terminate, runtime-link, xor-loop, log(no-op)}; newer drops `terminate`, inserts
  `env` (shifting every later function), turns `log` into a WriteFile call (modified function gains a
  capability) and adds a `.tls` section (file-scope, unlocalized). hostname/runtime-link/xor stay unchanged.
- capa-control: same code; newer has 0x40 bytes of leading padding in .text (all RVAs shift) and another
  timestamp: no capability may change.
- floss-static: string added/removed/unchanged (ASCII + UTF-16LE) and an AWS documentation example key for
  redaction tests.
- floss-decode: identical static strings; only the XOR-encoded `.data` payload differs (visible to FLOSS
  decoding, which is emulation and therefore opt-in).
- diec-same: MSVC-like Rich header + linker 14.36 on both sides, different code.
- diec-toolchain: older MSVC-like, newer GNU-ld-like (linker 2.38, no Rich header, MinGW-style sections).
"""
from __future__ import annotations

import hashlib
import struct
from dataclasses import dataclass, field

IMAGE_BASE = 0x140000000
FILE_ALIGN = 0x200
SECTION_ALIGN = 0x1000
TEXT_RVA, RDATA_RVA, DATA_RVA = 0x1000, 0x2000, 0x3000
DOS_STUB = bytes.fromhex(
    '0e1fba0e00b409cd21b8014ccd21546869732070726f6772616d2063616e6e6f'
    '742062652072756e20696e20444f53206d6f64652e0d0d0a2400000000000000')
AWS_EXAMPLE_KEY = 'AKIAIOSFODNN7EXAMPLE'  # AWS documentation example access key id (not a credential)


def align(value: int, to: int) -> int:
    return (value + to - 1) // to * to


def _rol(value: int, count: int) -> int:
    count %= 32
    value &= 0xFFFFFFFF
    return ((value << count) | (value >> (32 - count))) & 0xFFFFFFFF if count else value


def rich_header(dos: bytes, entries: list[tuple[int, int, int]]) -> bytes:
    """Rich header placed at len(dos): entries are (product id, build, count); checksum per the public algorithm."""
    start = len(dos)
    checksum = start
    for index, byte in enumerate(dos):
        if 0x3C <= index <= 0x3F:  # e_lfanew is excluded
            continue
        checksum = (checksum + _rol(byte, index)) & 0xFFFFFFFF
    for product, build, count in entries:
        checksum = (checksum + _rol((product << 16) | build, count)) & 0xFFFFFFFF
    out = struct.pack('<4I', 0x536E6144 ^ checksum, checksum, checksum, checksum)  # 'DanS' + 3 padding words
    for product, build, count in entries:
        out += struct.pack('<II', ((product << 16) | build) ^ checksum, count ^ checksum)
    return out + b'Rich' + struct.pack('<I', checksum)


MSVC_RICH = [(0x0105, 33134, 12), (0x0104, 33134, 9), (0x0103, 33134, 3), (0x0001, 0, 41),
             (0x0101, 33134, 4), (0x00FF, 33134, 1), (0x0102, 33134, 1)]


@dataclass
class Rdata:
    imports: dict[str, list[str]]
    strings: dict[str, bytes]
    blob: bytes = b''
    iat: dict[str, int] = field(default_factory=dict)
    string_rva: dict[str, int] = field(default_factory=dict)
    import_dir: tuple[int, int] = (0, 0)
    iat_dir: tuple[int, int] = (0, 0)


def plan_rdata(imports: dict[str, list[str]], strings: dict[str, bytes]) -> Rdata:
    """IAT first (fixed RVAs for code), then descriptors, ILT, hint/name entries, DLL names, user strings."""
    out = bytearray()
    plan = Rdata(imports, strings)
    iat_pos: dict[str, int] = {}
    for dll, funcs in imports.items():
        iat_pos[dll] = len(out)
        out += b'\0' * 8 * (len(funcs) + 1)
    iat_size = len(out)
    desc = len(out)
    out += b'\0' * 20 * (len(imports) + 1)
    ilt_pos: dict[str, int] = {}
    for dll, funcs in imports.items():
        ilt_pos[dll] = len(out)
        out += b'\0' * 8 * (len(funcs) + 1)
    for i, (dll, funcs) in enumerate(imports.items()):
        for j, func in enumerate(funcs):
            if len(out) % 2:
                out += b'\0'
            hint = RDATA_RVA + len(out)
            out += struct.pack('<H', 0) + func.encode() + b'\0'
            struct.pack_into('<Q', out, iat_pos[dll] + 8 * j, hint)
            struct.pack_into('<Q', out, ilt_pos[dll] + 8 * j, hint)
            plan.iat[func] = RDATA_RVA + iat_pos[dll] + 8 * j
        name = RDATA_RVA + len(out)
        out += dll.encode() + b'\0'
        struct.pack_into('<IIIII', out, desc + 20 * i, RDATA_RVA + ilt_pos[dll], 0, 0, name, RDATA_RVA + iat_pos[dll])
    for key, value in strings.items():
        while len(out) % 16:
            out += b'\0'
        plan.string_rva[key] = RDATA_RVA + len(out)
        out += value
    plan.blob = bytes(out)
    plan.import_dir = (RDATA_RVA + desc, 20 * (len(imports) + 1))
    plan.iat_dir = (RDATA_RVA, iat_size)
    return plan


class Asm:
    """Tiny x64 emitter for the handful of instructions the fixtures need (RIP-relative fixups by RVA)."""

    def __init__(self, base_rva: int = TEXT_RVA):
        self.base = base_rva
        self.code = bytearray()
        self.labels: dict[str, int] = {}
        self.fixups: list[tuple[int, str, int]] = []

    @property
    def here(self) -> int:
        return self.base + len(self.code)

    def label(self, name: str) -> None:
        self.labels[name] = self.here

    def raw(self, data: bytes) -> None:
        self.code += data

    def prologue(self) -> None:
        self.raw(b'\x48\x83\xec\x28')  # sub rsp, 0x28

    def epilogue(self) -> None:
        self.raw(b'\x48\x83\xc4\x28\xc3')  # add rsp, 0x28; ret

    def call_iat(self, slot_rva: int) -> None:
        self.raw(b'\xff\x15' + struct.pack('<i', slot_rva - (self.here + 6)))

    def lea(self, reg: str, target_rva: int) -> None:
        opcode = {'rcx': b'\x48\x8d\x0d', 'rdx': b'\x48\x8d\x15', 'r8': b'\x4c\x8d\x05', 'r9': b'\x4c\x8d\x0d'}[reg]
        self.raw(opcode + struct.pack('<i', target_rva - (self.here + 7)))

    def call(self, label: str) -> None:
        self.fixups.append((len(self.code) + 1, label, len(self.code) + 5))
        self.raw(b'\xe8\0\0\0\0')

    def finish(self) -> bytes:
        for at, label, end in self.fixups:
            struct.pack_into('<i', self.code, at, self.labels[label] - (self.base + end))
        return bytes(self.code)


@dataclass
class Section:
    name: str
    data: bytes
    characteristics: int
    rva: int


def build_pe64(sections: list[Section], *, entry_rva: int, import_dir: tuple[int, int] = (0, 0),
               iat_dir: tuple[int, int] = (0, 0), timestamp: int = 0x66000000, linker: tuple[int, int] = (14, 36),
               rich: list[tuple[int, int, int]] | None = None, overlay: bytes = b'') -> bytes:
    """PE32+ AMD64 console image; sections must be in ascending, SECTION_ALIGN-spaced RVA order."""
    dos = bytearray(0x40)
    struct.pack_into('<2sHHHHHHHHHHHHH', dos, 0, b'MZ', 0x90, 3, 0, 4, 0, 0xFFFF, 0, 0xB8, 0, 0, 0, 0x40, 0)
    stub = bytes(dos) + DOS_STUB
    rich_bytes = rich_header(stub, rich) if rich else b''
    e_lfanew = align(len(stub) + len(rich_bytes), 8)
    headers = bytearray(stub + rich_bytes)
    headers += b'\0' * (e_lfanew - len(headers))
    struct.pack_into('<I', headers, 0x3C, e_lfanew)
    if rich:  # the checksum covers the DOS header with e_lfanew zeroed; recompute with the final layout
        headers[len(stub):len(stub) + len(rich_bytes)] = rich_header(bytes(headers[:len(stub)]), rich)
    size_of_headers = align(e_lfanew + 4 + 20 + 240 + 40 * len(sections), FILE_ALIGN)
    raw_offset = size_of_headers
    table = bytearray()
    body = bytearray()
    size_of_code = size_of_init = 0
    for section in sections:
        raw_size = align(len(section.data), FILE_ALIGN) if section.data else 0
        table += struct.pack('<8sIIIIIIHHI', section.name.encode('latin-1')[:8].ljust(8, b'\0'),
                             max(len(section.data), 1), section.rva, raw_size, raw_offset if raw_size else 0,
                             0, 0, 0, 0, section.characteristics)
        body += section.data.ljust(raw_size, b'\0')
        raw_offset += raw_size
        if section.characteristics & 0x20:
            size_of_code += raw_size
        else:
            size_of_init += raw_size
    size_of_image = align(sections[-1].rva + max(len(sections[-1].data), 1), SECTION_ALIGN)
    coff = struct.pack('<4sHHIIIHH', b'PE\0\0', 0x8664, len(sections), timestamp, 0, 0, 240, 0x22)
    optional = bytearray(240)
    struct.pack_into('<HBBIIIII', optional, 0, 0x20B, linker[0], linker[1], size_of_code, size_of_init, 0,
                     entry_rva, TEXT_RVA)
    struct.pack_into('<QIIHHHHHHIIIIHHQQQQII', optional, 24, IMAGE_BASE, SECTION_ALIGN, FILE_ALIGN, 6, 0, 0, 0,
                     6, 0, 0, size_of_image, size_of_headers, 0, 3, 0x8160, 0x100000, 0x1000, 0x100000, 0x1000, 0, 16)
    for index, (rva, size) in ((1, import_dir), (12, iat_dir)):
        struct.pack_into('<II', optional, 112 + 8 * index, rva, size)
    headers += coff + optional + table
    headers += b'\0' * (size_of_headers - len(headers))
    return bytes(headers + body + overlay)


CODE, RDATA, DATA = 0x60000020, 0x40000040, 0xC0000040


def _image(asm_fn, imports: dict[str, list[str]], strings: dict[str, bytes], *, data: bytes = b'',
           extra_sections: tuple[tuple[str, bytes, int], ...] = (), pad: int = 0, **pe) -> bytes:
    rdata = plan_rdata(imports, strings)
    asm = Asm()
    asm.raw(b'\xcc' * pad)
    asm_fn(asm, rdata)
    code = asm.finish()
    sections = [Section('.text', code, CODE, TEXT_RVA), Section('.rdata', rdata.blob, RDATA, RDATA_RVA)]
    rva = RDATA_RVA + SECTION_ALIGN
    if data:
        sections.append(Section('.data', data, DATA, rva))
        rva += SECTION_ALIGN
    for name, payload, characteristics in extra_sections:
        sections.append(Section(name, payload, characteristics, rva))
        rva += SECTION_ALIGN
    return build_pe64(sections, entry_rva=asm.labels['main'], import_dir=rdata.import_dir, iat_dir=rdata.iat_dir,
                      **pe)


KERNEL32 = 'KERNEL32.dll'


def _capa_code(newer: bool):
    def emit(asm: Asm, rd: Rdata) -> None:
        asm.label('main')
        asm.prologue()
        if newer:
            asm.call('env')
        asm.call('host')
        if not newer:
            asm.call('term')
        asm.call('dyn')
        asm.call('log')
        asm.lea('rcx', rd.string_rva['buffer'])
        asm.raw(b'\xba\x10\x00\x00\x00')  # mov edx, 16
        asm.call('xor')
        asm.raw(b'\x48\x83\xc4\x28\x31\xc0\xc3')  # add rsp,0x28; xor eax,eax; ret
        if newer:  # inserted before `host`: every later function moves (RVA-shift control)
            asm.label('env')
            asm.prologue()
            asm.lea('rcx', rd.string_rva['envname'])
            asm.lea('rdx', rd.string_rva['buffer'])
            asm.raw(b'\x41\xb8\x10\x00\x00\x00')  # mov r8d, 16
            asm.call_iat(rd.iat['GetEnvironmentVariableA'])
            asm.epilogue()
        asm.label('host')
        asm.prologue()
        asm.lea('rcx', rd.string_rva['buffer'])
        asm.lea('rdx', rd.string_rva['size'])
        asm.call_iat(rd.iat['GetComputerNameA'])
        asm.epilogue()
        if not newer:
            asm.label('term')
            asm.prologue()
            asm.raw(b'\x48\xc7\xc1\xff\xff\xff\xff\x31\xd2')  # mov rcx,-1; xor edx,edx
            asm.call_iat(rd.iat['TerminateProcess'])
            asm.epilogue()
        asm.label('dyn')
        asm.prologue()
        asm.lea('rcx', rd.string_rva['kernel32'])
        asm.call_iat(rd.iat['GetModuleHandleA'])
        asm.raw(b'\x48\x89\xc1')  # mov rcx, rax
        asm.lea('rdx', rd.string_rva['beep'])
        asm.call_iat(rd.iat['GetProcAddress'])
        asm.epilogue()
        asm.label('log')
        if newer:  # modified function gains WriteFile
            asm.prologue()
            asm.raw(b'\x48\xc7\xc1\xf5\xff\xff\xff')  # mov rcx, -11 (STD_OUTPUT_HANDLE)
            asm.lea('rdx', rd.string_rva['message'])
            asm.raw(b'\x41\xb8\x08\x00\x00\x00\x45\x31\xc9')  # mov r8d, 8; xor r9d, r9d
            asm.call_iat(rd.iat['WriteFile'])
            asm.epilogue()
        else:
            asm.raw(b'\x31\xc0\xc3')  # xor eax,eax; ret
        asm.label('xor')  # tight loop with a non-zeroing XOR: rcx = buffer, rdx = length
        asm.raw(b'\x31\xc0')                      # xor eax, eax
        asm.raw(b'\x80\x34\x01\x5a')              # loop: xor byte [rcx+rax], 0x5a
        asm.raw(b'\x48\xff\xc0')                  # inc rax
        asm.raw(b'\x48\x39\xd0')                  # cmp rax, rdx
        asm.raw(b'\x72\xf4')                      # jb loop
        asm.raw(b'\xc3')
    return emit


def _capa_imports(newer: bool) -> dict[str, list[str]]:
    funcs = ['GetComputerNameA', 'GetModuleHandleA', 'GetProcAddress']
    funcs += ['GetEnvironmentVariableA', 'WriteFile'] if newer else ['TerminateProcess']
    return {KERNEL32: funcs}


_CAPA_STRINGS = {'kernel32': b'kernel32.dll\0', 'beep': b'Beep\0', 'envname': b'PATCHTRACE_SYNTHETIC\0',
                 'message': b'synthetic\0', 'size': struct.pack('<I', 16), 'buffer': b'\0' * 16}


def capa_api_pair() -> tuple[bytes, bytes]:
    older = _image(_capa_code(False), _capa_imports(False), _CAPA_STRINGS, rich=MSVC_RICH)
    newer = _image(_capa_code(True), _capa_imports(True), _CAPA_STRINGS, rich=MSVC_RICH,
                   extra_sections=(('.tls', b'\0' * 16, DATA),))
    return older, newer


def capa_control_pair() -> tuple[bytes, bytes]:
    older = _image(_capa_code(False), _capa_imports(False), _CAPA_STRINGS, rich=MSVC_RICH)
    newer = _image(_capa_code(False), _capa_imports(False), _CAPA_STRINGS, rich=MSVC_RICH, pad=0x40,
                   timestamp=0x66100000)
    return older, newer


def _strings_code(asm: Asm, rd: Rdata) -> None:
    asm.label('main')
    asm.prologue()
    for key in sorted(k for k in rd.string_rva if k.startswith('s_')):
        asm.lea('rcx', rd.string_rva[key])
        asm.call_iat(rd.iat['OutputDebugStringA'])
    asm.raw(b'\x48\x83\xc4\x28\x31\xc0\xc3')


def _floss_strings(newer: bool) -> dict[str, bytes]:
    strings = {'s_unchanged': b'PatchTrace synthetic: configuration loaded\0',
               's_wide': 'PatchTrace synthetic wide marker'.encode('utf-16-le') + b'\0\0',
               's_secret': f'aws_access_key_id={AWS_EXAMPLE_KEY}'.encode() + b'\0'}
    if newer:
        strings['s_added'] = b'PatchTrace synthetic: index %u exceeds length %u\0'
    else:
        strings['s_removed'] = b'PatchTrace synthetic: debug dump of internal state\0'
    return strings


def floss_static_pair() -> tuple[bytes, bytes]:
    imports = {KERNEL32: ['OutputDebugStringA']}
    return (_image(_strings_code, imports, _floss_strings(False), rich=MSVC_RICH),
            _image(_strings_code, imports, _floss_strings(True), rich=MSVC_RICH))


def _encode(text: bytes, key: int = 0x5A) -> bytes:
    return bytes(b ^ key for b in text)


def _decode_code(asm: Asm, rd: Rdata) -> None:
    asm.label('main')
    asm.prologue()
    asm.raw(b'\x48\x8d\x0d' + struct.pack('<i', DATA_RVA - (asm.here + 7)))  # lea rcx, [encoded]
    asm.raw(b'\xba\x20\x00\x00\x00')  # mov edx, 32
    asm.call('decode')
    asm.raw(b'\x48\x8d\x0d' + struct.pack('<i', DATA_RVA - (asm.here + 7)))
    asm.call_iat(rd.iat['OutputDebugStringA'])
    asm.lea('rcx', rd.string_rva['s_static'])
    asm.call_iat(rd.iat['OutputDebugStringA'])
    asm.raw(b'\x48\x83\xc4\x28\x31\xc0\xc3')
    asm.label('decode')
    asm.raw(b'\x31\xc0\x80\x34\x01\x5a\x48\xff\xc0\x48\x39\xd0\x72\xf4\xc3')


def floss_decode_pair() -> tuple[bytes, bytes]:
    imports = {KERNEL32: ['OutputDebugStringA']}
    strings = {'s_static': b'PatchTrace synthetic: static marker\0'}
    old_plain = b'PatchTrace decoded: build one\0'.ljust(32, b'\0')
    new_plain = b'PatchTrace decoded: build two\0'.ljust(32, b'\0')
    return (_image(_decode_code, imports, strings, data=_encode(old_plain), rich=MSVC_RICH),
            _image(_decode_code, imports, strings, data=_encode(new_plain), rich=MSVC_RICH))


def diec_same_pair() -> tuple[bytes, bytes]:
    older, _ = capa_api_pair()
    imports = {KERNEL32: ['OutputDebugStringA']}
    newer = _image(_strings_code, imports, _floss_strings(False), rich=MSVC_RICH)
    return older, newer


def diec_toolchain_pair() -> tuple[bytes, bytes]:
    """Older: MSVC-like (Rich header). Newer: the MinGW profile of DiE 3.21's `compiler_MinGW.6.sg` (GNU linker
    2.36, no Rich header so `e_lfanew` is 0x80 right after the standard stub, no `.rsrc`, a `GCC: ` string in
    `.rdata`). Same code on both sides: only the toolchain fingerprint changes."""
    older, _ = capa_api_pair()
    gnu_sections = (('.pdata', b'\0' * 12, RDATA), ('.xdata', b'\0' * 8, RDATA), ('.bss', b'', DATA | 0x80),
                    ('.CRT', b'\0' * 16, DATA), ('.tls', b'\0' * 16, DATA))
    strings = {**_CAPA_STRINGS, 'gcc': b'GCC: (GNU) 10-win32 20220113\0'}
    newer = _image(_capa_code(False), _capa_imports(False), strings, rich=None, linker=(2, 36),
                   extra_sections=gnu_sections)
    return older, newer


def diec_unknown_pair() -> tuple[bytes, bytes]:
    """No Rich header and GNU linker 2.38 (not in the MinGW rule's minor-version list), no `GCC: ` string: DiE 3.21
    reports `Unknown: Unknown` in plain mode and only a heuristic `(Heur)Protection: Generic` with -d -u. Older is
    the MSVC-like image, so the pair exercises 'one side unknown' (never read as a toolchain change)."""
    older, _ = capa_api_pair()
    gnu_sections = (('.pdata', b'\0' * 12, RDATA), ('.xdata', b'\0' * 8, RDATA), ('.bss', b'', DATA | 0x80),
                    ('.CRT', b'\0' * 16, DATA), ('.tls', b'\0' * 16, DATA))
    newer = _image(_capa_code(False), _capa_imports(False), _CAPA_STRINGS, rich=None, linker=(2, 38),
                   extra_sections=gnu_sections)
    return older, newer


PAIRS = {'capa-api': capa_api_pair, 'capa-control': capa_control_pair, 'floss-static': floss_static_pair,
         'floss-decode': floss_decode_pair, 'diec-same': diec_same_pair, 'diec-toolchain': diec_toolchain_pair,
         'diec-unknown': diec_unknown_pair}


def write_pairs(directory) -> dict[str, dict[str, str]]:
    """Write every pair as <name>-older.exe / <name>-newer.exe; returns name -> side -> SHA-256."""
    from pathlib import Path
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    hashes: dict[str, dict[str, str]] = {}
    for name, make in PAIRS.items():
        older, newer = make()
        hashes[name] = {}
        for side, data in (('older', older), ('newer', newer)):
            (directory / f'{name}-{side}.exe').write_bytes(data)
            hashes[name][side] = hashlib.sha256(data).hexdigest()
    return hashes


if __name__ == '__main__':  # research helper: python tests/test_intel_tools_pe.py OUTDIR
    import json
    import sys
    print(json.dumps(write_pairs(sys.argv[1]), indent=2, sort_keys=True))
