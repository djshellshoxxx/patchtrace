"""SYNTHETIC PE helpers for the byte-window tests (YRX plan s5). Bytes only, NEVER executed.

Builds on the hand-assembled images of `test_intel_tools_pe`: `function_layout` recovers each function's RVA and
size from the assembler labels, `LA`/`IMP`/`BOTH` are the three extra images of the synergy grid, and
`with_tables` appends `.pdata` and `.reloc` sections to a copy of an image so the table readers have real input.
"""
from __future__ import annotations

import struct
from dataclasses import dataclass

from test_intel_tools_pe import (
    _CAPA_STRINGS,
    KERNEL32,
    MSVC_RICH,
    RDATA,
    RDATA_RVA,
    SECTION_ALIGN,
    Asm,
    Rdata,
    _capa_code,
    _capa_imports,
    _image,
)

STRINGS = {'buffer': b'\0' * 16}


@dataclass(frozen=True)
class Layout:
    image: bytes
    functions: dict[str, tuple[int, int]]  # label -> (rva, size)


def function_layout(emit, imports: dict[str, list[str]], strings: dict[str, bytes], **pe) -> Layout:
    """Build an image and report (rva, size) of every label in code order; the last ends at the code end."""
    seen: list[Asm] = []

    def spy(asm: Asm, rd: Rdata) -> None:
        seen.append(asm)
        emit(asm, rd)

    image = _image(spy, imports, strings, **pe)
    asm = seen[0]
    ordered = sorted(asm.labels.items(), key=lambda item: item[1])
    ends = [rva for _, rva in ordered[1:]] + [asm.here]
    return Layout(image, {name: (rva, end - rva) for (name, rva), end in zip(ordered, ends, strict=True)})


def capa_layout(newer: bool) -> Layout:
    return function_layout(_capa_code(newer), _capa_imports(newer), _CAPA_STRINGS, rich=MSVC_RICH)


def _term_like(asm: Asm, api_slot: int) -> None:
    """`term`'s register setup around an indirect call to `api_slot`."""
    asm.prologue()
    asm.raw(b'\x48\xc7\xc1\xff\xff\xff\xff\x31\xd2')  # mov rcx,-1; xor edx,edx
    asm.call_iat(api_slot)
    asm.epilogue()


def _unrelated_terminate(asm: Asm, rd: Rdata) -> None:
    asm.prologue()
    asm.lea('rcx', rd.string_rva['buffer'])
    asm.raw(b'\xba\x07\x00\x00\x00')  # mov edx, 7
    asm.call_iat(rd.iat['TerminateProcess'])
    asm.epilogue()


def _main(asm: Asm, callees: list[str]) -> None:
    asm.label('main')
    asm.prologue()
    for callee in callees:
        asm.call(callee)
    asm.raw(b'\x48\x83\xc4\x28\x31\xc0\xc3')


def _la(asm: Asm, rd: Rdata) -> None:
    _main(asm, ['look'])
    asm.label('look')
    _term_like(asm, rd.iat['CloseHandle'])


def _imp(asm: Asm, rd: Rdata) -> None:
    _main(asm, ['other'])
    asm.label('other')
    _unrelated_terminate(asm, rd)


def _both(asm: Asm, rd: Rdata) -> None:
    _main(asm, ['look', 'other'])
    asm.label('look')
    _term_like(asm, rd.iat['CloseHandle'])
    asm.label('other')
    _unrelated_terminate(asm, rd)


def la_image() -> bytes:
    """A function with `term`'s register setup that calls CloseHandle: same masked shape, different API."""
    return _image(_la, {KERNEL32: ['CloseHandle']}, STRINGS, rich=MSVC_RICH)


def imp_image() -> bytes:
    """Imports and uses TerminateProcess in unrelated code."""
    return _image(_imp, {KERNEL32: ['TerminateProcess']}, STRINGS, rich=MSVC_RICH)


def both_image() -> bytes:
    """LA's function and IMP's code in one image."""
    return _image(_both, {KERNEL32: ['CloseHandle', 'TerminateProcess']}, STRINGS, rich=MSVC_RICH)


def reloc_block(fields: list[tuple[int, int]]) -> bytes:
    """One `.reloc` page block per 4 KiB page for (rva, type) fields (type 10 = DIR64, 3 = HIGHLOW)."""
    pages: dict[int, list[int]] = {}
    for rva, kind in fields:
        pages.setdefault(rva & ~0xFFF, []).append((kind << 12) | (rva & 0xFFF))
    out = b''
    for page, entries in sorted(pages.items()):
        entries = entries + [0] * (len(entries) % 2)
        out += struct.pack('<II', page, 8 + 2 * len(entries)) + struct.pack(f'<{len(entries)}H', *entries)
    return out


def tabled_image(emit, imports: dict[str, list[str]], strings: dict[str, bytes], *, pdata: tuple[str, ...] = (),
                 relocs: tuple[tuple[int, int], ...] = ()) -> Layout:
    """`function_layout` plus a `.pdata` entry for each labelled function and `.reloc` fields (rva, type).

    The entries share one UNWIND_INFO (version 1, no flags) in `.xdata`. The extra sections sit after `.rdata`, so
    `.text` and `.rdata` keep their RVAs; directory slots 3 (exception) and 5 (base relocation) are patched into
    the optional header afterwards."""
    functions = function_layout(emit, imports, strings).functions
    pdata_rva = RDATA_RVA + SECTION_ALIGN
    xdata_rva = pdata_rva + SECTION_ALIGN
    entries = b''.join(struct.pack('<III', functions[n][0], functions[n][0] + functions[n][1], xdata_rva)
                       for n in sorted(pdata, key=lambda n: functions[n][0]))
    extras = [('.pdata', entries or b'\0' * 12, RDATA), ('.xdata', b'\x01\x00\x00\x00', RDATA)]
    reloc = reloc_block(list(relocs))
    if relocs:
        extras.append(('.reloc', reloc, 0x42000040))
    image = bytearray(function_layout(emit, imports, strings, extra_sections=tuple(extras)).image)
    directories = struct.unpack_from('<I', image, 0x3C)[0] + 24 + 112
    if pdata:
        struct.pack_into('<II', image, directories + 8 * 3, pdata_rva, len(entries))
    if relocs:
        struct.pack_into('<II', image, directories + 8 * 5, xdata_rva + SECTION_ALIGN, len(reloc))
    return Layout(bytes(image), functions)
