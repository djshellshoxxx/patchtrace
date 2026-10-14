"""Raw and address-masked function body hashes (SPEC-32 s5.2).

`raw_sha256`: SHA-256 of the exact code bytes [rva, rva + size). `masked_sha256`: SHA-256 of the function's disassembly
(`llvm-objdump -d --no-show-raw-insn --symbolize-operands -M intel`) with every address-dependent operand normalised:
local labels renumbered per function, symbol annotations -> <A>, `rip +/- disp` -> rip+D, comments dropped, and
immediates that point into the image -> R. Two bodies with equal masked hashes differ at most in addresses.
"""
from __future__ import annotations

import bisect
import hashlib
import re
from dataclasses import dataclass
from pathlib import Path

from .pe import PEImage
from .toolchain import Toolchain, run_tool

_INSN = re.compile(r'^\s*([0-9a-f]+):\s+(.*)$')
_LABEL = re.compile(r'^<(L\d+)>:\s*$')
_LOCAL_REF = re.compile(r'<(L\d+)>')
_SYMBOL = re.compile(r'<[^<>]*>')
_RIP = re.compile(r'rip\s*([+-])\s*0x[0-9a-f]+')
_HEX = re.compile(r'\b0x([0-9a-f]+)\b')


@dataclass(frozen=True)
class Disassembly:
    addresses: list[int]          # sorted VAs of instructions
    texts: list[str]              # instruction text (mnemonic + operands), raw from objdump
    labels: dict[int, list[str]]  # VA -> local label names defined there
    image_base: int
    image_end: int
    tool_version: str

    def normalized(self, rva: int, size: int) -> list[str]:
        lo = bisect.bisect_left(self.addresses, self.image_base + rva)
        hi = bisect.bisect_left(self.addresses, self.image_base + rva + size)
        names: dict[str, str] = {}

        def local(name: str) -> str:
            return names.setdefault(name, f'L{len(names)}')

        out = []
        for k in range(lo, hi):
            va = self.addresses[k]
            for label in self.labels.get(va, ()):
                out.append(local(label) + ':')
            text = self.texts[k].split('#', 1)[0]
            text = _LOCAL_REF.sub(lambda m: '<' + local(m.group(1)) + '>', text)
            text = _SYMBOL.sub(lambda m: m.group(0) if re.fullmatch(r'<L\d+>', m.group(0)) else '<A>', text)
            text = _RIP.sub('rip+D', text)
            text = _HEX.sub(lambda m: 'R' if self.image_base <= int(m.group(1), 16) < self.image_end else m.group(0),
                            text)
            out.append(' '.join(text.split()))
        return out

    def masked_sha256(self, rva: int, size: int) -> str:
        return hashlib.sha256('\n'.join(self.normalized(rva, size)).encode('utf-8')).hexdigest()


def parse_objdump(text: str, image_base: int, image_end: int, tool_version: str = '') -> Disassembly:
    addresses, texts, labels = [], [], {}
    pending: list[str] = []
    for line in text.splitlines():
        lab = _LABEL.match(line.strip())
        if lab:
            pending.append(lab.group(1))
            continue
        m = _INSN.match(line)
        if not m:
            pending = [] if line.strip().endswith('>:') else pending   # a new symbol resets pending labels
            continue
        va = int(m.group(1), 16)
        if pending:
            labels[va] = pending
            pending = []
        addresses.append(va)
        texts.append(m.group(2))
    order = sorted(range(len(addresses)), key=addresses.__getitem__)
    return Disassembly([addresses[i] for i in order], [texts[i] for i in order], labels, image_base, image_end,
                       tool_version)


def disassemble(image: PEImage, tools: Toolchain, timeout: float = 900) -> Disassembly:
    exe = tools.path('llvm-objdump')
    result = run_tool([exe, '-d', '--no-show-raw-insn', '--symbolize-operands', '-M', 'intel', str(image.path)],
                      timeout=timeout, check=True)
    return parse_objdump(result.log_tail, image.image_base, image.image_base + image.size_of_image,
                         tools.get('llvm-objdump').version or '')


def raw_sha256(image: PEImage, rva: int, size: int) -> str:
    return hashlib.sha256(image.read(rva, size)).hexdigest()


def body_fact(old: tuple[str, str] | None, new: tuple[str, str] | None) -> str:
    """(raw, masked) per side -> identical | address-only | different | n/a."""
    if old is None or new is None:
        return 'n/a'
    if old[0] == new[0]:
        return 'identical'
    return 'address-only' if old[1] == new[1] else 'different'


def hash_functions(image: PEImage, disasm: Disassembly, spans: list[tuple[int, int]]) -> dict[int, tuple[str, str]]:
    """rva -> (raw_sha256, masked_sha256) for each (rva, size)."""
    return {rva: (raw_sha256(image, rva, size), disasm.masked_sha256(rva, size)) for rva, size in spans}


def file_sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as handle:
        for chunk in iter(lambda: handle.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()
