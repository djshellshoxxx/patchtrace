"""Build an `ExtractionContext` from tool evidence already on hand (duck-typed; pure, no tool imports).

Toolchain comes only from signature-certain DiE evidence; anything else is `unknown`, which makes a model
abstain through the unseen-level rule rather than guess. Never executes or opens the target.
"""
from __future__ import annotations

from collections.abc import Iterable

from .features import ExtractionContext

_ARCH = {0x8664: 'x64', 0xAA64: 'arm64', 0x14C: 'x86', 0x1C4: 'arm'}


def _toolchain(env_evidence: Iterable) -> str:
    found: set[str] = set()
    for item in env_evidence or ():
        if getattr(item, 'certainty', None) != 'signature':
            continue
        text = f'{getattr(item, "toolchain", None) or ""}'.lower()
        if 'msvc' in text or 'microsoft' in text or 'visual c' in text:
            found.add('msvc')
        elif 'clang' in text or 'llvm' in text:
            found.add('clang')
        elif 'gcc' in text or 'mingw' in text:
            found.add('gcc')
    return found.pop() if len(found) == 1 else 'unknown'


def context_from_tools(env_evidence: Iterable, pe_overview) -> ExtractionContext:
    machine = getattr(pe_overview, 'machine', None)
    arch = _ARCH.get(getattr(machine, 'code', None), 'other')
    return ExtractionContext(symbol_provenance='none', arch=arch, toolchain=_toolchain(env_evidence))
