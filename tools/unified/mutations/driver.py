"""Build and label planted mutants through the SPEC-32 factory (`tools/calibration/tier_r`); there is no second factory.

One class is one base image plus one mutant image per planted function, so `count` mutants cost `count + 1` builds.
Truth comes from `label_construction` (SPEC-32 s7, `planted-mutation`): the edited function is `changed(<class id>)`,
every other function is `unchanged`. A mutant is accepted only if the edit is real code (`classes.py` acceptance); an
equivalent mutant (the compiler produced the same code) is rejected with its reason and the next candidate edit of the
same function is tried, so the base image never changes. Output documents are `known-answer-labels/1`, stratum
`mutation`; the SPEC-31 provenance (class, edit, attempts, rejections, accepted verdicts) lives in `case`.
"""
from __future__ import annotations

import re
from bisect import bisect_left
from dataclasses import dataclass, field
from pathlib import Path

from tools.calibration.tier_r import factory as F
from tools.calibration.tier_r.bodyhash import Disassembly
from tools.calibration.tier_r.labeler import SideData, label_construction

from .classes import BY_ID, MutationClass
from .templates import Module

MAX_ATTEMPTS = 3
# Loops stay scalar: a vectorised loop turns one planted edit into a rewrite of the whole function body.
CFLAGS = ('-fno-vectorize', '-fno-slp-vectorize', '-fno-unroll-loops')
_SYMBOL = re.compile(r'<([^<>]+)>')
_LOCAL = re.compile(r'L\d+')


@dataclass
class MutantResult:
    docs: list[dict] = field(default_factory=list)
    rejected: list[dict] = field(default_factory=list)
    exhausted: list[int] = field(default_factory=list)       # indices whose every candidate edit was rejected


def symbol_refs(disasm: Disassembly, rva: int, size: int) -> tuple[str, ...]:
    """Every non-local `<symbol>` the disassembly of [rva, rva + size) names, in order: what a call, branch or
    RIP-relative operand refers to. Unlike the masked body hash, a swapped callee or global changes this tuple."""
    lo = bisect_left(disasm.addresses, disasm.image_base + rva)
    hi = bisect_left(disasm.addresses, disasm.image_base + rva + size)
    return tuple(name for k in range(lo, hi) for name in _SYMBOL.findall(disasm.texts[k])
                 if not _LOCAL.fullmatch(name))


def _write(directory: Path, source: str) -> Path:
    directory.mkdir(parents=True, exist_ok=True)
    (directory / 'mod.c').write_text(source, encoding='utf-8', newline='\n')
    return directory


def _base(module: Module, root: Path, version: str) -> F.BaseSource:
    cid = module.class_id
    return F.BaseSource(
        project=f'unified-mutants-{cid}', lineage=F.pair_id('L-ours', 'unified-mutants', cid), family='synthetic',
        source={'suite': f'unified-mutants/{cid}', 'version': version, 'license_spdx': 'MIT'}, root=root,
        files=('mod.c',), output=f'ka_{cid.replace("-", "_")}.dll', profile='msvc-free', std='c11', cflags=CFLAGS,
        tag=version)


def _check(mclass: MutationClass, record: dict, old: SideData, new: SideData) -> str | None:
    """None when the planted edit is real code (the record is settled in place), else why it is not."""
    if record['check'] == 'ok':
        return None
    if mclass.acceptance == 'symbolic' and record['body'] == 'address-only':
        before = symbol_refs(old.disasm, record['old_rva'], record['old_size'])
        after = symbol_refs(new.disasm, record['new_rva'], record['new_size'])
        if before == after:
            return 'the masked body and the symbol references are equal: the edit left the code unchanged'
        record['check'], record['notes'] = 'ok', 'address operand names another symbol'
        return None
    return 'the planted edit left the code unchanged'


def _document(module: Module, mclass: MutationClass, index: int, attempt: int, edit: dict, rejected: list[dict],
              base: F.BaseSource, mutant: F.BaseSource, old: SideData, new: SideData, functions: list[dict],
              opt: str) -> dict:
    case = {'unified_class': mclass.id, 'index': index, 'seed': module.seed, 'target': module.names[index],
            'edit': edit, 'attempts': attempt + 1, 'rejected': rejected, 'acceptance': mclass.acceptance,
            'verdicts': list(mclass.verdicts)}
    return F.finalize(pid=F.pair_id('mut', mclass.id, f'{index:02d}', opt), stratum='mutation', method='mutation',
                      base_old=base, base_new=mutant, old=old, new=new, label_source='planted-mutation',
                      functions=functions, case=case)


def build_mutants(session: F.Session, module: Module, *, work: Path, opt: str = 'O2',
                  indices: range | list[int] | None = None, max_attempts: int = MAX_ATTEMPTS) -> MutantResult:
    mclass = BY_ID[module.class_id]
    root = Path(work) / module.class_id
    base_dir = _write(root / 'base', module.base_source())
    base = _base(module, base_dir, 'base')
    old = session.side(session.build(base.spec(opt=opt, variant='base')), base_dir)
    out = MutantResult()
    for index in indices if indices is not None else range(len(module.names)):
        target, rejected = module.names[index], []
        for attempt in range(min(max_attempts, module.attempts(index))):
            source, edit = module.mutant(index, attempt)
            tag = f'm{index:02d}a{attempt}'
            mutant_dir = _write(root / tag, source)
            mutant = _base(module, mutant_dir, tag)
            new = session.side(session.build(mutant.spec(opt=opt, variant=tag)), mutant_dir)
            functions = label_construction(old, new, label_source='planted-mutation', semantic=True,
                                           declared={target: ('changed', mclass.id)})
            record = next((f for f in functions if f['name'] == target and f['identity'] == 'same'), None)
            problem = 'the planted function has no counterpart in both images' if record is None else \
                _check(mclass, record, old, new)
            if problem is None:
                out.docs.append(_document(module, mclass, index, attempt, edit, rejected, base, mutant, old, new,
                                          functions, opt))
                break
            rejected.append({'index': index, 'function': target, 'attempt': attempt, 'reason': problem})
        else:
            out.exhausted.append(index)
        out.rejected.extend(rejected)
    return out
