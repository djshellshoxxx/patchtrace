"""Honest synthetic walkthrough: no analysis engine or model is invoked."""
from __future__ import annotations

import json
import struct
import tempfile
from pathlib import Path

from .models import AnalysisRun, Finding, Hypothesis, InterpretationRun

OLD_CODE = '''int read_item(const unsigned char *buffer, size_t length, size_t index) {
    return buffer[index];
}'''
NEW_CODE = '''int read_item(const unsigned char *buffer, size_t length, size_t index) {
    if (buffer == NULL || index >= length) {
        return report_invalid_index(index, length);
    }
    return buffer[index];
}'''


def synthetic_pe(variant: int = 0) -> bytes:
    """Small structurally valid AMD64 PE fixture, explicitly synthetic and never executed."""
    image = bytearray(1024)
    image[:2] = b'MZ'
    struct.pack_into('<I', image, 0x3C, 0x80)
    image[0x80:0x84] = b'PE\0\0'
    struct.pack_into('<HHIIIHH', image, 0x84, 0x8664, 1, 0, 0, 0, 240, 0x2022)
    optional = 0x98
    struct.pack_into('<H', image, optional, 0x20B)
    struct.pack_into('<I', image, optional + 4, 512)
    struct.pack_into('<II', image, optional + 16, 0x1000, 0x1000)
    struct.pack_into('<Q', image, optional + 24, 0x180000000)
    struct.pack_into('<II', image, optional + 32, 0x1000, 0x200)
    struct.pack_into('<HH', image, optional + 40, 6, 0)
    struct.pack_into('<HH', image, optional + 48, 6, 0)
    struct.pack_into('<II', image, optional + 56, 0x2000, 0x200)
    struct.pack_into('<HH', image, optional + 68, 3, 0x160)
    struct.pack_into('<QQQQ', image, optional + 72, 0x100000, 0x1000, 0x100000, 0x1000)
    struct.pack_into('<I', image, optional + 108, 16)
    section = optional + 240
    image[section:section + 8] = b'.text\0\0\0'
    struct.pack_into('<IIII', image, section + 8, 64, 0x1000, 512, 512)
    struct.pack_into('<I', image, section + 36, 0x60000020)
    image[512:518] = b'\xb8\x00\x00\x00\x00\xc3'
    label = f'PatchTrace SYNTHETIC SAMPLE {variant}; no real analyzed code'.encode()
    image[576:576 + len(label)] = label
    return bytes(image)


def sample_diff(project) -> dict:
    artifacts = {a.side: a for a in project.artifacts}
    def function(name, address, code, calling=None, called=None):
        return {'name': name, 'fullname': name, 'address': address, 'code': code,
                'calling': calling or [], 'called': called or [], 'instructions': -17200333,
                'sig': f'int {name}(...)', 'sym_type': 'FUNCTION', 'external': False}
    return {
        'old_meta': {'Executable SHA256': artifacts['older'].sha256, 'Synthetic sample': True},
        'new_meta': {'Executable SHA256': artifacts['newer'].sha256, 'Synthetic sample': True},
        'functions': {
            'added': [function('report_invalid_index', '180001200',
                               'int report_invalid_index(size_t index, size_t length) {\n    return -1;\n}',
                               calling=['read_item'])],
            'deleted': [function('debug_dump', '180001400',
                                 'void debug_dump(const char *text) {\n    puts(text);\n}')],
            'modified': [
                {'old': function('read_item', '180001000', OLD_CODE),
                 'new': function('read_item', '180001080', NEW_CODE, called=['report_invalid_index']),
                 'diff_type': ['code', 'address', 'called'], 'ratio': 0.58,
                 'match_types': ['Symbols', 'StructuralGraph']},
                {'old': function('get_version', '180001600', 'int get_version(void) {\n    return 1;\n}'),
                 'new': function('get_version', '180001700', 'int get_version(void) {\n    return 2;\n}'),
                 'diff_type': ['code', 'address'], 'ratio': 0.94, 'match_types': ['Symbols']},
            ],
        },
        'stats': {'added_funcs_len': 1, 'deleted_funcs_len': 1, 'modified_funcs_len': 2},
        'md_credits': 'Synthetic PatchTrace walkthrough; not output from Ghidriff or a real model',
    }


def create_sample(root: Path):
    from .evidence import build_context
    from .service import ProjectService
    root = Path(root)
    with tempfile.TemporaryDirectory(prefix='patchtrace-sample-') as temporary:
        inputs = Path(temporary)
        older, newer = inputs / 'older_sample.dll', inputs / 'newer_sample.dll'
        older.write_bytes(synthetic_pe(0))
        newer.write_bytes(synthetic_pe(1))
        service = ProjectService.create(older, newer, 'Synthetic bounds-check walkthrough', root)
        try:
            raw = inputs / 'sample.ghidriff.json'
            raw.write_text(json.dumps(sample_diff(service.project), indent=2), encoding='utf-8')
            service.apply_analysis(raw, AnalysisRun(status='completed', backend='synthetic-sample',
                                                    backend_version='1', settings={'synthetic': True}))
            candidate = service.project.model_copy(deep=True)
            candidate.sample = True
            service._commit(candidate)
            selected = next(match for match in service.project.matches
                            if match.category == 'modified' and match.newer[0].name == 'read_item')
            context = build_context(service.project, [selected.id])
            old_ref = next(ref.id for ref in context.evidence if ref.side == 'older')
            new_ref = next(ref.id for ref in context.evidence if ref.side == 'newer')
            finding = Finding(context_id=context.id, match_ids=[selected.id],
                              summary='Synthetic example: guard added before indexed buffer access',
                              fix_purpose='Return an error for a null buffer or index outside the supplied length',
                              category='ordinary-bug',
                              hypothesis=Hypothesis(
                                  explanation='The sample now checks the pointer and index before dereferencing the buffer.',
                                  supporting=[old_ref, new_ref], confidence='medium',
                                  preconditions=['The supplied length accurately describes the readable buffer.'],
                                  unknowns=['Caller validation and actual shipped machine code are outside this synthetic example.'],
                                  verification=['Review callers and test null, empty, boundary and out-of-range inputs.']),
                              alternatives=[Hypothesis(
                                  explanation='Caller validation may already have prevented invalid access.',
                                  contradicting=[old_ref], confidence='unknown',
                                  unknowns=['No caller implementation was provided.'])])
            service.add_interpretation(InterpretationRun(context=context, provider='curated synthetic sample',
                                                       model='no model invoked', status='completed',
                                                       findings=[finding], raw_response='Synthetic walkthrough record'))
            service.annotate(selected.id,
                             'Synthetic sample only. PE fixtures, decompilation and finding are authored examples; '
                             'no backend or model was run, and no vulnerability is established.')
            return service
        except Exception:
            service.close()
            raise
