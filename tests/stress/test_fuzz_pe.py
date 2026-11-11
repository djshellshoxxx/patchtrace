"""QA-FUZZ: PE overview on mutated, truncated and random images built by the synthetic PE builder in tests/.

Properties: inspect_pe never raises for malformed content; the result is a typed PeOverview; every string in the
result is free of control, format and surrogate characters (the shared hostile-text rule); cancellation is honoured
without a crash. Images are written to temporary files and parsed only; nothing is executed.
"""
from __future__ import annotations

import dataclasses
import tempfile
import unicodedata
from pathlib import Path

from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pe_builder import CODE, DATA, PeSpec, SectionSpec, build_pe

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.pe_overview import inspect_pe
from patchtrace.pe_overview.models import PeOverview

SETTINGS = settings(max_examples=120, deadline=None, database=None, suppress_health_check=[HealthCheck.too_slow])
HOSTILE = frozenset({'Cc', 'Cf', 'Cs'})


@st.composite
def built_images(draw):
    spec = PeSpec(
        pe32plus=draw(st.booleans()),
        kind=draw(st.sampled_from(['exe', 'dll', 'sys'])),
        sections=[SectionSpec(name='.text', data=draw(st.binary(max_size=512)), characteristics=CODE),
                  SectionSpec(name='.data', data=draw(st.binary(max_size=256)), characteristics=DATA)],
        imports={'KERNEL32.dll': ['ExitProcess', 'GetProcAddress']} if draw(st.booleans()) else {},
        overlay=draw(st.binary(max_size=64)),
    )
    raw = bytearray(build_pe(spec))
    for _ in range(draw(st.integers(0, 8))):
        raw[draw(st.integers(0, len(raw) - 1))] = draw(st.integers(0, 255))
    cut = draw(st.one_of(st.none(), st.integers(0, len(raw))))
    return bytes(raw if cut is None else raw[:cut])


@st.composite
def mz_prefixed_noise(draw):
    head = bytearray(b'MZ' + bytes(58))
    head[0x3C:0x40] = draw(st.integers(0, 2**32 - 1)).to_bytes(4, 'little')
    return bytes(head) + draw(st.binary(max_size=2048))


def _leaves(value):
    if isinstance(value, str):
        yield value
    elif dataclasses.is_dataclass(value) and not isinstance(value, type):
        for field in dataclasses.fields(value):
            yield from _leaves(getattr(value, field.name))
    elif isinstance(value, (list, tuple)):
        for item in value:
            yield from _leaves(item)
    elif isinstance(value, dict):
        for key, item in value.items():
            yield from _leaves(key)
            yield from _leaves(item)


def _inspect(raw: bytes) -> PeOverview:
    with tempfile.TemporaryDirectory() as root:
        path = Path(root) / 'image.bin'
        path.write_bytes(raw)
        with VerifiedArtifactReader.open_path(path) as reader:
            return inspect_pe(reader)


@SETTINGS
@given(built_images())
def test_inspect_pe_result_is_typed_for_mutated_builder_images(raw):
    overview = _inspect(raw)
    assert isinstance(overview, PeOverview)
    assert overview.size == len(raw)


@SETTINGS
@given(mz_prefixed_noise())
def test_inspect_pe_result_is_typed_for_mz_prefixed_noise(raw):
    overview = _inspect(raw)
    assert isinstance(overview, PeOverview)


@SETTINGS
@given(st.one_of(built_images(), mz_prefixed_noise(), st.binary(max_size=1024)))
def test_inspect_pe_output_strings_obey_the_hostile_text_rule(raw):
    overview = _inspect(raw)
    assert any(len(text) == 64 for text in _leaves(overview))  # the SHA-256 is always present
    for text in _leaves(overview):
        for char in text:
            assert unicodedata.category(char) not in HOSTILE, f'hostile character {char!r} in PE output'


@SETTINGS
@given(st.integers(0, 1023), st.binary(min_size=1, max_size=32))
def test_inspect_pe_handles_header_window_overwrites(offset, patch):
    raw = bytearray(build_pe(PeSpec(sections=[SectionSpec(data=b'\x90' * 128)])))
    start = offset % len(raw)
    raw[start:start + len(patch)] = patch[:len(raw) - start]
    assert isinstance(_inspect(bytes(raw)), PeOverview)


@SETTINGS
@given(st.sampled_from([b'\x01', b'\x7f', b'\x9b', b'\xad', b'\x00']), st.integers(0, 7))
def test_hostile_section_name_bytes_are_replaced_in_the_output(byte, position):
    raw = bytearray(build_pe(PeSpec(sections=[SectionSpec(name='.text', data=b'\x90' * 64)])))
    at = raw.index(b'.text')
    raw[at + position:at + position + 1] = byte
    overview = _inspect(bytes(raw))
    for text in _leaves(overview):
        assert all(unicodedata.category(c) not in HOSTILE for c in text)


def test_inspect_pe_reports_a_truncated_image_without_raising():
    full = build_pe(PeSpec(sections=[SectionSpec(data=b'\x90' * 256)]))
    for cut in range(0, len(full), 37):
        assert isinstance(_inspect(full[:cut]), PeOverview)
