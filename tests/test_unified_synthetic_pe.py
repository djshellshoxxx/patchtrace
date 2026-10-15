"""Synthetic PE/assembler regression tests. UNVERIFIED: not executed; no target is ever loaded or run."""
from __future__ import annotations

import struct
from pathlib import Path

import pytest
from hypothesis import given, settings, strategies as st
from unified_support.assembler import Assembler
from unified_support.synthetic_pe import Function, Section, build_image

from patchtrace.artifact_bytes import VerifiedArtifactReader
from patchtrace.unified.ir.pe_tables import read_pe_tables


def test_labels_and_relative_targets_are_rebased() -> None:
    code = Assembler().mov("rax", 7).label("again").add("rax", 1).cmp("rax", 9)
    code.jcc("ne", "again").call("helper").lea("rdx", "again").ret()
    base = 0x1400
    raw = code.assemble(base, {"helper": 0x1800})
    assert raw[:10] == bytes.fromhex("48b80700000000000000")
    assert raw[10:17] == bytes.fromhex("4881c001000000")
    assert raw[17:24] == bytes.fromhex("4881f809000000")
    assert raw[24:26] == bytes.fromhex("0f85")
    assert 30 + struct.unpack_from("<i", raw, 26)[0] == 10
    assert base + 35 + struct.unpack_from("<i", raw, 31)[0] == 0x1800
    assert base + 42 + struct.unpack_from("<i", raw, 38)[0] == base + 10
    assert raw[-1:] == b"\xc3"


def test_assembler_refuses_ambiguity_and_invalid_encodings() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        Assembler().label("x").label("x")
    with pytest.raises(ValueError, match="unresolved"):
        Assembler().call("missing").assemble(0x1000)
    with pytest.raises(ValueError, match="register"):
        Assembler().mov("rsp", 1)
    with pytest.raises(ValueError, match="condition"):
        Assembler().jcc("invented", "x")
    with pytest.raises(ValueError, match="range"):
        Assembler().call("far").assemble(0, {"far": 2**40})


@settings(max_examples=24, derandomize=True, deadline=None)
@given(st.integers(min_value=0, max_value=2**32 - 1), st.integers(min_value=0, max_value=64))
def test_deterministic_image_and_real_pdata_parser(timestamp: int, padding: int, tmp_path: Path) -> None:
    # Hypothesis reuses tmp_path deliberately: a fixed file is replaced, never executed.
    fn = Function("entry", Assembler().mov("rax", 3).nop(padding).ret().assemble(0x1000))
    first = build_image((fn,), timestamp=timestamp)
    assert first == build_image((fn,), timestamp=timestamp)
    path = tmp_path / "synthetic.dll"
    path.write_bytes(first.data)
    with VerifiedArtifactReader.open_path(path) as reader:
        tables = read_pe_tables(reader)
        rva = dict(first.functions)["entry"]
        assert tables.extent(rva, [(rva, len(fn.body))]) == 1
        assert tables.is_executable(rva)
        assert tables.eh_for(rva) is not None
        assert tables.warnings == []


def test_export_targets_and_named_and_ordinal_imports() -> None:
    built = build_image(
        (Function("alpha", b"\xc3"), Function("omega", b"\x90\xc3")),
        imports=(("fixture.dll", ("DoThing", 7)),), exports=("omega", "alpha"),
        sections=(Section(".data", b"synthetic-data"),),
    )
    raw = built.data
    opt = struct.unpack_from("<I", raw, 0x3c)[0] + 24
    assert struct.unpack_from("<H", raw, opt)[0] == 0x20b
    export_rva, _ = struct.unpack_from("<II", raw, opt + 112)
    edata = built.offset(export_rva)
    nfunc, nname, eat = struct.unpack_from("<III", raw, edata + 20)
    assert nfunc == nname == 2
    assert struct.unpack_from("<II", raw, built.offset(eat)) == (
        dict(built.functions)["alpha"], dict(built.functions)["omega"])
    import_rva, _ = struct.unpack_from("<II", raw, opt + 120)
    desc = built.offset(import_rva)
    thunk, _, _, dll, iat = struct.unpack_from("<IIIII", raw, desc)
    assert thunk == iat
    assert raw[built.offset(dll):].startswith(b"fixture.dll\0")
    named, ordinal, terminal = struct.unpack_from("<QQQ", raw, built.offset(thunk))
    assert raw[built.offset(named) + 2:].startswith(b"DoThing\0")
    assert ordinal == 2**63 + 7 and terminal == 0


def test_switch_table_and_thunk_fixups() -> None:
    code = Assembler().switch("table").label("a").mov("rax", 1).ret()
    code.label("b").mov("rax", 2).ret().label("table").jump_table(("a", "b"))
    raw = code.assemble(0x1000)
    assert raw[:3] == bytes.fromhex("488d15")
    table = 7 + struct.unpack_from("<i", raw, 3)[0]
    assert table + struct.unpack_from("<i", raw, table)[0] == 16
    assert table + struct.unpack_from("<i", raw, table + 4)[0] == 27
    thunk = Assembler().thunk("target").assemble(0x2000, {"target": 0x1000})
    assert thunk[0] == 0xe9 and 0x2005 + struct.unpack_from("<i", thunk, 1)[0] == 0x1000


def test_invalid_layouts_are_rejected_before_emitting_bytes() -> None:
    with pytest.raises(ValueError, match="duplicate"):
        build_image((Function("f", b"\xc3"), Function("f", b"\xc3")))
    with pytest.raises(ValueError, match="export"):
        build_image((Function("f", b"\xc3"),), exports=("absent",))
    with pytest.raises(ValueError, match="section"):
        build_image((Function("f", b"\xc3"),), sections=(Section(".text", b"x"),))
