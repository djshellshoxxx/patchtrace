"""CODEX-6: source-level fail-closed archive cache contract; no network or tool launch."""
from __future__ import annotations

import re
from pathlib import Path

import pytest


WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/corpus-tier-r.yml"


def _step(source: str, name: str) -> str:
    """Read a named YAML list step, refusing duplicate or missing step headings."""
    marker = f"      - name: {name}\n"
    assert source.count(marker) == 1, f"missing or duplicate step: {name}"
    start = source.index(marker)
    next_step = source.find("\n      - ", start + len(marker))
    return source[start:] if next_step == -1 else source[start:next_step]


def admission_errors(source: str) -> list[str]:
    """Structural controls independent of actual runner/cache/network semantics."""
    errors = []
    for label, archive_dir, key, install, verifier, extractor in (
        ("rizin", "rizin-archive", "rizin-cache", "Install pinned rizin", "RIZIN_SHA256", "tar -xJf"),
        ("ghidra", "ghidra-archive", "ghidra-cache", "Install Ghidra and Ghidriff", "GHIDRA_SHA256", "unzip -q"),
    ):
        cache_name = "Restore pinned rizin" if label == "rizin" else "Restore Ghidra"
        try:
            restore = _step(source, cache_name)
            setup = _step(source, install if label == "rizin" else install + " (fail closed on digest mismatch)")
        except AssertionError:
            errors.append(f"{label}: missing or duplicate named step")
            continue
        if f"path: {archive_dir}" not in restore or f"key: {label}-" not in restore:
            errors.append(f"{label}: cache must contain only an archive")
        if f"steps.{key}.outputs.cache-hit" in setup or (label == "rizin" and re.search(
            r"^\s+if:\s*steps\.rizin-cache\.outputs\.cache-hit", setup, re.MULTILINE
        )):
            errors.append(f"{label}: restored content must be reverified")
        verified = f'${{{verifier}}}' in setup and "sha256sum -c -" in setup
        unpack = extractor in setup
        if not verified or not unpack:
            errors.append(f"{label}: pinned digest must precede extraction")
        elif setup.index("sha256sum -c -") > setup.index(extractor):
            errors.append(f"{label}: pinned digest must precede extraction")
        if label == "rizin":
            if "rm -rf rizin" not in setup or "rizin-archive/$RIZIN_ASSET" not in setup:
                errors.append("rizin: clean extraction and archive identity required")
        else:
            if "rm -rf ghidra-runtime" not in setup:
                errors.append("ghidra: clean extraction required")
            if not all(fragment in setup for fragment in (
                "if [ ! -f ghidra-archive/ghidra.zip ]; then",
                "curl -fsSL -o ghidra-archive/ghidra.zip",
                'echo "${GHIDRA_SHA256}  ghidra-archive/ghidra.zip" | sha256sum -c -',
                "unzip -q ghidra-archive/ghidra.zip -d ghidra-runtime",
            )):
                errors.append("ghidra: the same pinned archive must be downloaded, verified and extracted")
            if "contains(env.ENGINES, 'ghidriff')" not in setup:
                errors.append("ghidra: keep engine-conditional setup")
    return errors


def test_cached_tools_are_verified_archives_before_use():
    assert admission_errors(WORKFLOW.read_text(encoding="utf-8")) == []


@pytest.mark.parametrize(
    ("old", "new"),
    [
        ("path: rizin-archive", "path: rizin"),
        ("path: ghidra-archive", "path: ghidra-runtime"),
        ("sha256sum -c -", "true # no integrity check"),
        ("tar -xJf", "echo # skip extraction"),
        ("unzip -q", "echo # skip extraction"),
        ("rm -rf rizin", "echo skip-rizin-clean"),
        ("rm -rf ghidra-runtime", "echo skip-ghidra-clean"),
        ("rizin-archive/$RIZIN_ASSET", "rizin/$RIZIN_ASSET"),
        ("ghidra-archive/ghidra.zip", "ghidra-runtime/ghidra.zip"),
        ("contains(env.ENGINES, 'ghidriff')", "true"),
    ],
)
def test_regression_contract_detects_removed_integrity_boundary(old, new):
    original = WORKFLOW.read_text(encoding="utf-8")
    assert old in original
    mutated = original.replace(old, new) if old.startswith("contains(") else original.replace(old, new, 1)
    assert admission_errors(mutated), (old, new)
