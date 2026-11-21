"""Fixture-only execution of Tier R archive verification shell blocks.

These tests run the workflow's real Bash archive steps against tiny authored
tar.xz/ZIP files. They never fetch or execute rizin, Ghidra, or target binaries.
The Ghidriff pip-install line is replaced for this hermetic archive test only.
"""
from __future__ import annotations

import hashlib
import io
import os
import shutil
import subprocess
import tarfile
import textwrap
import zipfile
from pathlib import Path

import pytest

WORKFLOW = Path(__file__).resolve().parents[1] / ".github/workflows/corpus-tier-r.yml"
REQUIRED_TOOLS = ("bash", "sha256sum", "tar", "unzip")
pytestmark = pytest.mark.skipif(
    os.name == "nt" or any(shutil.which(tool) is None for tool in REQUIRED_TOOLS),
    reason="requires host Bash, sha256sum, tar and unzip",
)


def _shell_step(source: str, name: str) -> str:
    heading = f"      - name: {name}\n"
    assert source.count(heading) == 1, name
    part = source.split(heading, 1)[1].split("\n      - ", 1)[0]
    assert "        run: |\n" in part, name
    body = part.split("        run: |\n", 1)[1]
    return textwrap.dedent(body).strip() + "\n"


def _archive(root: Path, engine: str) -> tuple[Path, str]:
    if engine == "rizin":
        archive = root / "rizin-archive" / "fixture.tar.xz"
        archive.parent.mkdir(parents=True)
        with tarfile.open(archive, "w:xz") as handle:
            payload = b"authored fixture; do not execute\n"
            info = tarfile.TarInfo("bin/rz-diff")
            info.size = len(payload)
            handle.addfile(info, io.BytesIO(payload))
    else:
        archive = root / "ghidra-archive" / "ghidra.zip"
        archive.parent.mkdir(parents=True)
        with zipfile.ZipFile(archive, "w") as handle:
            handle.writestr("ghidra_fixture/README.txt", "authored fixture\n")
    return archive, hashlib.sha256(archive.read_bytes()).hexdigest()


@pytest.mark.parametrize("engine", ("rizin", "ghidra"))
@pytest.mark.parametrize("corrupt", (False, True), ids=("verified-cache-hit", "tampered-cache-hit"))
def test_actual_archive_step_verifies_cached_bytes_before_extraction(
    tmp_path: Path, engine: str, corrupt: bool
) -> None:
    source = WORKFLOW.read_text(encoding="utf-8")
    name = (
        "Install pinned rizin (fail closed on missing or mismatched SHA-256)"
        if engine == "rizin" else
        "Install Ghidra and Ghidriff (fail closed on digest mismatch)"
    )
    script = _shell_step(source, name)
    if engine == "ghidra":
        install = 'python -m pip install "$GHIDRIFF_PIN"'
        assert script.count(install) == 1
        script = script.replace(install, ': # no external Python install in archive fixture', 1)
    archive, digest = _archive(tmp_path, engine)
    extracted = tmp_path / ("rizin" if engine == "rizin" else "ghidra-runtime")
    extracted.mkdir()
    (extracted / "preexisting.txt").write_text("stale tree", encoding="utf-8")
    if corrupt:
        archive.write_bytes(archive.read_bytes() + b"tampering")
    fake_bin = tmp_path / "fake-bin"
    fake_bin.mkdir()
    curl = fake_bin / "curl"
    curl.write_text("#!/bin/sh\necho unexpected-network >&2\nexit 87\n", encoding="utf-8")
    curl.chmod(0o755)
    env = os.environ.copy()
    env.update({
        "PATH": str(fake_bin) + os.pathsep + env.get("PATH", ""),
        "RIZIN_ASSET": "fixture.tar.xz",
        "RIZIN_SHA256": digest,
        "GHIDRA_SHA256": digest,
        "GHIDRA_URL": "https://example.invalid/never-fetch",
        "GHIDRIFF_PIN": "fixture-only",
        "GITHUB_ENV": str(tmp_path / "github-env"),
    })
    result = subprocess.run(
        ["bash", "-e", "-c", script],
        cwd=tmp_path,
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )
    if corrupt:
        assert result.returncode != 0
        assert "FAILED" in result.stdout + result.stderr
        assert (extracted / "preexisting.txt").exists()
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert not (extracted / "preexisting.txt").exists()
        expected = (
            extracted / "bin" / "rz-diff"
            if engine == "rizin" else
            extracted / "ghidra_fixture" / "README.txt"
        )
        assert expected.is_file()
