"""Native-workflow archive contract and exact PowerShell step on authored ZIPs.

No Ghidra, Ghidriff or target executes here. Actions cache save/restore and all
five native outcomes still require source-specific hosted qualification.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/live-backend.yml"
CACHE_ACTION = "actions/cache@0057852bfaa89a56745cba8c7296529d2fc39830"
DIGEST = "c3b458661d69e26e203d739c0c82d143cc8a4a29d9e571f099c2cf4bda62a120"
VARIANTS = [
    "repro-plain-ghidriff", "patchtrace-clean", "patchtrace-seeded-store",
    "patchtrace-seeded-store-no-adjacent-pdb", "raw-cache-hit",
]


def workflow() -> dict:
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def archive_step() -> dict:
    steps = workflow()["jobs"]["native"]["steps"]
    matches = [step for step in steps if "Expand-Archive" in step.get("run", "")]
    assert len(matches) == 1, "exactly one Ghidra archive provisioning step is required"
    return matches[0]


def test_native_workflow_reuses_the_original_archive_cache_and_existing_pins():
    doc = workflow()
    steps = doc["jobs"]["native"]["steps"]
    restores = [step for step in steps if step.get("uses", "").startswith("actions/cache@")]
    assert len(restores) == 1, "retain the pinned original ZIP for the next native run"
    corpus = yaml.safe_load((ROOT / ".github/workflows/corpus-tier-r.yml").read_text(encoding="utf-8"))
    assert doc.get("env", {}).get("GHIDRA_SHA256") == DIGEST
    assert doc["env"]["GHIDRA_SHA256"] == corpus["env"]["GHIDRA_SHA256"]
    assert doc["env"]["GHIDRA_URL"] == corpus["env"]["GHIDRA_URL"]
    restore = restores[0]
    assert restore["uses"] == CACHE_ACTION
    assert restore["with"] == {
        "path": "ghidra-archive",
        "key": "ghidra-archive-v1-${{ env.GHIDRA_SHA256 }}",
    }
    install = archive_step()
    assert steps.index(restore) < steps.index(install)
    assert all("if" not in step and "continue-on-error" not in step for step in (restore, install))
    assert install["shell"] == "pwsh"
    assert "cache-hit" not in install["run"]


def test_actual_step_verifies_one_archive_before_removing_the_extracted_tree():
    script = archive_step()["run"]
    assert "Remove-Item -LiteralPath ghidra-runtime -Recurse -Force" in script, "fresh extraction is required"
    required_in_order = [
        "$ErrorActionPreference = 'Stop'",
        "$env:GHIDRA_SHA256 -cnotmatch '^[0-9a-f]{64}$'",
        "$archive = 'ghidra-archive/ghidra.zip'",
        "if (-not (Test-Path -LiteralPath $archive -PathType Leaf))",
        "Invoke-WebRequest $env:GHIDRA_URL -OutFile $archive",
        "Get-FileHash -LiteralPath $archive -Algorithm SHA256",
        "throw 'Ghidra archive digest mismatch'",
        "Remove-Item -LiteralPath ghidra-runtime -Recurse -Force",
        "Expand-Archive -LiteralPath $archive -DestinationPath ghidra-runtime",
        '"GHIDRA_INSTALL_DIR=$ghidra"',
    ]
    positions = []
    for fragment in required_in_order:
        assert script.count(fragment) == 1, fragment
        positions.append(script.index(fragment))
    assert positions == sorted(positions), "verification must precede fresh extraction"
    assert ".Hash.ToLowerInvariant() -ne $env:GHIDRA_SHA256" in script
    assert "throw 'Missing or malformed pinned Ghidra SHA-256'" in script
    assert "Verified Ghidra archive SHA-256:" in script


def test_restored_archive_is_not_overwritten_by_an_unconditional_download():
    script = archive_step()["run"]
    conditional_download = """if (-not (Test-Path -LiteralPath $archive -PathType Leaf)) {
  Invoke-WebRequest $env:GHIDRA_URL -OutFile $archive
}"""
    assert conditional_download in script
    assert script.count("Invoke-WebRequest") == 1


def test_archive_reuse_preserves_native_cases_and_required_acceptance():
    doc = workflow()
    job = doc["jobs"]["native"]
    assert job["strategy"] == {"fail-fast": False, "matrix": {"variant": VARIANTS}}
    assert job["runs-on"] == "windows-latest" and job["timeout-minutes"] == 25
    assert "if" not in job and "continue-on-error" not in job
    assert doc["permissions"] == {"contents": "read"}
    steps = job["steps"]
    assert all("continue-on-error" not in step for step in steps)
    install = archive_step()
    pip = next(step for step in steps if step.get("run", "").startswith("python -m pip install"))
    assert pip["run"] == (
        "python -m pip install -e . 'ghidriff @ "
        "git+https://github.com/clearbluejar/ghidriff.git@4f5d895fcbb1eacd65efd81145922c15bb7e741d'"
    )
    assert steps.index(install) < steps.index(pip)
    native = next(step for step in steps if step.get("run") == "python tools/live_backend_check.py")
    assert native["if"] == "matrix.variant != 'repro-plain-ghidriff' && matrix.variant != 'raw-cache-hit'"
    raw = next(step for step in steps if step.get("if") == "matrix.variant == 'raw-cache-hit'")
    assert raw["run"] == "python tools/live_cache_check.py --diagnostics-dir live-cache-diagnostics"
    repro = next(step for step in steps if step.get("if") == "matrix.variant == 'repro-plain-ghidriff'")
    assert "python -m ghidriff" in repro["run"] and "--no-symbols" in repro["run"]
    assert "$code -eq 0 -or -not" in repro["run"]
    assert "symbol is already downloaded" in repro["run"]
    assert 'throw "Native reproduction of cached-PDB failure did not occur' in repro["run"]


@pytest.fixture
def powershell() -> str:
    executable = shutil.which("pwsh")
    if executable is None:
        if sys.platform == "win32":
            pytest.fail("Windows QA requires PowerShell to exercise the actual Ghidra archive step")
        pytest.skip("PowerShell unavailable; exact archive-step fixtures require pwsh")
    return executable


def make_archive(root: Path) -> tuple[Path, str]:
    source = root / "authored-fixture.zip"
    with zipfile.ZipFile(source, "w") as archive:
        archive.writestr("ghidra_fixture/README.txt", "Authored archive fixture; no executable contents.\n")
    return source, hashlib.sha256(source.read_bytes()).hexdigest()


def run_archive_step(root: Path, powershell: str, source: Path, digest: str, *, download: bool):
    # Only the downloader is doubled; hashing, removal, extraction and export
    # run from the unchanged YAML scalar. No cache Action or native tool runs.
    prelude = """function Invoke-WebRequest {
    param([string]$Uri, [string]$OutFile)
    if ($env:PT_FIXTURE_DOWNLOAD -ne '1') { throw 'Unexpected fixture download' }
    if ($Uri -ne 'https://example.invalid/ghidra-fixture.zip') { throw 'Unexpected fixture URL' }
    Add-Content -LiteralPath $env:PT_FIXTURE_DOWNLOAD_LOG -Value 'download'
    Copy-Item -LiteralPath $env:PT_FIXTURE_ZIP -Destination $OutFile
}
"""
    script = root / "archive-fixture.ps1"
    script.write_text(prelude + archive_step()["run"], encoding="utf-8")
    env = {
        **os.environ,
        "GHIDRA_URL": "https://example.invalid/ghidra-fixture.zip",
        "GHIDRA_SHA256": digest,
        "GITHUB_ENV": str(root / "github-env"),
        "PT_FIXTURE_ZIP": str(source),
        "PT_FIXTURE_DOWNLOAD": "1" if download else "0",
        "PT_FIXTURE_DOWNLOAD_LOG": str(root / "downloads.txt"),
    }
    return subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-File", str(script)],
        cwd=root, env=env, text=True, encoding="utf-8", errors="replace",
        capture_output=True, timeout=30, check=False,
    )


@pytest.mark.parametrize("restored", (False, True), ids=("missing-archive", "restored-archive"))
@pytest.mark.parametrize("corrupt", (False, True), ids=("matching-bytes", "changed-bytes"))
def test_exact_step_verifies_downloaded_and_restored_zip_before_fresh_extraction(
    tmp_path, powershell, restored, corrupt
):
    source, digest = make_archive(tmp_path)
    if corrupt:
        source.write_bytes(source.read_bytes() + b"changed archive bytes")
    cached = tmp_path / "ghidra-archive" / "ghidra.zip"
    if restored:
        cached.parent.mkdir()
        shutil.copyfile(source, cached)
    extracted = tmp_path / "ghidra-runtime"
    extracted.mkdir()
    sentinel = extracted / "stale.txt"
    sentinel.write_text("prior extraction must survive verification failure", encoding="utf-8")
    result = run_archive_step(tmp_path, powershell, source, digest, download=not restored)
    assert cached.read_bytes() == source.read_bytes(), "retain the original archive, including failed evidence"
    downloads = tmp_path / "downloads.txt"
    assert downloads.exists() is not restored
    if not restored:
        assert downloads.read_text(encoding="utf-8-sig").splitlines() == ["download"]
    if corrupt:
        assert result.returncode != 0
        assert "Ghidra archive digest mismatch" in result.stderr
        assert sentinel.is_file()
        assert not (tmp_path / "github-env").exists()
        assert not (extracted / "ghidra_fixture").exists()
    else:
        assert result.returncode == 0, result.stdout + result.stderr
        assert "Verified Ghidra archive SHA-256:" in result.stdout and digest in result.stdout
        assert not sentinel.exists()
        assert (extracted / "ghidra_fixture" / "README.txt").is_file()
        assert (tmp_path / "github-env").read_text(encoding="utf-8-sig").strip() == (
            f"GHIDRA_INSTALL_DIR={extracted / 'ghidra_fixture'}"
        )


@pytest.mark.parametrize("digest", ("", "a" * 63, "A" * 64, "not-a-sha256"))
def test_exact_step_rejects_missing_or_malformed_pin_before_download(tmp_path, powershell, digest):
    source, _ = make_archive(tmp_path)
    result = run_archive_step(tmp_path, powershell, source, digest, download=True)
    assert result.returncode != 0
    assert "Missing or malformed pinned Ghidra SHA-256" in result.stderr
    assert not (tmp_path / "downloads.txt").exists()
    assert not (tmp_path / "ghidra-runtime").exists()
    assert not (tmp_path / "github-env").exists()


def test_exact_step_stops_on_extraction_error_without_exporting_a_runtime(tmp_path, powershell):
    source = tmp_path / "authored-fixture.zip"
    source.write_bytes(b"Inert bytes with a matching digest, but not a ZIP.")
    digest = hashlib.sha256(source.read_bytes()).hexdigest()
    result = run_archive_step(tmp_path, powershell, source, digest, download=True)
    assert result.returncode != 0
    assert "Verified Ghidra archive SHA-256:" in result.stdout
    assert not (tmp_path / "github-env").exists()
