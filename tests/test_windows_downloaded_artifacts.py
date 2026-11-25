"""Windows project preflight, downloaded-package job contract and exact artifact checksum step.

These fixtures never extract or execute their artifact bytes. Native portable/installer
acceptance belongs to the separate hosted Windows job, not these source/fixture checks.
"""
from __future__ import annotations

import hashlib
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github" / "workflows" / "qa-windows.yml"
ARTIFACTS = ("PatchTrace-0.1.0-windows-x64.zip", "PatchTrace-Windows-x64-Setup.exe")
MEMBERS = tuple(member for name in ARTIFACTS for member in (name, name + ".sha256"))


def test_windows_project_preflight_runs_before_full_qa_and_reports_skips():
    steps = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]["qa"]["steps"]
    report = "windows-project-results.xml"
    full = next(i for i, step in enumerate(steps) if "--junitxml=qa-results.xml" in step.get("run", ""))
    early = [step for step in steps[:full] if f"--junitxml={report}" in step.get("run", "").split()]
    assert len(early) == 1, "Missing focused Windows project results before full QA"
    preflight = early[0]
    assert preflight["if"] == "runner.os == 'Windows'"
    assert not preflight.get("continue-on-error", False)
    assert "PATCHTRACE_REQUIRE_WINDOWS_SMB" not in preflight.get("env", {})
    assert {"-rs", "tests/test_creation_schema_refusal.py", "tests/test_creation_replacement_refusal.py",
            "tests/test_gui_creation_retry.py", "tests/test_project_creation_stat_views.py",
            "tests/test_windows_project_smb.py"} <= set(preflight["run"].split())
    upload = next(step for step in steps if step.get("with", {}).get("name") == "qa-${{ runner.os }}")
    assert upload["if"] == "always()"
    assert report in upload["with"]["path"].splitlines()


def validation_job() -> dict:
    jobs = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))["jobs"]
    assert "windows-validate" in jobs, "Downloaded Windows artifact acceptance is missing"
    return jobs["windows-validate"]


def test_downloaded_artifact_job_uses_a_fresh_windows_runner_and_this_runs_bytes():
    job = validation_job()
    assert job["needs"] == "qa"
    assert job["runs-on"] == "windows-latest"
    assert job["timeout-minutes"] == 45
    assert "if" not in job and "continue-on-error" not in job
    steps = job["steps"]
    # A same-run named download follows checkout; no setup/build/install Action is added.
    assert len(steps) == 5
    assert steps[0] == {
        "uses": "actions/checkout@11d5960a326750d5838078e36cf38b85af677262",
        "with": {"persist-credentials": False},
    }
    assert steps[1] == {
        "uses": "actions/download-artifact@d3f86a106a0bac45b974a628896c90dbdf5c8093",
        "with": {"name": "PatchTrace-windows-x64", "path": "dist"},
    }


def test_both_downloaded_checksums_precede_required_portable_and_installer_smokes():
    steps = validation_job()["steps"]
    assert steps[2]["id"] == "verify-artifacts"
    assert all(step["shell"] == "pwsh" for step in steps[2:])
    assert all("if" not in step and "continue-on-error" not in step for step in steps)
    assert steps[3]["run"] == f"./tools/test_windows_portable.ps1 -Archive dist/{ARTIFACTS[0]}"
    assert steps[4]["run"] == f"./tools/test_windows_installer.ps1 -Installer dist/{ARTIFACTS[1]}"
    verifier = steps[2]["run"]
    assert all(name in verifier for name in ARTIFACTS)
    assert "Get-FileHash -LiteralPath" in verifier and "-Algorithm SHA256" in verifier
    assert "Start-Process" not in verifier and "Expand-Archive" not in verifier
    assert "pip install" not in verifier and "choco install" not in verifier


@pytest.fixture
def powershell() -> str:
    executable = shutil.which("pwsh")
    if executable is None:
        if sys.platform == "win32":
            pytest.fail("Windows QA requires PowerShell to exercise the actual artifact verifier")
        pytest.skip("PowerShell unavailable; exact checksum-step fixtures require pwsh")
    return executable


def make_artifacts(root: Path, *, mode=" ", newline="\n", uppercase=False) -> None:
    dist = root / "dist"
    dist.mkdir()
    for name in ARTIFACTS:
        content = ("Inert authored checksum fixture for " + name).encode("ascii")
        (dist / name).write_bytes(content)
        digest = hashlib.sha256(content).hexdigest()
        if uppercase:
            digest = digest.upper()
        (dist / (name + ".sha256")).write_bytes(f"{digest} {mode}{name}{newline}".encode("ascii"))


def run_verifier(root: Path, powershell: str) -> subprocess.CompletedProcess[str]:
    # Execute only the tracked verification step, never either package smoke command.
    script = next(step["run"] for step in validation_job()["steps"] if step.get("id") == "verify-artifacts")
    path = root / "verify-fixture.ps1"
    path.write_text(script, encoding="utf-8")
    return subprocess.run(
        [powershell, "-NoProfile", "-NonInteractive", "-File", str(path)],
        cwd=root, text=True, encoding="utf-8", errors="replace", capture_output=True,
        timeout=30, check=False,
    )


@pytest.mark.parametrize("mode,newline,uppercase", [(" ", "\n", False), ("*", "\r\n", True), (" ", "", False)])
def test_exact_checksum_step_accepts_both_valid_artifacts(tmp_path, powershell, mode, newline, uppercase):
    make_artifacts(tmp_path, mode=mode, newline=newline, uppercase=uppercase)
    result = run_verifier(tmp_path, powershell)
    assert result.returncode == 0, result.stdout + result.stderr
    assert result.stdout.count("Verified downloaded artifact SHA-256:") == 2
    assert all(name in result.stdout for name in ARTIFACTS)


@pytest.mark.parametrize("member", MEMBERS)
def test_exact_checksum_step_rejects_each_missing_member(tmp_path, powershell, member):
    make_artifacts(tmp_path)
    (tmp_path / "dist" / member).unlink()
    result = run_verifier(tmp_path, powershell)
    assert result.returncode != 0
    assert "Missing downloaded artifact member:" in result.stderr
    assert member in result.stderr


@pytest.mark.parametrize("name", ARTIFACTS)
def test_exact_checksum_step_rejects_modified_artifact_bytes(tmp_path, powershell, name):
    make_artifacts(tmp_path)
    (tmp_path / "dist" / name).write_bytes(b"Changed inert fixture")
    result = run_verifier(tmp_path, powershell)
    assert result.returncode != 0
    assert "Downloaded artifact SHA-256 mismatch:" in result.stderr
    assert name in result.stderr


@pytest.mark.parametrize("replacement", [ARTIFACTS[1], ARTIFACTS[0].lower()])
def test_exact_checksum_step_binds_the_record_to_the_executed_filename(tmp_path, powershell, replacement):
    make_artifacts(tmp_path)
    sidecar = tmp_path / "dist" / (ARTIFACTS[0] + ".sha256")
    sidecar.write_text(sidecar.read_text().replace(ARTIFACTS[0], replacement), encoding="ascii")
    result = run_verifier(tmp_path, powershell)
    assert result.returncode != 0
    assert "Invalid downloaded artifact SHA-256 sidecar:" in result.stderr


@pytest.mark.parametrize("record", [
    "", "not-a-digest  {name}\n", "{digest}  {name}\n{digest}  {name}\n",
    "{digest}  {name}\n\n", "{digest}  {name}\r", "{digest} {name}\n",
])
def test_exact_checksum_step_rejects_malformed_sidecars(tmp_path, powershell, record):
    make_artifacts(tmp_path)
    artifact = tmp_path / "dist" / ARTIFACTS[0]
    digest = hashlib.sha256(artifact.read_bytes()).hexdigest()
    artifact.with_name(artifact.name + ".sha256").write_bytes(record.format(digest=digest, name=artifact.name).encode())
    result = run_verifier(tmp_path, powershell)
    assert result.returncode != 0
    assert "Invalid downloaded artifact SHA-256 sidecar:" in result.stderr
