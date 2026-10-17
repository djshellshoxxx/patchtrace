"""Compile and checksum the self-contained Windows Setup executable."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path

NSIS_VERSION = "3.13"


def find_compiler() -> Path:
    """Locate the pinned NSIS compiler without downloading build tools."""
    override = os.environ.get("NSIS_COMPILER")
    if override:
        path = Path(override)
        if path.is_file():
            return path
        raise FileNotFoundError(f"NSIS_COMPILER does not point to a file: {path}")

    on_path = shutil.which("makensis.exe") or shutil.which("makensis")
    if on_path:
        return Path(on_path)

    root = Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)"))
    candidate = root / "NSIS" / "makensis.exe"
    if candidate.is_file():
        return candidate
    raise FileNotFoundError(
        f"NSIS {NSIS_VERSION} is required. Install the pinned compiler or set NSIS_COMPILER."
    )


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def main() -> int:
    if sys.platform != "win32":
        raise SystemExit("The Windows installer must be built on Windows.")
    root = Path(__file__).resolve().parents[1]
    bundle = root / "dist" / "PatchTrace"
    executable = bundle / "PatchTrace.exe"
    if not executable.is_file():
        raise FileNotFoundError(f"Frozen application is missing: {executable}")
    if not any(bundle.rglob("Qt6Core.dll")):
        raise FileNotFoundError("Frozen bundle is missing Qt6Core.dll.")
    if not any(bundle.rglob("qwindows.dll")):
        raise FileNotFoundError("Frozen bundle is missing the Qt Windows platform plugin.")

    compiler = find_compiler()
    version = subprocess.run(
        [str(compiler), "-VERSION"], check=True, capture_output=True, text=True
    ).stdout.strip().lstrip("v")
    if version != NSIS_VERSION:
        raise RuntimeError(f"Expected NSIS {NSIS_VERSION}, found {version or 'unknown'}.")

    with (root / "pyproject.toml").open("rb") as stream:
        app_version = tomllib.load(stream)["project"]["version"]
    script = root / "installer" / "PatchTrace.nsi"
    subprocess.run(
        [str(compiler), f"/DAPP_VERSION={app_version}", str(script)],
        cwd=root,
        check=True,
    )

    installer = root / "dist" / "PatchTrace-Windows-x64-Setup.exe"
    if not installer.is_file() or installer.stat().st_size == 0:
        raise RuntimeError(f"NSIS did not produce a valid installer: {installer}")
    checksum = installer.with_name(installer.name + ".sha256")
    checksum.write_text(f"{sha256(installer)}  {installer.name}\n", encoding="ascii")
    print(f"NSIS {NSIS_VERSION} installer: {installer}")
    print(f"SHA-256: {sha256(installer)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
