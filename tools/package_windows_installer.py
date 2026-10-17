"""Compile the per-user Inno Setup installer around the tested onedir bundle."""
from __future__ import annotations

import hashlib
import os
import shutil
import subprocess
import sys
import tomllib
from pathlib import Path


def find_compiler() -> Path:
    """Find an installed Inno Setup compiler without downloading tools at build time."""
    override = os.environ.get("INNO_SETUP_COMPILER")
    if override:
        path = Path(override)
        if path.is_file():
            return path
        raise FileNotFoundError(f"INNO_SETUP_COMPILER does not point to a file: {path}")

    on_path = shutil.which("ISCC.exe") or shutil.which("ISCC")
    if on_path:
        return Path(on_path)

    roots = [
        Path(os.environ.get("ProgramFiles(x86)", r"C:\Program Files (x86)")),
        Path(os.environ.get("ProgramFiles", r"C:\Program Files")),
    ]
    candidates = [
        root / folder / "ISCC.exe"
        for root in roots
        for folder in ("Inno Setup 7", "Inno Setup 6")
    ]
    for candidate in candidates:
        if candidate.is_file():
            return candidate
    raise FileNotFoundError(
        "Inno Setup 6 or 7 is required to build the installer. "
        "Install it on the build machine or set INNO_SETUP_COMPILER."
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

    with (root / "pyproject.toml").open("rb") as stream:
        version = tomllib.load(stream)["project"]["version"]
    script = root / "installer" / "PatchTrace.iss"
    compiler = find_compiler()
    subprocess.run(
        [str(compiler), f"/DAppVersion={version}", str(script)],
        cwd=root,
        check=True,
    )

    installer = root / "dist" / "PatchTrace-Windows-x64-Setup.exe"
    if not installer.is_file() or installer.stat().st_size == 0:
        raise RuntimeError(f"Inno Setup did not produce a valid installer: {installer}")
    checksum = installer.with_name(installer.name + ".sha256")
    checksum.write_text(f"{sha256(installer)}  {installer.name}\n", encoding="ascii")
    print(f"Installer: {installer}")
    print(f"SHA-256: {sha256(installer)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
