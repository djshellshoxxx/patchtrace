# Offline backend ZIP: assembly, installation and acceptance

This is the implementation guide for [SPEC-06](specs/offline-backend-installer.md). **The installer is implemented to accept a prepared archive. No official fully tested offline backend archive is published yet.** The PyInstaller desktop ZIP by itself does not include Ghidra, Java or Ghidriff.

## End-user procedure (once an approved bundle exists)

1. On an Internet-connected machine, obtain the complete PatchTrace Windows desktop ZIP, the separately published offline backend ZIP, the publisher-provided ZIP SHA-256, and the software notices. Move the files to the target PC using removable media.
2. Launch `PatchTrace.exe`, open **Setup**, paste the trusted 64-character lowercase ZIP SHA-256 into **Trusted offline ZIP checksum**, then click **Install offline backend ZIP…** and select the archive on disk.
3. PatchTrace verifies the ZIP and every payload SHA-256 without executing its contents or contacting any site. Read the runtime identity, full archive hash and warning before confirming the install.
4. The files go to `%LOCALAPPDATA%\PatchTrace\runtimes\<runtime-id>\payload\`. Only a complete verified runtime becomes visible. Installed `python/python.exe`, `ghidra`, and `jdk` paths are filled into Setup after success.
5. Click **Diagnose dependencies**, then **Save setup**. Diagnose checks component metadata and Java presence; it does not prove the engines can successfully compare binaries. Run a known compatible binary pair and inspect the results.
6. The native backend uses the selected JDK through child-process `JAVA_HOME` and `PATH`, leaving system settings unchanged. Ghidriff symbol-server lookup remains disabled unless explicitly enabled by the analyst. Use operating-system firewall controls for a true air gap.

The imported archive is read-only; a failed or cancelled import leaves existing installations, analyst projects, and preferences intact. If antivirus or power loss strands a hidden staging directory, review and remove that specific directory manually after confirming no installer runs. A stale installation lock must likewise be reviewed, never stolen automatically. No runtime is automatically updated or overwritten.

**Security:** An archive's own file hashes detect corruption, but are not a digital signature. Check the full ZIP SHA-256 from an independent trusted source. Never import untrusted executables simply because the manifest validates.

## Maintainer: build an offline ZIP from a ready-to-run payload

Before packaging, assemble and verify a **relocatable** portable Windows x64 runtime in a staging directory:

```text
backend-payload/
  python/
    python.exe
    python312.dll
    python312._pth
    ... vendored, pinned compatible Ghidriff/pyghidra/JPype and dependencies ...
  ghidra/
    Ghidra/application.properties
    ... complete matching Ghidra release ...
  jdk/
    bin/java.exe
    ... complete matching JDK distribution ...
  LICENSES/
    NOTICE.txt
    ... complete applicable source/redistribution notices ...
```

The Python 3.12 Windows embeddable distribution explicitly does **not** support ordinary end-user pip management. Vendor complete compatible site packages into the portable Python runtime and correctly configure the `._pth` file before release. Do not copy a virtual environment and assume absolute paths can be relocated. Check required DLLs and Java/Ghidra plugin integration on a clean computer.

From a developer environment with PatchTrace installed in editable mode:

```powershell
python tools/make_offline_bundle.py `
  --payload "D:\backend-payload" `
  --out "D:\release\PatchTrace-Backend-windows-amd64.zip" `
  --runtime-id "ghidra-12.0.4-ghidriff-windows-amd64" `
  --python-version "3.12.10" `
  --ghidra-version "12.0.4" `
  --jdk-version "25" `
  --ghidriff-revision "4f5d895fcbb1eacd65efd81145922c15bb7e741d"
```

This producer creates the inventory/strict manifest, ZIP and a `.zip.sha256` checksum file. It does not fetch dependencies, install Python, run the payload, or assert license compatibility. Version arguments must be verified against the actual payload. The ZIP has a top-level `manifest.json` and every payload file below `payload/`; ZIP integrity and schema are checked again after assembly.

The official runtime must be built from pinned, auditable distributions and dependency wheels, with a full source/license notice inventory. The binary package release gate requires (1) isolated disconnected Windows install, (2) `python -m ghidriff --help`, (3) real Ghidra/JDK launch, (4) known-patch static diff and proper normalization, (5) no external network traffic, (6) hash/ZIP/license audit, (7) cancellation/partial-install recovery, and (8) successful Windows application QA and packaging. A synthetic ZIP test only verifies installer mechanics.

## Sources and constraints

- [Python 3.12 Windows embeddable distribution](https://docs.python.org/3.12/using/windows.html): pip not supported as ordinary runtime package management; installer must vendor extensions and manage runtime isolation.
- [Ghidriff source](https://github.com/clearbluejar/ghidriff): current CLI and license requirements; PatchTrace pins the inspected revision.
- [Ghidra](https://github.com/NationalSecurityAgency/ghidra): supported Java version and release assets; only a complete binary distribution is valid.
- [PyGhidra](https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/PyGhidra/src/main/py/README.md): offline package behavior is version-dependent.

Only publishing an actually verified portable runtime will allow users to skip all manual Python/JDK/Ghidra setup. Until then existing manual paths and runtime discovery remain supported.
