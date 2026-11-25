# Install

Choose the unsigned Windows x64 per-user installer or portable ZIP, or the Linux x86-64 portable archive. Each desktop package includes Python and Qt.

## Choose a package

| You want | Package | Status |
|---|---|---|
| Browse the sample, import diff files, review, export | Windows `PatchTrace-Windows-x64-Setup.exe`, portable ZIP `PatchTrace-Windows-x64-Portable.zip`, or Linux `PatchTrace-<version>-linux-x86_64.tar.gz` ("lite") | Published as prereleases on the GitHub Releases page |
| Run comparisons with nothing else to install | "Full" package `PatchTrace-<version>-windows-x64-full.zip` or `...-linux-x86_64-full.tar.gz` | Builder, workflow and acceptance tooling are merged. **No full package has been published or accepted yet** (see below) |
| Run comparisons with your own tools | Lite package plus external Ghidra, Java and Ghidriff | Works today |

The lite package includes Python and Qt. It does not include Ghidra, Java, Ghidriff or AI model weights. Without an analysis runtime the app still opens the sample and imports Ghidriff JSON.

## Windows

For the installer, download `PatchTrace-Windows-x64-Setup.exe` and its `.sha256` file from [Releases](https://github.com/djshellshoxxx/PatchTrace/releases). Verify the download using the commands below, run Setup under your own account, then launch **PatchTrace** from the Start menu. The installer uses the current user’s LocalAppData by default.

For the portable package:

1. Download the zip and its `.sha256` file from the Releases page, then verify it (below).
2. If Windows marked the zip as downloaded from the internet, right-click it, open Properties and tick **Unblock** before extracting, or run `Unblock-File` on it.
3. Extract the **whole** zip into a user-writable folder. Keep `PatchTrace.exe` and `_internal` together.
4. Run `PatchTrace.exe`. SmartScreen may warn because the package is unsigned.
5. Keep your projects outside the application folder so updates never touch them.

## Linux

```bash
tar xzf PatchTrace-0.1.0-linux-x86_64.tar.gz
./PatchTrace/PatchTrace
QT_QPA_PLATFORM=offscreen ./PatchTrace/PatchTrace --self-test   # headless smoke test
```

Qt needs host libraries that are not bundled. On Debian or Ubuntu: `libegl1 libgl1 libfontconfig1 libdbus-1-3 libxkbcommon0 libxkbcommon-x11-0 libxcb-cursor0 libxcb-icccm4 libxcb-image0 libxcb-keysyms1 libxcb-randr0 libxcb-render-util0 libxcb-shape0 libxcb-xinerama0 libxcb-xkb1 libxcb-xfixes0` (or a Wayland session). If startup aborts with `Could not load the Qt platform plugin "xcb"`, run `ldd PatchTrace/_internal/PySide6/Qt/lib/libQt6XcbQpa.so.6 | grep 'not found'`. Live Ghidriff analysis from the frozen Linux build is not yet verified.

## Verify a download

```powershell
$package = 'PatchTrace-Windows-x64-Setup.exe' # Or PatchTrace-Windows-x64-Portable.zip
Get-FileHash -LiteralPath $package -Algorithm SHA256
Get-Content -LiteralPath "$package.sha256"
```

```bash
sha256sum -c PatchTrace-0.1.0-linux-x86_64.tar.gz.sha256
```

The two hashes must match. A checksum published next to the file detects corruption. It does not prove who built it, because there is no code signature yet. For a stronger check, compare the hash with the one in the release notes or on a second channel.

## Bundled backend versus external tools

**Zero-download bundle (planned for release).** A full package adds a `backend/` folder holding a private Python 3.12, JDK 21, Ghidra 12.0.4 and the pinned Ghidriff build, all listed in `backend/manifest.json` with per-file SHA-256. The designed checks are:

```text
PatchTrace backend status    # fast file check, starts no process
PatchTrace backend verify    # check files against the manifest; --full hashes every file
PatchTrace backend selftest --older OLD.dll --newer NEW.dll --expect-function NAME
PatchTrace backend diagnose
```

These verbs are available in the CLI. The [backend pin file](../tools/backend_pin.json) records the component versions, digests and project distribution policy. A complete Windows runtime still needs an archive with a verified payload and a disconnected acceptance run for that archive. See the [backend bundle runbook](runbooks/backend-bundle.md).

**External tools (works today).** Follow [windows.md](windows.md): install a JDK that Ghidra supports, unpack Ghidra, create a Python 3.12 virtual environment and install the pinned Ghidriff revision. Then open **Setup**, use **Find existing installations**, set the backend Python and the Ghidra root, run **Diagnose dependencies**, and **Save setup**. The tested combination is Python 3.12.10, Ghidra 12.0.4, Temurin Java 25 and Ghidriff revision `4f5d895fcbb1eacd65efd81145922c15bb7e741d`. Other combinations may work but are not claimed.

**Offline backend ZIP.** **Setup > Install offline backend ZIP...** imports a prepared runtime archive. Paste the trusted ZIP SHA-256 first. PatchTrace verifies the inventory without running anything and installs under `%LOCALAPPDATA%\PatchTrace\runtimes\<runtime-id>\payload\` (Windows only). Failure or cancel leaves earlier installs untouched. See [offline-backend.md](offline-backend.md).

## Offline use

- Offline is the default. Opening projects, comparing with an installed backend, ranking, reading evidence and exporting need no network.
- The only things that touch the network are listed in [specs/network-egress-privacy.md](specs/network-egress-privacy.md), and each needs its own consent: Winbindex and Microsoft symbol-server downloads, CVE fetches (NVD, MSRC), CSAF fetch, and an AI provider you configure.
- Ghidriff symbol-server lookups are off by default.
- Ghidra and Java are separate programs. If you need a hard air gap, enforce it with operating-system firewall rules, not with PatchTrace settings.
- To work fully offline, move the package, its checksum and any backend ZIP by removable media, and use saved CVE snapshots (`correlate --snapshot`) and local CSAF files (`intelligence import`).

## Update

Unpack a new version into a separate folder. Projects and settings are not overwritten. Back up a project (**Project > Back up project...**) before opening it with a much newer version, since future schema migrations are possible.

## Uninstall

Remove a Setup installation in Windows **Settings > Apps > Installed apps**, or run `Uninstall.exe` in its application folder. For a portable installation, delete the extracted application folder. Keep projects in their own directories. The following paths identify project data and preferences:

| Item | Windows | Linux |
|---|---|---|
| Installed offline runtimes | `%LOCALAPPDATA%\PatchTrace\runtimes\` | `~/.local/share/patchtrace/runtimes/` by default for CLI installations |
| Settings (window, paths, preferences) | registry `HKCU\Software\PatchTrace\PatchTrace` | `~/.config/PatchTrace/PatchTrace.conf` |
| Analysis profiles | `%APPDATA%\PatchTrace\profiles\` | `$XDG_CONFIG_HOME/PatchTrace/profiles/` |
| KB and KEV stores | `%LOCALAPPDATA%\PatchTrace\kb`, `...\kev` | `~/.local/share/PatchTrace/` |
| Bundled-runtime scratch | `%LOCALAPPDATA%\PatchTrace\work` | `~/.local/state/patchtrace/work` |
| Your projects | wherever you created them | same |
| Derived-result cache | the directory you passed as `--cache-dir` | same |
