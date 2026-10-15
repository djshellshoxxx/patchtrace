# First run

Two ways to get a first result without analysing anything real: the built-in sample (GUI) and the CLI on a project you already have. Both work offline.

## GUI walkthrough

1. Start PatchTrace (`PatchTrace.exe`, or `./PatchTrace/PatchTrace` on Linux). One main window opens: function matches on the left, paired older/newer code in the centre, findings and review on the right, job log below.
2. Click **Sample** and choose a parent folder. PatchTrace creates `patchtrace-sample-<timestamp>` there. The sample is an authored, synthetic bounds-check fix. No engine or model runs, and it does not represent a real binary.
3. Select the modified function in **FUNCTION MATCHES**. Read the old and new code and press **Alt+Down** for the next difference. Switch between Decompiled code, Assembly and Metadata. Unavailable views are labelled, never invented.
4. Select the finding on the right, read its unknowns and evidence, and click an evidence entry to jump to the code.
5. Add a note, set a review status, write your own conclusion, then **Save finding review**.
6. **Export** (Ctrl+E), look at the preview, write a Markdown, HTML or JSON report.
7. Close and reopen with **Open** (Ctrl+O) on the project folder.

### Your own pair

1. **New** (Ctrl+N). Name the project and pick the **Older PE x64** and **Newer PE x64** files yourself. Choose a new or empty project folder. Use **Swap older and newer** if they are reversed.
2. PatchTrace validates both files, hashes them and stores copies. The originals are not touched, and neither file is ever run or loaded as a driver.
3. To compare you need an analysis runtime: a full package, or the external setup in [install.md](install.md). Click **Setup**, check the paths, **Diagnose dependencies**, **Save setup**.
4. **Run comparison** (F5). **Cancel job** (Esc) is cooperative; wait for the terminal status.
5. **Analysis > Rank changes** (Ctrl+R) orders functions by attention score.
6. No runtime? Run Ghidriff elsewhere and use **Import JSON** on a project made from the exact same pair.

Other entry points: **File overview** gives a preliminary PE comparison (sections, headers, Authenticode probe, hex/binary/Base64 views) with no backend at all. **Project > Download from Microsoft symbol server...** fetches both builds after you approve the hosts shown. **Project > Series window...** compares 3 to 8 builds.

## CLI walkthrough

`python -m patchtrace` (or the packaged executable) with no arguments opens the desktop. With a verb it runs headless and loads no Qt. Verbs: `rank flags correlate cache acquire series secondary intelligence unified intel-tools backend panels`. Run `<verb> --help` for options (verbs with sub-commands, such as `backend status --help`, list them there).

```text
python -m patchtrace rank PROJECT_DIR --limit 20
python -m patchtrace rank PROJECT_DIR --json --dry-run
python -m patchtrace flags PROJECT_DIR
python -m patchtrace correlate PROJECT_DIR --cve CVE-2024-12345 --snapshot saved.json
python -m patchtrace backend status
python -m patchtrace cache status --cache-dir DIR
```

`--json` prints exactly one JSON document on stdout; diagnostics go to stderr. Exit codes: 0 success, 2 invalid arguments or environment, 3 runtime failure, 4 legitimate no result, 5 cancelled. `rank` and `flags` need a project that already holds a completed analysis run (made in the GUI or by import). `--dry-run` does not write results into the project.

Network verbs (`acquire`, `correlate --fetch`, `intelligence fetch`) refuse to run without a consent flag naming the exact host, for example `--consent-hosts winbindex.m417z.com`. Without it they do nothing.

## Project files

A project is a folder you choose:

| Item | Purpose |
|---|---|
| `project.sqlite3` | Snapshot and history database: artifacts, runs, matches, findings, reviews, notes |
| copied input binaries and raw comparison output | Project-owned copies, hash-checked on open |
| `.patchtrace.lock` | Writer lock; a second instance cannot edit the same project. Close the other instance rather than deleting the lock |

Use **Project > Back up project...** for a full copy (a SQLite backup plus companion files, written to a new folder outside the project). Copying only the database is not a backup. Project storage is not encrypted, and stored interpretation context can contain decompiled code even when an exported report omits it.

## Where data lives

| Data | Location |
|---|---|
| Projects | The folders you create |
| Window layout, paths, font, preferences | Qt settings: Windows registry `HKCU\Software\PatchTrace\PatchTrace`; Linux `~/.config/PatchTrace/PatchTrace.conf`. API keys are not stored there |
| Analysis profiles | Windows `%APPDATA%\PatchTrace\profiles\`; Linux `$XDG_CONFIG_HOME/PatchTrace/profiles/` (default `~/.config/PatchTrace/profiles/`) |
| Derived-result cache | Only if you pass `--cache-dir` or set it in a profile; safe to delete |
| Installed offline runtimes | `%LOCALAPPDATA%\PatchTrace\runtimes\` (Windows) |
| KB and KEV stores | `%LOCALAPPDATA%\PatchTrace\kb` and `kev`, else `$XDG_DATA_HOME/PatchTrace/` |
| Bundled-runtime scratch | `%LOCALAPPDATA%\PatchTrace\work`; Linux `~/.local/state/patchtrace/work` |

Next: [user-guide.md](user-guide.md) for tasks, [concepts.md](concepts.md) for what the numbers mean.
