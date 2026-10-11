# Upstream research: ghidriff and Diffalayze

Research snapshot recorded 2026-10-11. Sources were cloned outside the PatchTrace repository into `/workspace/scratch/8cf07b853620/research` and inspected locally. The revisions below pin every source claim in this note; upstream `main` will change.

| Project | Revision inspected | License in repository | Main source paths |
|---|---|---|---|
| [clearbluejar/ghidriff](https://github.com/clearbluejar/ghidriff) | `4f5d895fcbb1eacd65efd81145922c15bb7e741d` | GPL-3.0 (see `LICENSE`, `setup.cfg`) | `ghidriff/parser.py`, `ghidriff/__main__.py`, `ghidriff/ghidra_diff_engine.py`, `ghidriff/markdown.py`, `README.md` |
| [SySS-Research/diffalayze](https://github.com/SySS-Research/diffalayze) | `7cab0aae254432f7786d8a450b400f5cc4433865` | MIT (see `LICENSE`) | `diffalayze.py`, `utils/llmanalyze.py`, `utils/llm_client.py`, `utils/prompts.yaml`, `targets/*/fetch_target.py`, `README.md` |

## ghidriff interface and output

Ghidriff is a Python command-line workflow over Ghidra's Program API. The inspected README describes Python 3.10+, with `pyghidra>=3.0.0,<4` and `mdutils==1.6.0` as declared runtime dependencies (`setup.cfg`). The README identifies Ghidra 12.0.4 and pyghidra 3.x as its current development target. Ghidra must be separately installed and `GHIDRA_INSTALL_DIR` set.

The command parser in `ghidriff/parser.py` accepts `ghidriff [options] old new [new ...]`. The first binary is the old version; subsequent binaries are versions in sequence. `--engine` defaults to `VersionTrackingDiff`; other source-defined choices are `SimpleDiff` and `StructualGraphDiff` (spelling as implemented). `-o/--output-path` defaults to `ghidriffs`; `--summary` requests an additional first-to-last diff when three or more binaries are supplied. Ghidra runtime options are added by `GhidraDiffEngine.add_ghidra_args_to_parser`, including project/symbol/GZF paths, base address, analysis options, threading, force flags, JVM memory/args, and decompiler timeout. `--sxs` emits the side-by-side HTML view.

For a two-file comparison, the main function calls `diff_bins(old, new)` and writes the result through `dump_pdiff_to_path`. The output directory contains:

- `<old>-<new>.ghidriff.md`, the readable report (the generated basename includes `.ghidriff`, then `.md`).
- `json/<old>-<new>.ghidriff.json`, the minimized PDiff JSON.
- `json/<old>-<new>.ghidriff.matches.json`, the extracted `matches` object.
- With `--sxs`, `sxs_html/` containing an HTML file per changed matched function.
- Ghidra project data, local symbols, GZF cache, and the configured log path may also be created under the output path by default.

The PDiff JSON shape is assembled in `GhidraDiffEngine.diff_bins` (`ghidriff/ghidra_diff_engine.py`). Core keys and types are:

```json
{
  "program_options": {"<program name>": {"<option>": "<value>"}},
  "matches": {
    "address_matches": {"<old address>": [["<new address>", ["<match type>"]]]},
    "name_matches": {"<old name>": [["<new name>", ["<match type>"]]]}
  },
  "symbols": {"added": ["name"], "deleted": ["name"]},
  "strings": {"added": [{"name": "..."}], "deleted": [{"name": "..."}]},
  "functions": {"added": [], "deleted": [], "modified": []},
  "stats": {"added_funcs_len": 0, "modified_funcs_len": 0},
  "old_meta": {"<Ghidra metadata key>": "..."},
  "new_meta": {"<Ghidra metadata key>": "..."},
  "md_credits": "...",
  "html_credits": "..."
}
```

This is a representative shape, not a complete schema contract: metadata keys depend on the input/Ghidra loader, stats has additional counters, and the root can also contain `old_pe_url` and `new_pe_url` for qualifying PE files. A modified function record has `{old, new, diff, diff_type, ratio, i_ratio, m_ratio, b_ratio, match_types}`. Enhanced function records include `name`, `fullname`, `parent`, `refcount`, `length`, `called`, `calling`, `paramcount`, `address`, `sig`, `code`, `instructions`, `mnemonics`, `blocks`, `sym_type`, `sym_source`, and `external`. Added/deleted records use the enhanced-symbol/function representation rather than names alone. In written JSON, `minimise_pdiff` replaces nonempty `instructions`, `mnemonics`, and `blocks` arrays with Python hash values; consumers should not rely on those fields being arrays in the saved document. The in-memory structure before serialization has the original arrays. Parse defensively and treat Ghidriff's output as versioned-by-upstream, not as a stable public schema.

## Windows and runtime fit

Ghidriff itself documents Windows host setup in `README.md` (PowerShell sets `GHIDRA_INSTALL_DIR`; `pip install ghidriff`). It is therefore a viable local analysis backend for a Windows desktop, provided the app handles Ghidra/JDK provisioning or setup, process lifetime, cancellation, stdout/stderr, output paths, and runtime version compatibility. A first-class adapter should invoke the CLI as an argument vector, not shell-concatenated text, and should snapshot the exact executable/runtime versions used for each case.

Diffalayze is a useful workflow reference but its inspected orchestration is not directly Windows-ready. `diffalayze.py` evaluates `os.getuid()`/`os.getgid()` at module import, which are Unix APIs absent on standard Windows Python. Its Ghidriff process uses the Docker CLI, `-u UID:GID`, `HOME=/tmp`, a Linux `PYTHONPATH`, a POSIX-style bind mount, and a Linux container image; it also calls `Path.chmod(0o777)`. Docker Desktop may support Linux containers and bind mounts on Windows, but this exact Python orchestration assumes Unix identity and path semantics and needs a Windows-aware adapter. The script moves fetched input binaries into a working folder before running the container, so PatchTrace should preserve original user-selected files and stage copies in an isolated case directory.

Ghidriff's parser exposes `--jvm-args` and `--max-ram-percent`, and its README shows the JVM argument equals form (for example `--jvm-args=-Xmx8G`) for leading-dash values. The diff preflight can reject symbol-count mismatches unless `--force-diff` is used. Reports should surface such failures as analysis state rather than implying a meaningful zero-change result. Multi-version sequence inputs create adjacent pair comparisons; the optional summary comparison is first-to-last.

## Diffalayze workflow and AI boundary

Diffalayze composes three distinct operations: a product-specific `fetch_target.py` returns old/new paths, `diffalayze.py` runs Ghidriff in Docker and archives the output, and `utils/llmanalyze.py` converts per-function HTML files to Markdown and runs per-document analysis, final synthesis, and a JSON evaluation. The evaluation prompt expects fields such as `level`, `security_score`, `summary`, and recommended actions; the trigger threshold can launch an arbitrary configured command. Its LLM helper supports Ollama, OpenAI, and Anthropic in `utils/llm_client.py`. The README estimates token usage but explicitly describes LLM results as assistive and requiring human review.

For PatchTrace's evidence-grounded AI feature, reuse the staged workflow idea but attach each claim to the exact function diff and static evidence record, retain the model/provider/model-version and prompt, and show confidence/limitations to a human reviewer. Keep AI optional and separate from deterministic binary comparison; a remote provider changes the data boundary because submitted decompilation/diff text leaves the workstation. Local inference is an alternative in Diffalayze's backend list, not evidence that arbitrary local models share identical output quality or capabilities.

## Source map

- Ghidriff CLI arguments: `ghidriff/ghidriff/parser.py`, `ghidriff/ghidriff/__main__.py`, and `ghidriff/ghidriff/ghidra_diff_engine.py` (`add_ghidra_args_to_parser`, `diff_bins`, `minimise_pdiff`, `dump_pdiff_to_path`).
- Ghidriff output rendering: `ghidriff/ghidriff/markdown.py`.
- Ghidriff Windows setup and CLI examples: `ghidriff/README.md`.
- Diffalayze process, archive, and flags: `diffalayze/diffalayze.py`.
- Diffalayze LLM stages and report: `diffalayze/utils/llmanalyze.py`, `diffalayze/utils/llm_client.py`, `diffalayze/utils/prompts.yaml`.
- Diffalayze example Windows binary acquisition: `diffalayze/targets/mrxsmb/fetch_target.py`, `diffalayze/utils/winbindexer.py`.

## Issues and maintenance signals

The checked-out ghidriff commit is dated 2026-05-11. Its checked-in workflows include Ubuntu lint and Ghidra-backed tests; the test workflow is manually dispatchable and its matrix in this revision has a single Ghidra 12.0.4/Python 3.13 container. This gives useful Linux integration evidence, but not Windows host compatibility coverage. As of the issue-list inspection on 2026-10-11, GitHub showed 28 open ghidriff issues. Relevant examples included [performance #144](https://github.com/clearbluejar/ghidriff/issues/144), [small function changes not captured #121](https://github.com/clearbluejar/ghidriff/issues/121), [decompiler timeout #119](https://github.com/clearbluejar/ghidriff/issues/119), and [large-binary JVM crash #97](https://github.com/clearbluejar/ghidriff/issues/97). These reports are signals to build PatchTrace failure states and regression fixtures, not proof each report affects the pinned revision.

The checked-out Diffalayze commit is dated 2025-09-15. The inspected repository snapshot has no test directory or GitHub Actions workflows; GitHub's issue list displayed zero open issues on 2026-10-11. That is not evidence of tested Windows support or that the project has no defects. Treat both projects as dependencies whose exact revisions and runtime compatibility must be revalidated before release.

The related candidates required by the project brief were also source-inspected. Their exact revisions, README/license paths, capabilities, tests, and reuse decisions are recorded in [reuse-matrix.md](reuse-matrix.md): PatchWatch, BinDiff, BinExport, Diaphora, Ghidra RPC, GhidrAssist, and Ghidra. Ghidra was sparse-checked out at master commit `918d44ebc2962a53d23eeee52b8f44c7816e7815`; the other related repositories were shallow-cloned at the listed commit snapshots. All source/license findings are as of 2026-10-11.
