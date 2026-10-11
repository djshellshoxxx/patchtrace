# PatchTrace
Compare binaries. Trace fixes. Investigate flaws.

PatchTrace is a local desktop for reviewing changes between two Windows x64 PE binaries. Ghidriff/Ghidra provides static analysis; PatchTrace provides project ownership, paired code review, manual match decisions, evidence-linked optional AI hypotheses, and reports. A changed function is not automatically a vulnerability.

## Development
Python 3.12+ is required. From repository root:
```sh
python -m pip install -e '.[dev]'
python -m patchtrace
QT_QPA_PLATFORM=offscreen python -m pytest -q
python -m ruff check src tests tools
PYTHONPATH=src python tools/generate_schemas.py
```
The included synthetic sample works without Ghidra or a model. See [module index](docs/modules.md), [specifications](docs/specs/architecture.md), [upstream research](docs/research.md), and [delivery tracker](tasks/todo.md).

## Windows standalone
The Windows Actions workflow builds a desktop ZIP with Python and Qt included. Extract the whole ZIP before running `PatchTrace.exe`. Ghidra, Java and a separate Python/Ghidriff environment are external analysis dependencies and are not bundled. Optional AI requires a configured local Ollama model or an explicitly chosen remote OpenAI-compatible endpoint. Credentials stay in the session.

Use Sample to explore the workspace. New comparison asks you to select older and newer artifacts explicitly. Configure external backend Python and Ghidra directory, then Run. Imported Ghidriff JSON must belong to the selected artifacts. Review code, annotate, correct matches and export. Interpretation first previews the exact context to be sent; model output remains a hypothesis pending analyst review.

See [Windows setup](docs/windows.md) and [QA record](docs/qa.md) for verified and blocked checks. This repository does not claim backend matching or LLM conclusions are validated by unit tests.
