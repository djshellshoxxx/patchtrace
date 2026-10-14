"""Every spec file under docs/specs/ must be cited by path in docs/specs/REGISTRY.md.

The registry maps each spec file to its canonical SPEC alias, so a cross-reference
never depends on a number printed inside a document. A new spec file that is not
registered fails here until it is added to the registry table.
"""

from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[1]
SPECS_DIR = REPO_ROOT / "docs" / "specs"
REGISTRY = SPECS_DIR / "REGISTRY.md"
EXCLUDED_DIR = SPECS_DIR / "program-e"


def _spec_files() -> list[str]:
    files = []
    for path in SPECS_DIR.rglob("*"):
        if not path.is_file() or path.is_relative_to(EXCLUDED_DIR):
            continue
        files.append(path.relative_to(REPO_ROOT).as_posix())
    return sorted(files)


SPEC_FILES = _spec_files()


def test_spec_walk_is_not_vacuous():
    # An empty walk would make the parametrized check below pass trivially.
    assert len(SPEC_FILES) >= 40, SPEC_FILES


@pytest.mark.parametrize("rel", SPEC_FILES)
def test_registry_cites_spec_file_by_path(rel):
    assert REGISTRY.is_file(), "docs/specs/REGISTRY.md is missing"
    text = REGISTRY.read_text(encoding="utf-8")
    assert f"`{rel}`" in text, f"{rel} is not cited by path in docs/specs/REGISTRY.md"
