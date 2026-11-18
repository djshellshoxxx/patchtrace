"""Published local-package schemas must match the exact shipped record definitions."""
from __future__ import annotations

import importlib
import json
from pathlib import Path


def test_generated_package_schemas_are_registered_bounded_and_current():
    generator = importlib.import_module('tools.generate_package_schemas')
    root = Path(__file__).resolve().parents[1] / 'docs' / 'schemas' / 'local-package'
    rendered = generator.render()
    assert set(rendered) >= {'PackageInventory.json', 'PackageSelection.json', 'PackageLimits.json',
                             'PackageUsage.json', 'PackageCapability.json'}
    assert {p.name for p in root.glob('*.json')} == set(rendered)
    for name, text in rendered.items():
        assert (root / name).read_text(encoding='utf-8') == text
        schema = json.loads(text)
        assert schema['$id'] == f'https://patchtrace.local/schemas/local-package/1/{name}'
        assert schema['additionalProperties'] is False
