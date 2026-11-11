"""Recipe `libs` (bare link-library names, LBL-01 contract) reach the mingw link line; offline, no compiler needed."""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools.calibration.tier_r import build as B  # noqa: E402
from tools.calibration.tier_r import contracts as C  # noqa: E402
from tools.calibration.tier_r import factory as F  # noqa: E402
from tools.calibration.tier_r.fetch import RECEIPT, checkout_dir  # noqa: E402

COMMIT = 'a' * 40


def _recipe(libs):
    return C.Recipe.model_validate_json(json.dumps({
        'contract': 'tier-r-recipe/1', 'project': 'demo', 'family': 'parser', 'upstream_git': 'https://github.com/o/demo.git',
        'license_spdx': 'MIT', 'license_file': 'LICENSE', 'license_evidence': 'MIT text', 'libc': 'mingw',
        'output': 'demo.dll', 'sources': ['*.c'], 'libs': libs,
        'pins': [{'ref': 'v1', 'commit': COMMIT, 'license_sha256': 'b' * 64}]}))


def test_recipe_libs_reach_the_build_spec(tmp_path):
    root = checkout_dir(tmp_path, 'demo', COMMIT)
    root.mkdir(parents=True)
    (root / 'demo.c').write_text('int demo(void) { return 1; }\n')
    (root / RECEIPT).write_text(json.dumps({'commit': COMMIT, 'verified': True, 'commit_time': 1}))
    recipe = _recipe(['ws2_32', 'iphlpapi'])
    base = F.recipe_base(C.RecipeBook(contract='tier-r-recipes/1', recipes=(recipe,)), recipe, 'v1', COMMIT, tmp_path)
    assert base.spec().libs == ('ws2_32', 'iphlpapi')
    assert F.recipe_base(C.RecipeBook(contract='tier-r-recipes/1', recipes=(_recipe([]),)), _recipe([]), 'v1', COMMIT,
                         tmp_path).spec().libs == ()


def test_link_lib_args_follow_the_objects_in_declared_order():
    spec = B.BuildSpec(project='demo', source_root=ROOT, files=('demo.c',), output='demo.dll', profile='mingw-gcc',
                       libs=('ws2_32', 'iphlpapi'))
    assert B.link_lib_args(spec) == ['-lws2_32', '-liphlpapi']
    assert B.link_lib_args(B.BuildSpec(project='demo', source_root=ROOT, files=('demo.c',), output='demo.dll',
                                       profile='mingw-gcc')) == []
