"""SPEC-09b section 4: tolerant discovery, recoverable save and classified staleness."""
from test_nway_series import builds, create, populated  # noqa: F401, F811  (fixture and helper reuse)

from patchtrace.nway import series as store
from patchtrace.nway.series import sha256_file
from patchtrace.service import ProjectService


def _wanted(files):
    h = [sha256_file(b) for b in files[:3]]
    return {(h[0], h[1]): (0, 1), (h[1], h[2]): (1, 2)}


def _junk(path):
    path.mkdir(parents=True)
    (path / 'project.sqlite3').write_bytes(b'not a database' * 100)


def test_discover_pairs_skips_unreadable_and_locked_siblings(builds, tmp_path, capsys):  # noqa: F811
    root = tmp_path / 's'
    assert create(capsys, builds[:3], root)[0] == 0
    refs = store.load(root / 'series.json').pair_projects
    _junk(root / 'zz-junk')
    holder = ProjectService.open(root / refs[1].path)
    try:
        found = store.discover_pairs(root, _wanted(builds))
    finally:
        holder.close()
    assert found.found == {(0, 1): root / refs[0].path}
    assert {(s.name, s.code) for s in found.skipped} == {('zz-junk', 'unreadable'), (refs[1].path, 'locked')}


def test_create_reports_skipped_sibling_as_warning_and_exits_0(builds, tmp_path, capsys):  # noqa: F811
    root = tmp_path / 's'
    _junk(root / 'junk')
    code, doc, _ = create(capsys, builds[:3], root)
    assert code == 0, doc
    assert any(w.startswith('skipped sibling junk:') for w in doc['warnings'])


def test_unreadable_directory_at_deterministic_name_exits_2(builds, tmp_path, capsys):  # noqa: F811
    h = [sha256_file(b) for b in builds[:3]]
    bad = tmp_path / 's' / f'pair-0-1-{h[0][:12]}-{h[1][:12]}'
    _junk(bad)
    code, doc, _ = create(capsys, builds[:3], tmp_path / 's')
    assert code == 2 and 'cannot be read' in doc['error'] and bad.name in doc['error']


def test_save_refuses_corrupt_series_unless_replace_corrupt(builds, tmp_path, capsys):  # noqa: F811
    root = tmp_path / 's'
    assert create(capsys, builds[:3], root)[0] == 0
    path = root / 'series.json'
    good = path.read_bytes()
    path.write_bytes(b'{ truncated')
    code, doc, _ = create(capsys, builds[:3], root)
    assert code == 2 and '--replace-corrupt' in doc['error'] and path.read_bytes() == b'{ truncated'
    code, doc, _ = create(capsys, builds[:3], root, '--replace-corrupt')
    assert code == 0, doc
    assert path.read_bytes() == good
    [copy] = list(root.glob('series.json.corrupt-*'))
    assert copy.read_bytes() == b'{ truncated'
    path.write_bytes(b'{ other')
    assert create(capsys, builds[:3], root, '--replace-corrupt')[0] == 0
    assert len(list(root.glob('series.json.corrupt-*'))) == 2 and copy.read_bytes() == b'{ truncated'


def test_replace_corrupt_never_replaces_a_readable_other_series(builds, tmp_path, capsys):  # noqa: F811
    root = tmp_path / 's'
    assert create(capsys, builds[:3], root)[0] == 0
    code, doc, _ = create(capsys, builds[1:4], root, '--replace-corrupt')
    assert code == 2 and 'another series' in doc['error']


def test_staleness_survives_a_damaged_pair_and_evaluates_others(builds, tmp_path, capsys):  # noqa: F811
    root = tmp_path / 's'
    plan, _ = populated(capsys, builds, root)
    series = store.load(root / 'series.json')
    (plan[0] / 'project.sqlite3').write_bytes(b'x' * 64)
    stale = store.staleness(series, root / 'series.json')
    assert 0 in stale.pairs and 1 not in stale.pairs
    assert len(stale.reasons) == 1 and stale.reasons[0].startswith('pair 0')
