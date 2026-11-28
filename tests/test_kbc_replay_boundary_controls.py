"""Independent authored offline replay controls; no target execution or sockets."""
from __future__ import annotations

import gzip
import json
import shutil

import pytest
from kbc_k1_support import no_sockets  # noqa: F401
from test_kbc_acquire_cli import HOSTS, plan_of
from test_kbc_acquire_cli import ready as ready  # noqa: F401
from test_kbc_acquisition_replay_cli import replay
from test_kbc_raw_index_acquisition import complete, source_path, stored

from patchtrace.kbcorrelation.acquisition_evidence import canonical

pytestmark = pytest.mark.usefixtures('no_sockets')


@pytest.mark.parametrize('component', ['evidence', 'raw'])
@pytest.mark.parametrize('alias', ['file', 'directory'])
def test_exact_bytes_through_an_unowned_alias_are_refused(ready, tmp_path, component, alias):
    kb, server, _inv, _flags, project = ready
    assert complete(ready)[0] == 0
    evidence = stored(project)
    path = project / (evidence.relative_path if component == 'evidence'
                      else evidence.source.replay.source.relative_path)
    original = path.read_bytes()
    outside = tmp_path / f'external-{component}-{alias}'
    if alias == 'file':
        path.rename(outside)
        path.symlink_to(outside)
        retained = outside
    else:
        shutil.move(str(path.parent), outside)
        path.parent.symlink_to(outside, target_is_directory=True)
        retained = outside / path.name
    calls = tuple(server.calls)
    code, doc, _err = replay(kb, project, evidence.evidence_id)
    assert code == 3 and 'PT-KBC-STORAGE' in doc['error']
    assert retained.read_bytes() == original
    assert tuple(server.calls) == calls
    assert (path if alias == 'file' else path.parent).is_symlink()


def test_gzip_header_only_change_invalidates_consent_even_when_semantics_match(ready):
    kb, server, inv, flags, project = ready
    path = source_path(kb)
    plain = path.read_bytes()
    zipped = path.with_suffix('.json.gz')
    zipped.write_bytes(gzip.compress(plain, mtime=1))
    path.unlink()
    first = plan_of(kb, inv, flags, project)
    zipped.write_bytes(gzip.compress(plain, mtime=2))
    second = plan_of(kb, inv, flags, project)
    one, two = first['source']['replay'], second['source']['replay']
    for key in ('mapping_sha256', 'mapping_count', 'lineage_sha256', 'lineage_count',
                'resolution_sha256', 'selected_pair_id'):
        assert one[key] == two[key]
    assert one['source']['sha256'] != two['source']['sha256']
    assert first['plan_sha'] != second['plan_sha']
    code, doc, _ = kb('acquire', inv, '--project', str(project), *flags,
                     '--consent-hosts', HOSTS, '--consent-plan', first['plan_sha'])
    assert code == 2 and 'PT-KBC-CONSENT' in doc['error']
    assert not server.calls and not project.exists()
    assert not (kb.workspace / 'winbindex-objects').exists()


def test_unusable_unrelated_row_is_retained_and_gap_reproduced(ready):
    kb, server, inv, flags, project = ready
    baseline = plan_of(kb, inv, flags, project)['source']['replay']
    path = source_path(kb)
    document = json.loads(path.read_bytes())
    document['independent-invalid-sha'] = {'unusable': 'original retained source claim'}
    path.write_bytes(json.dumps(document).encode('utf-8'))
    raw = path.read_bytes()
    assert complete(ready)[0] == 0
    evidence = stored(project)
    retained = evidence.source.replay
    assert retained.mapping_count == baseline['mapping_count']
    assert retained.parser_skipped == baseline['parser_skipped'] + 1
    assert (project / retained.source.relative_path).read_bytes() == raw
    calls = tuple(server.calls)
    code, doc, _ = replay(kb, project, evidence.evidence_id)
    assert code == 0 and doc['result']['state'] == 'reproduced'
    assert doc['result']['skipped_rows'] == (retained.parser_skipped + retained.parser_skipped_bodies
                                           + retained.conversion_rejected)
    assert tuple(server.calls) == calls


def test_missing_project_source_does_not_substitute_valid_workspace_copy(ready):
    kb, server, _inv, _flags, project = ready
    assert complete(ready)[0] == 0
    evidence = stored(project)
    source = evidence.source.replay.source
    cache = kb.workspace / source.workspace_path
    original = cache.read_bytes()
    (project / source.relative_path).unlink()
    calls = tuple(server.calls)
    code, doc, _ = replay(kb, project, evidence.evidence_id)
    assert code == 3 and 'PT-KBC-STORAGE' in doc['error']
    assert cache.read_bytes() == original and not (project / source.relative_path).exists()
    assert tuple(server.calls) == calls


def test_future_replay_contract_is_reported_unsupported_without_rewriting(ready):
    kb, server, _inv, _flags, project = ready
    assert complete(ready)[0] == 0
    evidence = stored(project)
    document = evidence.model_dump(mode='json')
    document['source']['replay']['replay_version'] = 99
    raw = canonical(document)
    path = project / evidence.relative_path
    path.write_bytes(raw)
    calls = tuple(server.calls)
    code, doc, _ = replay(kb, project, evidence.evidence_id)
    assert code == 2 and 'PT-KBC-UNSUPPORTED' in doc['error']
    assert path.read_bytes() == raw and tuple(server.calls) == calls
