"""Research receipts identify the selected checkout without invoking a Git process."""
from __future__ import annotations

from pathlib import Path

import pytest

from tools.research_qualification.receipt import git_head

SHA = 'a' * 40
OTHER = 'b' * 40


def put(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding='utf-8')


@pytest.mark.parametrize('packed', [False, True])
def test_regular_checkout_uses_exact_branch_ref(tmp_path, packed):
    put(tmp_path / '.git/HEAD', 'ref: refs/heads/topic\n')
    if packed:
        put(tmp_path / '.git/packed-refs', f'# pack-refs\n{OTHER} refs/heads/other\n{SHA} refs/heads/topic\n')
    else:
        put(tmp_path / '.git/refs/heads/topic', SHA + '\n')
    assert git_head(tmp_path) == SHA


@pytest.mark.parametrize('mode', ['detached', 'loose', 'packed', 'worktree-ref'])
@pytest.mark.parametrize('absolute', [False, True])
def test_linked_checkout_uses_its_own_head_and_declared_common_refs(tmp_path, mode, absolute):
    root, common = tmp_path / 'checkout', tmp_path / 'shared.git'
    private = common / 'worktrees/linked'
    locator = str(private) if absolute else '../shared.git/worktrees/linked'
    put(root / '.git', 'gitdir: ' + locator + '\n')
    put(private / 'commondir', str(common) + '\n' if absolute else '../..\n')
    put(common / 'HEAD', OTHER + '\n')
    if mode == 'detached':
        put(private / 'HEAD', SHA + '\n')
    else:
        ref = 'refs/worktree/probe' if mode == 'worktree-ref' else 'refs/heads/topic'
        put(private / 'HEAD', f'ref: {ref}\n')
        if mode == 'packed':
            put(common / 'packed-refs', f'{SHA} {ref}\n')
        else:
            put((private if mode == 'worktree-ref' else common) / ref, SHA + '\n')
    assert git_head(root) == SHA


def test_separate_gitdir_without_commondir_is_supported(tmp_path):
    root, metadata = tmp_path / 'checkout', tmp_path / 'module.git'
    put(root / '.git', 'gitdir: ../module.git\n')
    put(metadata / 'HEAD', SHA + '\n')
    assert git_head(root) == SHA


@pytest.mark.parametrize('text', ['not-a-commit', 'a' * 39, 'a' * 41, 'A' * 40,
                                  SHA + '\n' + OTHER, 'x' * 65537])
def test_invalid_or_oversized_head_cannot_be_a_receipt_commit(tmp_path, text):
    put(tmp_path / '.git/HEAD', text)
    assert git_head(tmp_path) is None


@pytest.mark.parametrize('ref', ['../secret', 'refs/../secret', '/absolute', 'refs//heads/topic',
                                 'refs/heads/./topic', r'refs\heads\topic'])
def test_symbolic_ref_cannot_escape_metadata_namespace(tmp_path, ref):
    put(tmp_path / '.git/HEAD', 'ref: ' + ref + '\n')
    put(tmp_path / '.git/secret', SHA + '\n')
    put(tmp_path / 'secret', SHA + '\n')
    assert git_head(tmp_path) is None


def test_conflicting_packed_refs_are_unknown(tmp_path):
    put(tmp_path / '.git/HEAD', 'ref: refs/heads/topic\n')
    put(tmp_path / '.git/packed-refs', f'{SHA} refs/heads/topic\n{OTHER} refs/heads/topic\n')
    assert git_head(tmp_path) is None


def test_loose_ref_has_precedence_over_older_packed_ref(tmp_path):
    put(tmp_path / '.git/HEAD', 'ref: refs/heads/topic\n')
    put(tmp_path / '.git/refs/heads/topic', SHA + '\n')
    put(tmp_path / '.git/packed-refs', f'{OTHER} refs/heads/topic\n')
    assert git_head(tmp_path) == SHA


def test_missing_checkout_is_unknown(tmp_path):
    assert git_head(tmp_path) is None


def test_cyclic_metadata_location_is_unknown(tmp_path):
    put(tmp_path / '.git', 'gitdir: loop-a\n')
    try:
        (tmp_path / 'loop-a').symlink_to('loop-b')
        (tmp_path / 'loop-b').symlink_to('loop-a')
    except OSError:
        pytest.skip('the runner cannot create symbolic links')
    assert git_head(tmp_path) is None


def test_nonregular_head_is_unknown(tmp_path):
    (tmp_path / '.git/HEAD').mkdir(parents=True)
    assert git_head(tmp_path) is None


def test_oversized_packed_refs_are_unknown_without_returning_a_prefix_match(tmp_path):
    put(tmp_path / '.git/HEAD', 'ref: refs/heads/topic\n')
    path = tmp_path / '.git/packed-refs'
    with path.open('wb') as stream:
        stream.write(f'{SHA} refs/heads/topic\n'.encode())
        stream.truncate(8 * 1024 * 1024 + 1)
    assert git_head(tmp_path) is None
