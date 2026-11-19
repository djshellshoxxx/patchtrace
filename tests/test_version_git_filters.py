"""Independent real-Git side-effect probe against immutable 7bce4d02."""
import shlex
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from patchtrace import buildinfo


def test_version_git_observation_does_not_execute_repository_clean_filter():
    git = shutil.which('git')
    assert git
    with tempfile.TemporaryDirectory(prefix='patchtrace-version-review-', dir=Path.home()) as private:
        root = Path(private)
        def run(*args):
            return subprocess.run([git, *args], cwd=root, check=True, capture_output=True)
        run('init', '-q')
        marker = root / 'filter-executed'
        helper = root / 'fixture_filter.py'
        helper.write_text('import pathlib,sys\npathlib.Path(' + repr(str(marker)) + ').write_text("called")\n'
                          'sys.stdout.buffer.write(sys.stdin.buffer.read())\n')
        (root / '.gitattributes').write_text('tracked.txt filter=review-proof\n')
        tracked = root / 'tracked.txt'
        tracked.write_text('before\n')
        command = shlex.quote(sys.executable) + ' ' + shlex.quote(str(helper))
        run('config', 'filter.review-proof.clean', command)
        run('add', '.gitattributes', 'tracked.txt')
        run('-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid', 'commit', '-qm', 'fixture')
        marker.unlink(missing_ok=True)
        tracked.write_text('after!\n')
        result = buildinfo.git_info(root)
        assert not marker.exists(), result
