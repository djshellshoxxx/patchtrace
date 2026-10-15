"""Release gate for the `release` job of qa-windows.yml (windows-acceptance spec section 1.1). Stdlib only.

usage: release_gate.py --head SHA --event NAME --ref REF [--repo OWNER/NAME] >> "$GITHUB_OUTPUT"

Prints `publish=true|false`, `milestones=N` and `reason=TEXT` on stdout, one line each, and a one-line
summary on stderr. A milestone is a first-parent commit on main after the commit of the latest published
prerelease tagged v0.1.0-beta.*, the head included. A commit whose whole message (subject and body) holds a
marker GitHub skips CI for is not one: no build exists for it. The head always is: this run exists. Publish when
  - the ref is a tag, or
  - the head message contains [release], or
  - no earlier prerelease exists, or the latest one is not on the head's first-parent history, or
  - 3 milestones have accumulated, or
  - the gate itself fails: it fails open and says why, so a broken gate never withholds the Windows alpha.
Any event but `push`, and any push to a ref that is neither main nor a tag, never publishes. `milestones` is 0
whenever no count was made. Needs git with the full history and `gh` with GH_TOKEN (contents: read is enough);
only the newest 100 releases are read.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import IO, NamedTuple, NoReturn

BETA_PREFIX = 'v0.1.0-beta.'
MAIN_REF = 'refs/heads/main'
THRESHOLD = 3
RELEASE_MARKER = '[release]'
# The strings GitHub itself honours anywhere in a head commit message (docs: "Skipping workflow runs").
SKIP_MARKERS = ('[skip ci]', '[ci skip]', '[no ci]', '[skip actions]', '[actions skip]')
LOG_FORMAT = '--format=%H%x1f%P%x1f%B%x1e'
TIMEOUT_SECONDS = 60
REASON_LIMIT = 300
SHA = re.compile(r'[0-9a-f]{40}')
REPO = re.compile(r'[\w.-]+/[\w.-]+')


class GateError(Exception):
    """The gate cannot decide; main() turns it into a published (fail-open) decision."""


class Commit(NamedTuple):
    sha: str
    parents: tuple[str, ...]
    message: str


class Release(NamedTuple):
    tag: str
    commit: str
    published: str


class Decision(NamedTuple):
    publish: bool
    milestones: int
    reason: str


SKIP_TRAILER = re.compile(r'^skip-checks:[ \t]*true[ \t]*$', re.IGNORECASE | re.MULTILINE)


def skips_ci(message: str) -> bool:
    lowered = message.lower()
    return any(marker in lowered for marker in SKIP_MARKERS) or bool(SKIP_TRAILER.search(message))


def counted_merges(commits: Sequence[Commit], head: str) -> int:
    """Milestones in the range. The head counts whatever its message says: this run exists, so GitHub did not
    skip it."""
    return sum(commit.sha == head or not skips_ci(commit.message) for commit in commits)


def reaches(commits: Sequence[Commit], anchor: str) -> bool:
    """True when the oldest commit of the range sits directly on the anchor, i.e. the anchor is on the head's
    first-parent chain and the range can be counted. An empty range is the head being the anchor (or older)."""
    return not commits or commits[-1].parents[:1] == (anchor,)


def parse_git_log(text: str) -> list[Commit]:
    """Parse `git log LOG_FORMAT` output, newest first. Anything but 40-hex ids is an error, not a guess."""
    commits = []
    for record in text.split('\x1e'):
        if not record.strip():
            continue
        fields = record.lstrip('\n').split('\x1f', 2)
        if len(fields) != 3:
            raise GateError('unexpected git log output')
        sha, parents, message = fields[0], tuple(fields[1].split()), fields[2]
        if not all(SHA.fullmatch(item) for item in (sha, *parents)):
            raise GateError('unexpected git log output')
        commits.append(Commit(sha, parents, message))
    return commits


def latest_beta_prerelease(text: str) -> Release | None:
    """The newest published prerelease tagged v0.1.0-beta.* in `gh api repos/OWNER/NAME/releases` output."""
    try:
        items = json.loads(text)
    except ValueError as exc:
        raise GateError(f'releases response is not JSON ({exc})') from exc
    if not isinstance(items, list):
        raise GateError('releases response is not a list')
    found = [
        Release(item['tag_name'], str(item.get('target_commitish') or ''),
                str(item.get('published_at') or item.get('created_at') or ''))
        for item in items
        if isinstance(item, dict) and isinstance(item.get('tag_name'), str)
        and item['tag_name'].startswith(BETA_PREFIX) and item.get('prerelease') and not item.get('draft')]
    return max(found, key=lambda release: (release.published, release.tag), default=None)


def ref_decision(event: str, ref: str) -> Decision | None:
    """What the event and ref alone settle; None when the history has to be consulted."""
    if event != 'push':
        return Decision(False, 0, f'event {event or "(none)"} never publishes')
    if ref.startswith('refs/tags/'):
        return Decision(True, 0, f'tag {ref.removeprefix("refs/tags/")} always publishes')
    if ref != MAIN_REF:  # the old release condition named main; keep that if the push triggers are ever widened
        return Decision(False, 0, f'{ref or "(none)"} is neither main nor a tag')
    return None


def decide(head: Commit, anchor: Release | None, commits: Sequence[Commit]) -> Decision:
    """The milestone rule. `commits` is the first-parent range (anchor, head], newest first; it is empty without
    an anchor. A release marker in the head message overrides the count, which is still reported."""
    if anchor is None:
        count, publish, why = 0, True, f'no earlier prerelease tagged {BETA_PREFIX}*'
    elif not reaches(commits, anchor.commit):
        count, publish, why = 0, True, f'{anchor.tag} is not on the first-parent history of the head'
    else:
        count = counted_merges(commits, head.sha)
        publish = count >= THRESHOLD
        why = (f'{count} counted merges since {anchor.tag}, the publish threshold is {THRESHOLD}' if publish
               else f'{count} of {THRESHOLD} counted merges since {anchor.tag}')
    if RELEASE_MARKER in head.message.lower():
        return Decision(True, count, f'head commit message contains {RELEASE_MARKER}')
    return Decision(publish, count, why)


class Tools:
    """The two programs the gate reads from. Tests replace this class; nothing else starts a process."""

    def __init__(self, cwd: Path | None = None) -> None:
        self.cwd = cwd

    def git(self, *args: str) -> str:
        return self._run(['git', *args], self.cwd)

    def releases(self, repo: str) -> str:
        """The newest 100 releases as JSON. Drafts show only with push access, which the job token lacks."""
        return self._run(['gh', 'api', f'repos/{repo}/releases?per_page=100'], None)

    @staticmethod
    def _run(argv: list[str], cwd: Path | None) -> str:
        try:
            done = subprocess.run(argv, cwd=cwd, capture_output=True, timeout=TIMEOUT_SECONDS, check=False)
        except subprocess.TimeoutExpired as exc:
            raise GateError(f'{argv[0]} timed out after {TIMEOUT_SECONDS} s') from exc
        except OSError as exc:
            raise GateError(f'{argv[0]} could not run ({exc})') from exc
        if done.returncode != 0:
            detail = done.stderr.decode('utf-8', 'replace').strip()
            raise GateError(f'{" ".join(argv[:2])} failed with exit {done.returncode}: {detail[:200]}')
        return done.stdout.decode('utf-8', 'replace')


def read_log(tools: Tools, *selection: str) -> list[Commit]:
    return parse_git_log(tools.git('log', '--no-show-signature', LOG_FORMAT, *selection))


def evaluate(tools: Tools, repo: str, head: str) -> Decision:
    """The decision that needs git and the API. A failure raises (GateError or a bug), and main() fails open."""
    if not REPO.fullmatch(repo):
        raise GateError('repository must be OWNER/NAME (--repo or GITHUB_REPOSITORY)')
    head_sha = tools.git('rev-parse', '--verify', f'{head}^{{commit}}').strip()
    if not SHA.fullmatch(head_sha):
        raise GateError(f'{head!r} is not a commit')
    (head_commit,) = read_log(tools, '-1', head_sha)
    anchor = latest_beta_prerelease(tools.releases(repo))
    commits: list[Commit] = []
    if anchor is not None:
        if not SHA.fullmatch(anchor.commit):
            raise GateError(f'{anchor.tag} targets {anchor.commit!r}, which is not a commit SHA')
        commits = read_log(tools, '--first-parent', f'{anchor.commit}..{head_sha}')
    return decide(head_commit, anchor, commits)


def one_line(text: str, limit: int = REASON_LIMIT) -> str:
    """Printable ASCII on one line: safe as a $GITHUB_OUTPUT value and in the release notes."""
    flat = ' '.join(text.split())
    return ''.join(char if char.isascii() and char.isprintable() else '?' for char in flat)[:limit]


def render(decision: Decision) -> str:
    return (f'publish={"true" if decision.publish else "false"}\n'
            f'milestones={decision.milestones}\nreason={one_line(decision.reason)}\n')


class _Parser(argparse.ArgumentParser):
    def error(self, message: str) -> NoReturn:
        raise GateError(f'usage error: {message}')


def build_parser(environ: Mapping[str, str]) -> argparse.ArgumentParser:
    parser = _Parser(description=__doc__.splitlines()[0], allow_abbrev=False)
    parser.add_argument('--head', required=True, help='commit this run builds ($GITHUB_SHA)')
    parser.add_argument('--event', required=True, help='workflow event ($GITHUB_EVENT_NAME)')
    parser.add_argument('--ref', required=True, help='pushed ref ($GITHUB_REF)')
    parser.add_argument('--repo', default=environ.get('GITHUB_REPOSITORY', ''),
                        help='OWNER/NAME (default $GITHUB_REPOSITORY)')
    return parser


def fallback_decision(argv: Sequence[str] | None) -> Decision | None:
    """The event and ref alone, read leniently from a command line the strict parser refused. Only a
    non-publishing answer is used: a parse error must never publish for a pull request or other non-push event."""
    lenient = argparse.ArgumentParser(add_help=False, allow_abbrev=False, exit_on_error=False)
    lenient.add_argument('--event', default='')
    lenient.add_argument('--ref', default='')
    try:
        known, _ = lenient.parse_known_args(list(argv) if argv is not None else sys.argv[1:])
    except (argparse.ArgumentError, SystemExit):
        return None
    if not known.event or (known.event == 'push' and not known.ref):
        return None
    decision = ref_decision(known.event, known.ref)
    return decision if decision is not None and not decision.publish else None


def describe(exc: Exception) -> str:
    return str(exc) if isinstance(exc, GateError) else f'{type(exc).__name__} {exc}'


def main(argv: Sequence[str] | None = None, *, tools: Tools | None = None,
         environ: Mapping[str, str] | None = None, out: IO[str] | None = None,
         err: IO[str] | None = None) -> int:
    environ = os.environ if environ is None else environ
    out = sys.stdout if out is None else out
    err = sys.stderr if err is None else err
    try:
        args = build_parser(environ).parse_args(argv)
        decision = ref_decision(args.event, args.ref)
        if decision is None:
            decision = evaluate(Tools() if tools is None else tools, args.repo, args.head)
    except Exception as exc:  # fail open: a broken gate must never withhold a build, and it says why
        decision = fallback_decision(argv) or Decision(
            True, 0, f'gate error, publishing anyway: {describe(exc)}')
    text = render(decision)
    out.write(text)
    err.write(f'release_gate: {" ".join(text.split())}\n')
    return 0


if __name__ == '__main__':
    sys.exit(main())
