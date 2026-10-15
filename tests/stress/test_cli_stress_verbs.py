"""QA-CLI: every verb and sub-verb, help and error paths, exit codes 0/2/3/4/5 only, one JSON document in --json."""
from __future__ import annotations

import argparse

import pytest
from cli_stress_support import CVE, assert_clean, json_documents, make_sample, run_main, run_process

from patchtrace import cli


def _subparsers(parser: argparse.ArgumentParser) -> argparse._SubParsersAction:
    return next(a for a in parser._actions if isinstance(a, argparse._SubParsersAction))


def _verb_paths() -> list[list[str]]:
    paths: list[list[str]] = []
    for verb, sub in _subparsers(cli._parser(['patchtrace'])).choices.items():
        nested = [a for a in sub._actions if isinstance(a, argparse._SubParsersAction)]
        paths += [[verb, name] for name in nested[0].choices] if nested else [[verb]]
    return paths


def _requires_arguments(path: list[str]) -> bool:
    """True when the verb cannot run bare. Leaf verbs without required arguments are never run bare: a bare
    `backend verify` or `intel-tools probe` would start a probe of external tools."""
    node = cli._parser(['patchtrace'])
    for name in path:
        node = _subparsers(node).choices[name]
    return any(a.required for a in node._actions if a.dest != 'help')


VERB_PATHS = _verb_paths()
VERB_IDS = [' '.join(path) for path in VERB_PATHS]
TOP_LEVEL = [[name] for name in _subparsers(cli._parser(['patchtrace'])).choices]
BARE_PATHS = [path for path in [*TOP_LEVEL, *VERB_PATHS] if _requires_arguments(path)]


@pytest.mark.parametrize('path', VERB_PATHS, ids=VERB_IDS)
def test_help_exits_zero_and_prints_usage(path, capsys):
    code, out, err = run_main([*path, '--help'], capsys)
    assert code == cli.OK, err
    assert out.startswith('usage: patchtrace'), out[:200]
    assert_clean(code, out, err)


@pytest.mark.parametrize('path', BARE_PATHS, ids=[' '.join(p) for p in BARE_PATHS])
def test_bare_verb_missing_arguments_is_a_usage_error(path, capsys):
    code, out, err = run_main(path, capsys)
    assert code == cli.ENVIRONMENT, (code, err)
    assert_clean(code, out, err)


@pytest.mark.parametrize('path', VERB_PATHS, ids=VERB_IDS)
def test_unknown_option_is_a_usage_error(path, capsys):
    code, out, err = run_main([*path, '--no-such-option'], capsys)
    assert code == cli.ENVIRONMENT, (code, err)
    assert_clean(code, out, err)


# '@case' is a committed sample project, '@missing' a path that does not exist, '@file' a plain file.
ERROR_CASES = [
    (['rank', '@missing'], cli.ENVIRONMENT, 'rank-missing-project'),
    (['rank', '@file'], cli.ENVIRONMENT, 'rank-file-not-directory'),
    (['rank', '@case', '--limit', '-1'], cli.ENVIRONMENT, 'rank-negative-limit'),
    (['rank', '@case', '--weights', '@missing/w.json'], cli.ENVIRONMENT, 'rank-missing-weights'),
    (['rank', '@case', '--disable', 'bogus'], cli.ENVIRONMENT, 'rank-unknown-detector'),
    (['rank', '@case', '--refresh'], cli.ENVIRONMENT, 'rank-refresh-without-cache'),
    (['rank', '@case', '--profile', 'no-such-profile'], cli.ENVIRONMENT, 'rank-unknown-profile'),
    (['flags', '@missing'], cli.ENVIRONMENT, 'flags-missing-project'),
    (['correlate', '@case', '--cve', CVE, '--fetch'], cli.ENVIRONMENT, 'correlate-fetch-without-consent'),
    (['correlate', '@case', '--cve', 'CVE-24-1', '--fetch', '--consent-providers', 'nvd,msrc'], cli.ENVIRONMENT,
     'correlate-malformed-cve-with-fetch'),
    (['cache', 'status'], cli.ENVIRONMENT, 'cache-status-without-dir'),
    (['acquire', 'search', 'x.sys', '--consent-hosts', 'example.com'], cli.ENVIRONMENT,
     'acquire-search-wrong-host'),
    (['secondary', 'run', '@case', '--engine', 'nope'], cli.ENVIRONMENT, 'secondary-run-unknown-engine'),
    (['secondary', 'run', '@missing'], cli.ENVIRONMENT, 'secondary-run-missing-project'),
    (['series', 'chains', '@missing/series.json'], cli.ENVIRONMENT, 'series-chains-missing-file'),
    (['unified', 'show', '@missing'], cli.ENVIRONMENT, 'unified-show-missing-project'),
]


@pytest.fixture(scope='module')
def fixture_paths(tmp_path_factory):
    base = tmp_path_factory.mktemp('verbs')
    plain = base / 'plain.txt'
    plain.write_text('not a project\n', encoding='utf-8', newline='\n')
    return {'@case': make_sample(base / 'case'), '@missing': base / 'does-not-exist', '@file': plain}


def _resolve(argv: list[str], paths: dict) -> list[str]:
    resolved = []
    for token in argv:
        for marker, value in paths.items():
            if token.startswith(marker):
                token = str(value) + token[len(marker):]
        resolved.append(token)
    return resolved


@pytest.mark.parametrize('argv,expected,case_id', ERROR_CASES, ids=[c[2] for c in ERROR_CASES])
def test_error_path_exit_code_and_no_traceback(argv, expected, case_id, fixture_paths, capsys):
    code, out, err = run_main(_resolve(argv, fixture_paths), capsys)
    assert code == expected, (code, err[-500:])
    assert_clean(code, out, err)


# Successful and no-result runs in --json mode: exactly one JSON document, contract envelope present.
JSON_RUNS = [
    (['rank', '@case', '--json', '--dry-run'], cli.OK, 'rank-dry-run'),
    (['flags', '@case', '--json'], cli.NO_RESULTS, 'flags-no-transitions'),
    (['unified', 'status', '@case', '--json'], cli.OK, 'unified-status'),
    (['backend', 'status', '--json'], None, 'backend-status'),
    (['intel-tools', 'probe', '--json'], None, 'intel-tools-probe'),
    (['cache', 'status', '--cache-dir', '@missing/cache', '--json'], cli.OK, 'cache-status-empty'),
    (['rank', '@missing', '--json'], cli.ENVIRONMENT, 'rank-missing-project-json'),
    (['series', 'chains', '@missing/series.json', '--json'], cli.ENVIRONMENT, 'series-chains-missing-json'),
]


@pytest.mark.parametrize('argv,expected,case_id', JSON_RUNS, ids=[c[2] for c in JSON_RUNS])
def test_json_mode_emits_exactly_one_document(argv, expected, case_id, fixture_paths, capsys):
    code, out, err = run_main(_resolve(argv, fixture_paths), capsys)
    assert_clean(code, out, err)
    if expected is not None:
        assert code == expected, (code, err[-500:])
    documents = json_documents(out)
    assert len(documents) == 1, out[:500]
    assert documents[0]['contract'] == 'enrichment-cli/1'
    assert isinstance(documents[0]['status'], str)


# Parse failures in --json mode. The contract says stdout carries exactly one document, so these must emit one.
PARSE_FAILURES_JSON = [
    (['rank', '--json'], 'rank-no-project'),
    (['correlate', '--json'], 'correlate-no-cve'),
    (['acquire', 'search', '--json'], 'acquire-search-no-name'),
    (['rank', '@case', '--json', '--limit', 'x'], 'rank-bad-limit'),
]
@pytest.mark.xfail(strict=True, reason='QA-CLI-1: argparse failures in --json mode print no JSON document '
                   '(cli.main builds the envelope only after a successful parse)')
@pytest.mark.parametrize('argv,case_id', PARSE_FAILURES_JSON, ids=[c[1] for c in PARSE_FAILURES_JSON])
def test_json_mode_parse_failure_emits_one_document(argv, case_id, fixture_paths, capsys):
    code, out, err = run_main(_resolve(argv, fixture_paths), capsys)
    assert code == cli.ENVIRONMENT
    documents = json_documents(out)
    assert len(documents) == 1, out


@pytest.mark.xfail(strict=True, reason='QA-CLI-2: an offline correlate accepts a malformed CVE id and reports '
                   'exit 4 (complete evidence, zero entries) instead of rejecting it with exit 2')
def test_offline_correlate_rejects_malformed_cve_id(fixture_paths, capsys):
    code, out, err = run_main(['correlate', fixture_paths['@case'], '--cve', 'bad'], capsys)
    assert code == cli.ENVIRONMENT, (code, err)


def test_entry_point_exit_status_for_representative_verbs(fixture_paths, tmp_path):
    """The real `python -m patchtrace` process: status the shell sees, not the return value of cli.main."""
    case = fixture_paths['@case']
    expectations = [
        (['rank', '--help'], 0),
        (['rank', str(fixture_paths['@missing']), '--json'], cli.ENVIRONMENT),
        (['no-such-verb'], cli.ENVIRONMENT),
        (['--no-such-flag'], cli.ENVIRONMENT),
        (['rank', str(case), '--dry-run', '--json'], cli.OK),
    ]
    for argv, expected in expectations:
        result = run_process(argv, tmp_path)
        assert_clean(result.returncode, result.stdout, result.stderr)
        assert result.returncode == expected, (argv, result.returncode, result.stderr[-500:])
