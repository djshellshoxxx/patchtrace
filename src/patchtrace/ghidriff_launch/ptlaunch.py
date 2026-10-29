"""PatchTrace-owned Ghidriff launcher (SPEC-53, contract ptlaunch/1).

This file is DATA. PatchTrace copies it into a private scratch directory and runs it with the analyst's own
external Python, never importing it. It imports nothing of PatchTrace: stdlib plus `ghidriff` only. It is original
code that calls public Ghidriff names; it does not copy Ghidriff source.

    python ptlaunch.py --pt-mode off|local|online --pt-report <path> [--pt-staged <name>]... [--pt-allow-servers] -- <ghidriff args>

`local` forces the Ghidra symbol-server list to empty by wrapping `GhidraDiffEngine.setup_symbol_server`. If the hook
is missing or has another shape the launcher exits 78 and never falls back to online lookups.
Exit codes: 64 usage, 78 incompatible Ghidriff, otherwise Ghidriff's own status.
"""
import inspect
import json
import os
import sys

CONTRACT = 'ptlaunch/1'
EX_USAGE = 64
EX_INCOMPATIBLE = 78
MODES = ('off', 'local', 'online')


def _fail(code, message, status):
    sys.stderr.write(f'{code}: {message}\n')
    sys.stderr.flush()
    return status


def _parse(argv):
    opts = {'mode': None, 'report': None, 'staged': [], 'allow_servers': False}
    i = 0
    while i < len(argv):
        arg = argv[i]
        if arg == '--':
            return opts, argv[i + 1:]
        if arg == '--pt-allow-servers':
            opts['allow_servers'] = True
        elif arg in ('--pt-mode', '--pt-report', '--pt-staged') and i + 1 < len(argv):
            i += 1
            if arg == '--pt-staged':
                opts['staged'].append(argv[i])
            else:
                opts[arg[5:]] = argv[i]
        else:
            return None, None
        i += 1
    return None, None


def _version(name):
    try:
        from importlib import metadata
        return metadata.version(name)
    except Exception:  # noqa: BLE001 - any failure means unknown
        return 'unknown'


def _wrap_setup_symbol_server(state):
    from ghidriff import ghidra_diff_engine as engine_module
    engine = getattr(engine_module, 'GhidraDiffEngine', None)
    original = getattr(engine, 'setup_symbol_server', None)
    if not callable(original):
        return False
    try:
        signature = inspect.signature(original)
    except (TypeError, ValueError):
        return False
    if 'server_urls' not in signature.parameters:
        return False

    def setup_symbol_server(*args, **kwargs):
        state['setup_calls'] += 1
        bound = signature.bind(*args, **kwargs)
        bound.arguments['server_urls'] = []
        state['forced_empty'] = True
        return original(*bound.args, **bound.kwargs)

    engine.setup_symbol_server = setup_symbol_server
    return True


def _handshake(mode):
    return f"PT-LAUNCHER/1 mode={mode} servers={'unknown' if mode == 'online' else 0}"


def _write_report(path, state, opts):
    report = {'contract': CONTRACT, 'mode': opts['mode'], 'ghidriff_version': _version('ghidriff'),
              'server_urls_forced_empty': state['forced_empty'], 'setup_calls': state['setup_calls'],
              'pdbs_staged': list(opts['staged']), 'python': sys.version.split()[0],
              'handshake': _handshake(opts['mode'])}
    tmp = path + '.tmp'
    with open(tmp, 'w', encoding='utf-8') as out:
        json.dump(report, out, sort_keys=True)
    os.replace(tmp, path)


def _delegate(rest):
    sys.argv = ['ghidriff'] + rest
    try:
        from ghidriff.__main__ import main as upstream_main
    except ImportError:
        import runpy
        runpy.run_module('ghidriff', run_name='__main__')
        return 0
    result = upstream_main()
    return result if isinstance(result, int) else 0


def main(argv):
    opts, rest = _parse(argv)
    if opts is None or opts['mode'] not in MODES or not opts['report'] or not rest:
        return _fail('PT-SYMBOL-MODE', 'usage: ptlaunch.py --pt-mode M --pt-report P -- <ghidriff args>', EX_USAGE)
    if opts['mode'] == 'online' and not opts['allow_servers']:
        return _fail('PT-SYMBOL-NETWORK-REFUSED', 'online mode requires --pt-allow-servers', EX_USAGE)
    if opts['mode'] != 'online' and not os.environ.get('XDG_CONFIG_HOME'):
        return _fail('PT-SYMBOL-LAUNCHER-INCOMPATIBLE', 'XDG_CONFIG_HOME must name a per-run settings directory',
                     EX_INCOMPATIBLE)
    state = {'setup_calls': 0, 'forced_empty': False}
    if opts['mode'] == 'local':
        try:
            hooked = _wrap_setup_symbol_server(state)
        except ImportError:
            hooked = False
        if not hooked:
            return _fail('PT-SYMBOL-LAUNCHER-INCOMPATIBLE',
                         'GhidraDiffEngine.setup_symbol_server hook is missing or has another shape', EX_INCOMPATIBLE)
    sys.stdout.write(_handshake(opts['mode']) + '\n')
    sys.stdout.flush()
    status = 0
    try:
        status = _delegate(rest)
    except SystemExit as exc:
        status = exc.code if isinstance(exc.code, int) else (0 if exc.code is None else 1)
    finally:
        _write_report(opts['report'], state, opts)
    return status


if __name__ == '__main__':
    sys.exit(main(sys.argv[1:]))
