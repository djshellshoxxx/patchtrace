"""`patchtrace profile list|show|validate|save|delete` (docs/specs/cli-profile-doctor-runtime.md section 2). No Qt.

A thin dispatcher over `enrichment.profiles`: the strict `profile/1` model, the 64 KiB read limit, the atomic write and
the name rules are that module's and are not repeated here. Output is the `enrichment-cli/1` envelope with a
`profile-cli/1` result. Exit codes: 0 done; 2 invalid arguments or a refused profile file or name; 3 the directory
cannot be written, or `list` met an invalid stored file (partial); 4 `delete` of a name that is not stored.

A profile file is untrusted input: it must be a regular file, it is read only through `profiles.load_file`, and the
refusal reason (which can quote a field name from the file) is cut to MAX_REASON characters.
"""
from __future__ import annotations

import re
from argparse import ArgumentParser, Namespace
from pathlib import Path
from threading import Event

from ..cli_commands import ENVIRONMENT, NO_RESULTS, OK, RUNTIME, CliError, emit
from . import profiles
from .profiles import DEFAULT_NAME, AnalysisProfile, ProfileError, ProfileStore, profile_digest

SUMMARY = 'analysis profiles: list, show, validate, save, delete'
CONTRACT = 'profile-cli/1'
MAX_LISTED = 1000   # stored profiles read by `list`; each read is bounded by profiles.MAX_FILE_BYTES
MAX_REASON = 400    # characters of an untrusted refusal reason that reach stderr or the envelope


def add_parser(sub) -> ArgumentParser:
    parser = sub.add_parser('profile', help=SUMMARY)
    actions = parser.add_subparsers(dest='action', required=True)

    def leaf(name: str, help_: str) -> ArgumentParser:
        item = actions.add_parser(name, help=help_)
        item.set_defaults(command_label=f'profile {name}')
        item.add_argument('--profiles-dir', type=Path, default=None, metavar='DIR',
                          help='profile folder (default: the folder the desktop uses)')
        item.add_argument('--json', action='store_true', help='emit exactly one JSON document on stdout')
        return item

    leaf('list', 'list the built-in default and every stored profile with its digest')
    leaf('show', 'print one profile and its digest').add_argument(
        'profile', metavar='NAME|FILE', help='a stored name, or a profile JSON file (ends in .json or has a separator)')
    leaf('validate', 'check a profile JSON file without storing it').add_argument('file', type=Path, metavar='FILE')
    save = leaf('save', 'validate a profile JSON file and store it')
    save.add_argument('file', type=Path, metavar='FILE')
    save.add_argument('--name', metavar='NAME', help='store it under this name instead of the name in the file')
    save.add_argument('--force', action='store_true', help='replace a stored profile of the same name')
    delete = leaf('delete', 'delete one stored profile (needs --confirm)')
    delete.add_argument('name', metavar='NAME')
    delete.add_argument('--confirm', action='store_true', help='required: really delete the stored profile')
    return parser


def run(args: Namespace, cancel: Event) -> int:
    directory = Path(args.profiles_dir) if args.profiles_dir is not None else profiles.default_profiles_dir()
    if directory.exists() and not directory.is_dir():
        raise CliError(ENVIRONMENT, f'the profiles directory {directory} is not a directory')
    return _LEAVES[args.action](args, ProfileStore(directory))


def _clip(text: str) -> str:
    return text if len(text) <= MAX_REASON else text[:MAX_REASON] + '...'


def is_file_argument(value: str) -> bool:
    """The rule of `profiles.resolve` (so of `--profile NAME|FILE`): a path-like value is a file, anything else a name."""
    return value.endswith('.json') or '/' in value or '\\' in value


def _load(path: Path) -> AnalysisProfile:
    if not path.is_file():  # a directory, device or pipe is never opened
        raise CliError(ENVIRONMENT, f'{_clip(path.name)!r} is not an existing regular file')
    try:
        return profiles.load_file(path)
    except ProfileError as exc:
        raise CliError(ENVIRONMENT, f'invalid profile: {_clip(str(exc))}') from None


def _stored_as(store: ProfileStore, name: str) -> str | None:
    """The stored name that equals `name` when case is ignored (what collides on Windows), or None."""
    return next((stored for stored in store.names() if stored.casefold() == name.casefold()), None)


def _row(profile: AnalysisProfile) -> dict:
    return {'name': profile.name, 'digest': profile_digest(profile), 'builtin': profile is profiles.DEFAULT_PROFILE}


def _list(args: Namespace, store: ProfileStore) -> int:
    names = store.names()
    rows, invalid = [_row(profiles.DEFAULT_PROFILE)], []
    for name in names[:MAX_LISTED]:
        if name == DEFAULT_NAME:  # ProfileStore.get would answer with the built-in and hide the file
            invalid.append('default.json: the name is reserved for the built-in profile; the file is ignored')
            continue
        try:
            rows.append(_row(store.get(name)))
        except ProfileError as exc:
            invalid.append(_clip(f'{name}.json: {exc}'))
    truncated = len(names) > MAX_LISTED
    warnings = [f'invalid profile file: {reason}' for reason in invalid]
    if truncated:
        warnings.append(f'only the first {MAX_LISTED} of {len(names)} stored profiles were read')
    partial = bool(invalid) or truncated
    result = {'contract': CONTRACT, 'profiles_dir': str(store.directory), 'profiles': rows, 'invalid': invalid,
              'truncated': truncated}
    text = '\n'.join(f'{row["name"]}  {row["digest"]}' + ('  (built-in)' if row['builtin'] else '') for row in rows)
    emit(args, 'profile list', 'partial' if partial else 'complete', result, warnings, text)
    return RUNTIME if partial else OK


def _show(args: Namespace, store: ProfileStore) -> int:
    if is_file_argument(args.profile):
        profile, source = _load(Path(args.profile)), 'file'
    else:
        try:
            profile = store.get(args.profile)
        except ProfileError as exc:
            raise CliError(ENVIRONMENT, f'invalid profile: {_clip(str(exc))}') from None
        source = 'built-in' if profile is profiles.DEFAULT_PROFILE else 'stored'
    digest = profile_digest(profile)
    result = {'contract': CONTRACT, 'source': source, 'name': profile.name, 'digest': digest,
              'profile': profile.model_dump(mode='json')}
    emit(args, 'profile show', 'complete', result, [], f'{profiles.dumps(profile)}digest: {digest}')
    return OK


def _validate(args: Namespace, store: ProfileStore) -> int:
    profile = _load(args.file)
    reserved = profile.name.casefold() == DEFAULT_NAME
    existing = _stored_as(store, profile.name)
    warnings = []
    if reserved:
        warnings.append("the name 'default' belongs to the built-in profile; `profile save` needs --name NAME")
    elif existing is not None:
        warnings.append(f'a profile named {existing!r} is already stored; `profile save` needs --force to replace it')
    digest = profile_digest(profile)
    result = {'contract': CONTRACT, 'valid': True, 'name': profile.name, 'digest': digest, 'reserved': reserved,
              'name_taken': existing is not None}
    emit(args, 'profile validate', 'complete', result, warnings, f'valid profile {profile.name} (digest {digest})')
    return OK


def _save(args: Namespace, store: ProfileStore) -> int:
    profile = _load(args.file)
    if args.name is not None:
        try:
            profile = profiles.build(profile.model_dump(mode='json') | {'name': args.name})
        except ProfileError as exc:
            raise CliError(ENVIRONMENT, f'invalid --name: {_clip(str(exc))}') from None
    existing = _stored_as(store, profile.name)
    if existing is not None and not args.force:
        raise CliError(ENVIRONMENT, f'a profile named {existing!r} already exists; pass --force to replace it')
    try:
        store.save(profile, replaces=existing)  # `replaces` also removes a stored name that differs only in case
    except ProfileError as exc:
        raise CliError(ENVIRONMENT, _clip(str(exc))) from None
    except OSError as exc:
        raise CliError(RUNTIME, f'cannot write the profile: {exc.strerror or type(exc).__name__}') from None
    path = store.directory / f'{profile.name}.json'
    result = {'contract': CONTRACT, 'name': profile.name, 'digest': profile_digest(profile), 'path': str(path),
              'replaced': existing is not None}
    emit(args, 'profile save', 'complete', result, [], f'saved profile {profile.name} to {path}')
    return OK


def _delete(args: Namespace, store: ProfileStore) -> int:
    name = args.name
    if len(name) > 64 or not re.fullmatch(profiles.NAME_PATTERN, name):
        raise CliError(ENVIRONMENT, _clip(f'invalid profile name {name!r}'))
    if name == DEFAULT_NAME:
        raise CliError(ENVIRONMENT, 'the built-in default profile cannot be deleted')
    if not args.confirm:
        raise CliError(ENVIRONMENT, f'nothing was deleted: this removes the stored profile {name!r} from '
                       f'{store.directory}; pass --confirm to do it')
    if name not in store.names():
        other = _stored_as(store, name)
        hint = [f'a profile named {other!r} is stored; names are matched exactly'] if other is not None else []
        emit(args, 'profile delete', 'no-results', {'contract': CONTRACT, 'name': name, 'deleted': False}, hint,
             f'no stored profile is named {name!r}')
        return NO_RESULTS
    try:
        store.delete(name)
    except ProfileError as exc:
        raise CliError(ENVIRONMENT, _clip(str(exc))) from None
    except OSError as exc:
        raise CliError(RUNTIME, f'cannot delete the profile: {exc.strerror or type(exc).__name__}') from None
    emit(args, 'profile delete', 'complete', {'contract': CONTRACT, 'name': name, 'deleted': True}, [],
         f'deleted profile {name}')
    return OK


_LEAVES = {'list': _list, 'show': _show, 'validate': _validate, 'save': _save, 'delete': _delete}
