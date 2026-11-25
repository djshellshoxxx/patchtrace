"""SQLite file URIs shared by project storage and verified backups."""
from pathlib import PurePath


def project_database_uri(path: PurePath) -> str:
    uri = path.as_uri()
    # SQLite normally rejects file://server authorities. Keep both leading UNC
    # separators inside the decoded filename passed to the Windows VFS.
    if not uri.startswith('file:///'):
        return 'file:%2F%2F' + uri.removeprefix('file://')
    return uri
