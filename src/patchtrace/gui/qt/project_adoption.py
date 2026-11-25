"""Transactional GUI project adoption; preserve the original open service on failure."""
from __future__ import annotations


def project_path_hint(value: object) -> str:
    """Return a usable path string without probing the filesystem."""
    return value if isinstance(value, str) and '\x00' not in value else ''


def recent_projects(settings, *, newest: str | None = None, forget: str | None = None) -> list[str]:
    """Read at most eight distinct project paths in most-recent-first order."""
    paths = [newest] if newest else []
    # Read the stored type: Qt's conversion to a list can truncate a scalar path at a NUL.
    stored = settings.value('recent/projects')
    if isinstance(stored, str):
        stored = [stored]
    if not isinstance(stored, list | tuple):
        return paths
    for value in stored:
        path = project_path_hint(value)
        if path and path != forget and path not in paths:
            paths.append(path)
            if len(paths) == 8:
                break
    return paths


def adopt_project(window, service):
    previous = window.service
    recent_state = {key: window.settings.value(key) for key in ('recent/project', 'recent/projects')}
    try:
        if previous is not service:
            window._stop_inspection()
        window.service = service
        window.refresh()
        current = str(service.root)
        window.settings.setValue('recent/project', current)
        window.settings.setValue('recent/projects', recent_projects(window.settings, newest=current))
        window.refresh_recent()
    except BaseException:
        window.service = previous
        try:
            window._stop_inspection()
            for key, value in recent_state.items():
                if value is None:
                    window.settings.remove(key)
                else:
                    window.settings.setValue(key, value)
            window.refresh()
            window.refresh_recent()
        except Exception:
            window.logs.appendPlainText('Previous project retained; its view could not be refreshed.')
        finally:
            if previous is not service:
                service.close()
        raise
    if previous and previous is not service:
        previous.close()
