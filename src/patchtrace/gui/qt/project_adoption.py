"""Transactional GUI project adoption; preserve the original open service on failure."""
from __future__ import annotations


def adopt_project(window, service):
    previous = window.service
    recent_state = {key: window.settings.value(key) for key in ('recent/project', 'recent/projects')}
    try:
        if previous is not service:
            window._stop_inspection()
        window.service = service
        window.refresh()
        window.settings.setValue('recent/project', str(service.root))
        recent = window.settings.value('recent/projects', [], type=list)
        recent = [str(service.root), *[path for path in recent if path != str(service.root)]]
        window.settings.setValue('recent/projects', recent[:8])
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
