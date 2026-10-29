import os, sqlite3, tempfile
from pathlib import Path
from patchtrace.kbcorrelation.store import WorkspaceStore, KbcStoreError
tmp = Path(tempfile.mkdtemp()); os.chdir(tmp)
WorkspaceStore(Path('ws')).close()                       # create schema v1 (relative path)
c = sqlite3.connect('ws/kbc.sqlite3'); c.execute('PRAGMA user_version=2'); c.commit(); c.close()   # "newer client" store
for label, root in (('absolute', tmp/'ws'), ('relative', Path('ws'))):
    try:
        s = WorkspaceStore(root); print(label, 'opened read_only =', s.read_only); s.close()
    except KbcStoreError as e: print(label, 'KbcStoreError', e.code)
    except Exception as e: print(label, 'UNHANDLED', type(e).__name__, e)
