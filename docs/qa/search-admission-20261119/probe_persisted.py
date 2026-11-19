"""Persisted-row correction of the independent search probe; original file is preserved."""
from contextlib import redirect_stderr, redirect_stdout
from io import StringIO
import json
import os
from pathlib import Path
import subprocess
from tempfile import TemporaryDirectory

from test_capa_cli import stored_project
from patchtrace import cli
from patchtrace.enrichment.storage import EnrichmentStore
from patchtrace.intelligence.tools import cli as tools_cli
from patchtrace.intelligence.tools.store import ToolStore
from patchtrace.search import wiring
from patchtrace.service import ProjectService

for name in tools_cli.ENV.values():
    os.environ.pop(name, None)

def search(root, cache):
    out, err = StringIO(), StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = cli.main(['search',str(root),'--query','write file','--rebuild','--json','--cache-dir',str(cache)])
    result = json.loads(out.getvalue())['result']
    evidence = [e for hit in result['hits'] for e in hit['evidence']]
    return {'exit':code,'newer_capa_hits':sum(e['group']=='tool:capa:newer' for e in evidence),
            'newer_coverage':next(r for r in result['coverage'] if r['group']=='tool:capa:newer')}

cases=[]
with TemporaryDirectory(prefix='patchtrace-search-guard-') as directory:
    base=Path(directory)
    for name,column,value in [('stale-run','stale',1),('foreign-run-project','project_id','foreign-authored-project')]:
        folder=base/name
        folder.mkdir()
        with redirect_stdout(StringIO()), redirect_stderr(StringIO()):
            root=stored_project(folder)
        before=search(root,folder/'cache')
        with ProjectService.open(root) as service:
            original=wiring.snapshot_sources(service)
            store=ToolStore(EnrichmentStore(service.store),service.root,service.project.id,service.project.revision)
            run,_=store.latest('capa','newer')
            if column=='stale':
                service.store.connection.execute('UPDATE enrichment_entries SET stale=? WHERE id=?',(value,run.run_id))
            else:
                service.store.connection.execute('UPDATE enrichment_entries SET project_id=? WHERE id=?',(value,run.run_id))
            after=wiring.snapshot_sources(service,original)
            selected=next(s for s in after.extra_specs() if s.group=='tool:capa:newer')
            admission={'snapshot_rebuilt':after is not original,'buildable':selected.buildable,
                       'status':selected.status,'comparable':after.comparable('capa')}
            service.store.connection.commit()
        with ProjectService.open(root) as reopened:
            persisted = reopened.store.connection.execute(
                f'SELECT {column} FROM enrichment_entries WHERE id=?', (run.run_id,)).fetchone()
            assert persisted == (value,), (name, persisted, value)
        cases.append({'case':name,'before':before,'persisted_after_close':persisted == (value,),
                      'admission_after':admission,'after':search(root,folder/'cache')})
print(json.dumps({'source':subprocess.check_output(['git','rev-parse','HEAD'],text=True).strip(),
                  'wiring_source':str(Path(wiring.__file__).resolve()),'cases':cases},indent=2))
