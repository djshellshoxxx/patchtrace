import sys, shutil, pathlib
from patchtrace.service import ProjectService
d = pathlib.Path(sys.argv[1]); shutil.rmtree(d, ignore_errors=True); d.mkdir(parents=True)
with ProjectService.sample(d/'case') as s: print(s.project.id)
