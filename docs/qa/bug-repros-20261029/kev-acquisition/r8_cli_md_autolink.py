import sys, tempfile, io, contextlib
sys.path.insert(0,'tests')
from kev_helpers import document, entry, render
from patchtrace import cli
d = tempfile.mkdtemp(); p = d+'/c.json'; open(p,'wb').write(render(document([entry(1)])))
out = io.StringIO()
with contextlib.redirect_stdout(out):
    code = cli.main(['kev','lookup','https://evil.example/login','www.evil.example','a@evil.example','CVE-2098-00001','--catalog',p,'--md'])
print(code); print('\n'.join(l for l in out.getvalue().splitlines() if l.startswith('| ') ))
from patchtrace.kev.report import escape_md
print('report.escape_md:', escape_md('https://evil.example/login'), escape_md('www.evil.example'), escape_md('a@evil.example'))
