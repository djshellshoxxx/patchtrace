import sys, tempfile, pathlib
sys.path[:0] = [__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'tests'), __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'src')]
from search_builders import make_service
from patchtrace.search.service import SearchService
from patchtrace.search.query import parse_query
from patchtrace.search.contracts import SearchRequest
tmp = pathlib.Path(tempfile.mkdtemp())
svc = make_service(tmp/'p')   # FormatLine has sig 'int FormatLine(int v)'
s = SearchService(svc, tmp/'cache')
for q in ['FormatLine in:signature', '"zzz nomatch" in:signature', 'FormatLine -int in:signature']:
    r = s.search(SearchRequest(plan=parse_query(q)))
    print(repr(q), '->', r.status, [h.evidence[0].title for h in r.hits])
