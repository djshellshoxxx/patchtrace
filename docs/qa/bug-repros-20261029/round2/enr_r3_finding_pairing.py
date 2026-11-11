import sys, tempfile, pathlib
sys.path[:0] = [__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'tests'), __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'src')]
from search_builders import make_service
from patchtrace.search.service import SearchService
from patchtrace.search.query import parse_query
from patchtrace.search.contracts import SearchRequest
tmp = pathlib.Path(tempfile.mkdtemp())
svc = make_service(tmp/'p')   # finding fnd-1 summary 'Added length validation', match_ids ['m-mod'] (modified)
s = SearchService(svc, tmp/'cache')
for q in ['length validation', 'length validation is:modified', 'length validation scope:changed']:
    r = s.search(SearchRequest(plan=parse_query(q)))
    print(q, '->', r.status, [(h.evidence[0].kind, h.change_class, h.expansion and h.expansion.category) for h in r.hits])
r = s.search(SearchRequest(plan=parse_query('bounds check is:modified')))
print('note control ->', [(h.evidence[0].kind, h.change_class, h.expansion and h.expansion.category) for h in r.hits])
