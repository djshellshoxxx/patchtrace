import sys, tempfile, pathlib
sys.path[:0] = [__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'tests'), __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'src')]
from search_synergy_builders import attention, make_project, _spec
from patchtrace.search.segment import SegmentDoc
from patchtrace.search.service import SearchService
from patchtrace.search.query import parse_query
from patchtrace.search.contracts import SearchRequest
def extra(_r):
    exact = SegmentDoc('advisory', None, 'CVE-2099-10001', 'CVE-2099-10001', 0, text_title='CVE-2099-10001', text_body='the real one')
    other = SegmentDoc('advisory', None, 'CVE-2099-100011', 'CVE-2099-100011', 1, text_title='CVE-2099-100011', text_body='related to CVE-2099-10001 but a different vulnerability')
    return (_spec('adv', ('advisory',), None, [exact, other]),)
tmp = pathlib.Path(tempfile.mkdtemp()); svc = make_project(tmp/'p')
s = SearchService(svc, tmp/'cache', attention=attention, extra_specs=extra)
r = s.search(SearchRequest(plan=parse_query('CVE-2099-10001')))
for h in r.hits:
    e = h.evidence[0]; print(h.tier, e.title, [(x.code, x.field) for x in e.reasons])
