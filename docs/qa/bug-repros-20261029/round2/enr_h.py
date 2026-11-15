import sys, tempfile, pathlib
sys.path[:0] = [__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'tests'), __import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'src')]
from search_synergy_builders import attention, extra_specs, make_project
from patchtrace.search.service import SearchService
from patchtrace.search.query import parse_query
from patchtrace.search.contracts import SearchRequest
def make(tmp=None):
    tmp = pathlib.Path(tmp or tempfile.mkdtemp())
    svc = make_project(tmp/'project')
    return SearchService(svc, tmp/'cache', attention=attention, extra_specs=extra_specs), svc
def search(s, q, **kw):
    mode = kw.pop('mode','auto')
    return s.search(SearchRequest(plan=parse_query(q, mode=mode), **kw))
