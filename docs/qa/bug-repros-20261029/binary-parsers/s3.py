import sys, hashlib
sys.path.insert(0,'tests')
from strings_pe import builtin_table
from patchtrace.strings.sources import SourceRow
from patchtrace.strings.links import link_strings, SideFunctions
from patchtrace.intelligence.tools.normalize import FunctionPairing
from patchtrace.models import FunctionRecord, FunctionMatch
text='A long message that is quite long indeed for prefix'
sha=hashlib.sha256(text.encode()).digest()
rows=[SourceRow(sha,text,len(text),'static','ASCII',off,0x1000+off,None,None,None,None,'verified-bytes') for off in (0,100)]  # same string twice (FLOSS keeps duplicates)
t=builtin_table('older','a'*64,rows)
import inspect
print([f for f in FunctionRecord.model_fields])
rec=FunctionRecord(id='f1',artifact_id='a',run_id='r',name='main',address='0x1000',address_space='relative',
   code='void main(){ puts("A long message that is quite long..." /* TRUNCATED STRING LITERAL */); }')
m=FunctionMatch(id='m1',run_id='r',older=[rec],category='modified')
sf=SideFunctions.from_matches([m],'older',0,None)
try:
    r=link_strings({'older':t},pairing=FunctionPairing.empty(),functions={'older':sf},ghidra_group='g')
    print(r.links)
except Exception as e: import traceback; traceback.print_exc()
