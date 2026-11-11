from types import SimpleNamespace as NS
from patchtrace.kbcorrelation.service import KbService
mk=lambda pid,g='A': NS(pair_id=pid, grade=g)
found=[NS(pairs=(mk('ab'+'1'*62), mk('ab'+'2'*62), mk('cd'+'3'*62)))]
for pfx in ('ab','','a'):
    p=KbService._pick_pair(found, pfx)
    print(repr(pfx), '->', p.pair_id[:4], '(2 pairs match' if pfx!='cd' else '', ')')
