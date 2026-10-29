import sys
sys.path.insert(0,'tests')
from kev_helpers import document, entry, parse_document, at
from patchtrace.kev.join import lookup, split_cve_ids
from patchtrace.kev.view_model import KevColumnProvider
cat = parse_document(document([entry(1)]))
now = at(2098,2,2)
for raw in ['CVE-2098-00001​', 'CVE-2098-00001\x00', '‮CVE-2098-00001', 'cve-2098-00001', 'CVE-2098-00001 ']:
    row = lookup(cat, [raw], now)[0]
    cell = KevColumnProvider(cat, now).cell(raw)
    print(repr(raw), '->', row.status, repr(row.cve_id), '| cell:', cell.state, repr(cell.cve))
print(split_cve_ids('cve-2098-00001, CVE-2098-00001 cve-2098-00002'))
