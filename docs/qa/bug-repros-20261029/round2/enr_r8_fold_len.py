import sys, unicodedata
sys.path[:0]=[__import__('os').path.join(__import__('os').path.dirname(__import__('os').path.abspath(__file__)), '../../../..', 'src')]
from patchtrace.search.normalize import fold
from patchtrace.search.query import parse_query
mx = max(((len(fold(chr(c))), c) for c in range(0x110000) if not 0xD800<=c<0xE000), key=lambda t:t[0])
print('max fold expansion', mx[0], hex(mx[1]))
# sequence effects: NFKC of a char then casefold, whole-string
for ch in ['ﷺ','ﷻ','ΐ','ᾀ','ﬃ','㎒']:
    print(hex(ord(ch)), len(fold(ch)))
for ch in ['ﷺ']:
    q = ch*250
    try: p = parse_query(q); print('ok', len(p.terms[0].fold))
    except Exception as e: print('RAISED', type(e).__name__, str(e)[:100])
# find worst: expansion of nfc-normalised single char across all chars where clean nfc is that char
worst=0
for c in range(0x110000):
    if 0xD800<=c<0xE000: continue
    ch=chr(c)
    if unicodedata.category(ch) in ('Cc','Cf','Cn','Co','Cs','Zl','Zp'): continue
    n=len(fold(unicodedata.normalize('NFC',ch)))
    worst=max(worst,n)
print('worst', worst)
