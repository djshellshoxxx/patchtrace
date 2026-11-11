import time
from patchtrace.strings.cues import cues_for, _FORMAT
for name,s in {'pct0':'%'+'0'*20000, 'pctpct':'%0'*10000, 'dash':'%'+'-0'*10000+'!', 'space':'%'+' 0'*10000,'url':'http://'+'a'*20000,'rel':'a.'*10000+'\\','abs':'/a'*10000+'!'}.items():
    t=time.time(); cues_for(s); print(name, len(s), '%.2fs'%(time.time()-t))
