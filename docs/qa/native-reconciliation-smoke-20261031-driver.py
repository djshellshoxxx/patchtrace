from __future__ import annotations
import hashlib, importlib.metadata, json, platform, shutil, subprocess, threading, time
from pathlib import Path
from patchtrace.backend import BackendConfig, run_comparison, redact_log
from patchtrace.service import ProjectService
from patchtrace.unified import pipeline, store
from patchtrace.unified.compute import MATCH_POLICY_VERSION
from patchtrace.unified.registry import REGISTRY
from patchtrace.unified.ir.place import place_ir
from tools.live_unified_check import Side
ROOT=Path('/workspace/work/native-smoke-v2');INPUTS=ROOT/'inputs'
def digest(p):
 with Path(p).open('rb') as f:return hashlib.file_digest(f,'sha256').hexdigest()
repo=Path('/workspace/work/patchtrace-semantic')
config=BackendConfig('/workspace/work/patchtrace-native-venv/bin/python', '/workspace/work/native-runtime/ghidra/ghidra_12.0.4_PUBLIC',300,java_home=str(Path(shutil.which('java')).resolve().parents[1]),restrict_env=True,no_cache=True,retain_gzf=True,symbol_mode='off',force_identical_diff=True)
receipt={'source_commit':subprocess.check_output(['git','rev-parse','HEAD'],cwd=repo,text=True).strip(),'dirty_paths':subprocess.check_output(['git','diff','--name-only'],cwd=repo,text=True).splitlines(),'platform':platform.platform(),'versions':{k:importlib.metadata.version(k) for k in ('ghidriff','pyghidra','JPype1','ziglang')},'ghidriff_revision':'4f5d895fcbb1eacd65efd81145922c15bb7e741d','ghidra_archive_sha256':digest('/workspace/work/native-runtime/ghidra.zip'),'source_inputs':{p.name:{'sha256':digest(p),'text':p.read_text()} for p in sorted(INPUTS.glob('*.c'))},'compile_commands':json.loads((INPUTS/'compile-commands.json').read_text()),'cases':[],'scope':'Authored exported-name-visible one-function Linux native smoke. No target executed; no Tier R, held-out, BinDiff, Windows, air-gap or full G-U acceptance claim.'}
receipt['policies']={'matching':MATCH_POLICY_VERSION,'channels':dict(REGISTRY.channel_versions),'proofs':dict(REGISTRY.proof_versions)}
receipt['compiler_binary_sha256']=digest(Path(importlib.metadata.distribution('ziglang').locate_file('ziglang/zig')))
failed=False
for name,oldname,newname,expected in [('bounds','bounds-old','bounds-new','changed'),('signed-long','long-old','long-new','changed'),('float','float-old','float-new','changed'),('exponent','exponent-old','exponent-new','changed'),('identical','bounds-old','bounds-old','unchanged')]:
 started=time.monotonic();entry={'name':name,'expected':expected,'status':'running'};receipt['cases'].append(entry)
 service=None;sides={}
 try:
  old,new=INPUTS/(oldname+'.dll'),INPUTS/(newname+'.dll')
  entry.update(older_sha256=digest(old),newer_sha256=digest(new))
  service=ProjectService.create(old,new,name,ROOT/'projects'/name)
  raw,run=run_comparison(config,service.project,service.root,threading.Event(),lambda e:None)
  entry.update(backend_status=run.status,run_id=run.id,backend_error=run.error,settings=run.settings)
  if run.status!='completed':raise RuntimeError(f'Native backend did not complete: {run.status}: {run.error}; retained {raw}')
  service.apply_analysis(raw,run)
  entry['raw_sha256']=digest(raw)
  entry['backend_functions']=[{'category':m.category,'older':[{'name':f.name,'address':f.address,'code':f.code} for f in m.older],'newer':[{'name':f.name,'address':f.address,'code':f.code} for f in m.newer]} for m in service.project.matches]
  gzf=service.root/'runs'/run.id/'unified'/'gzf';work=service.root/'smoke-extraction';work.mkdir()
  entry['gzf']={};entry['ir']={}
  for label,dll,other in [('older',old,new),('newer',new,old)]:
   sides[label]=Side(label,dll,digest(other),config,work)
   program=gzf/(label+'.gzf');entry['gzf'][label]={'sha256':digest(program),'bytes':program.stat().st_size}
   built=sides[label].run('gzf',program,digest(program));place_ir(service.root,run.id,built['directory'])
   entry['ir'][label]={'content_digest':built['manifest'].content_digest,'functions':built['manifest'].counts.functions}
  pipeline.run_unified(service,pipeline.UnifiedOptions(backend=config,timeout_s=600))
  loaded=pipeline.load_current(service,pipeline.make_plan(service));assert loaded is not None
  facts={f.row_id:f for f in store.read_facts(loaded.directory,loaded.manifest)}
  rows=[]
  for r in store.read_rows(loaded.directory,loaded.manifest):
   f=facts.get(r.row_id)
   rows.append({'older':[(s.name,s.rva) for s in r.older],'newer':[(s.name,s.rva) for s in r.newer],'decision':r.decision,'verdict':f.verdict if f else None,'proof':f.proof if f else None,'classes':[d.cls for d in f.deltas] if f else [],'channels':dict(f.channels) if f else {},'eh':f.eh if f else None})
  entry.update(result_id=loaded.manifest.result_id,manifest_status=loaded.manifest.status,rows=rows)
  paired=[r for r in rows if r['older'] and r['newer']]
  assert paired,'no paired exported function'
  if expected=='unchanged':assert all(r['verdict']=='unchanged' for r in paired),paired
  else:assert all(r['verdict'] in ('material','review','unknown') for r in paired),paired
  assert digest(old)==entry['older_sha256'] and digest(new)==entry['newer_sha256']
  entry['status']='passed'
 except Exception as exc:
  failed=True;entry.update(status='failed',error=redact_log(f'{type(exc).__name__}: {exc}',4000))
 finally:
  for side in sides.values():side.close()
  if service is not None:service.close()
  entry['elapsed_seconds']=round(time.monotonic()-started,2)
  (ROOT/'receipt.json').write_text(json.dumps(receipt,indent=2,default=str)+'\n')
  print(name,entry['status'],entry.get('error',''),flush=True)
raise SystemExit(1 if failed else 0)
