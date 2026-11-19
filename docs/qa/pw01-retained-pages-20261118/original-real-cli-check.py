from __future__ import annotations
import hashlib,json,os,pathlib,subprocess,tempfile,time
root=pathlib.Path("/workspace/scratch/e83fbf4505c3")
checkout=root/"qualification-pw01-csv"
python="/workspace/scratch/3a6632a6e5ff/venv/bin/python"
source=root/"pw01-live-evidence/20261118T074241Z-e077563/proxy-csv-raw.csv"
output=root/"pw01-real-cli-c023dec3"
output.mkdir(exist_ok=False)
assert hashlib.sha256(source.read_bytes()).hexdigest()=="b327eb5d0f8d7a0d6a9c8c2d1a7af1df134bc2a54c3e0da2eff0fb335547a627"
report={"kind":"pw01-real-cli-qualification/1","source_commit":"c023dec36a464c3e7e1a8689f52a22263f0c24c5","source_tree":"d390d0f2f77b34cdb0a265b9bfb33e06d4428e09","raw_sha256":hashlib.sha256(source.read_bytes()).hexdigest(),"operations":[],"pages":[],"target_executed":False,"network_requested":False}
env=dict(os.environ,PYTHONPATH="src",QT_QPA_PLATFORM="offscreen")
with tempfile.TemporaryDirectory(prefix="pw01-cli-real-",dir=root) as temporary:
    def run(label,args,code):
        argv=[python,"-m","patchtrace","kb","inventory",*args,"--workspace",str(pathlib.Path(temporary)/"ws"),"--json"]
        before=time.monotonic()
        with (output/(label+".stdout.json")).open("xb") as stdout,(output/(label+".stderr.txt")).open("xb") as stderr:
            completed=subprocess.run(argv,cwd=checkout,env=env,stdout=stdout,stderr=stderr,timeout=90,check=False)
        elapsed=time.monotonic()-before
        raw=(output/(label+".stdout.json")).read_bytes()
        report["operations"].append({"label":label,"argv":argv,"exit_code":completed.returncode,"expected_exit_code":code,"seconds":round(elapsed,3),"stdout_sha256":hashlib.sha256(raw).hexdigest(),"stdout_bytes":len(raw)})
        assert completed.returncode==code,(label,completed.returncode)
        document=json.loads(raw)
        assert not document.get("error"),label
        return document
    original=run("01-import",["import",str(source),"--kb","KB5036893","--offline"],3)
    original_id=original["result"]["import_id"]
    original_source=original["result"]["inventory"]["source"]
    assert original["result"]["inventory"]["accepted_count"]==5000
    before=run("02-original-show",["show",original_id,"--limit","1"],3)
    assert before["result"]["entries"][0]["architecture"]=="arm64"
    for page,count in enumerate((5000,5000,5000,3761),1):
        retained=run(f"{page+2:02d}-retain-{page}",["retain",original_id,"--architecture","amd64","--page",str(page)],3)
        item=retained["result"]["inventory"]
        assert item["source"]==original_source and item["retention"]=={"architecture":"amd64","page":page}
        assert item["accepted_count"]==count and item["matching_count"]==18761 and item["scan_complete"]
        new_id=retained["result"]["import_id"]
        shown=run(f"{page+6:02d}-show-{page}",["show",new_id,"--limit","1"]+(["--name","aarsvc.dll"] if page in (1,4) else []),3)
        entry=shown["result"]["entries"][0]
        assert entry["architecture"]=="amd64"
        witness=None
        if page in (1,4):
            witness=next(w for w in shown["result"]["inventory"]["conflict_witnesses"] if w["conflict_group"]==entry["conflict_group"])
            assert (witness["first"]["logical_record"],witness["second"]["logical_record"])==(24355,41380)
        report["pages"].append({"page":page,"import_id":new_id,"inventory_id":item["inventory_id"],"retained":count,"matching":item["matching_count"],"excluded":item["excluded_count"],"omitted":item["omitted_count"],"scan_complete":item["scan_complete"],"witness":witness})
    after=run("11-original-show-again",["show",original_id,"--limit","1"],3)
    assert before==after
    repeated=run("12-repeat-page1-from-page4",["retain",new_id,"--architecture","amd64","--page","1"],3)
    assert repeated["result"]["already_present"] and repeated["result"]["import_id"]==report["pages"][0]["import_id"]
    listed=run("13-list",["list"],0)
    assert listed["result"]["total"]==5
    report.update(status="PASS",original_import_unchanged=True,source_provenance_unchanged=True,idempotent=True,total_imports=5)
report["raw_unchanged"]=hashlib.sha256(source.read_bytes()).hexdigest()==report["raw_sha256"]
(output/"qualification.json").write_text(json.dumps(report,indent=2)+"\n")
print(json.dumps({"status":report["status"],"operations":len(report["operations"]),"pages":[p["retained"] for p in report["pages"]],"output":str(output)}),flush=True)
