from __future__ import annotations
import csv, io, json, random
from patchtrace.kbcorrelation.inventory_contracts import InventoryContext, InventoryLimits, InventoryRetention
from patchtrace.kbcorrelation.inventory_csv import parse_inventory_page
context = InventoryContext(kb="KB5036893")
limits = InventoryLimits(max_entries=3)
pages = 0
for seed in range(80):
    rng = random.Random(seed)
    rows = [(f"part{rng.randrange(5)}.dll", f"1.2.3.{rng.randrange(3)}", str(rng.randrange(2) + 10), rng.choice(("amd64", "arm64", "unknown"))) for _ in range(23)]
    out = io.StringIO(newline="")
    writer = csv.writer(out)
    writer.writerow(("File name", "File version", "File size", "Architecture"))
    writer.writerows(rows)
    raw = out.getvalue().encode()
    for architecture in ("amd64", "arm64", "unknown", "all"):
        selected = [(i+2,row) for i,row in enumerate(rows) if architecture == "all" or row[3] in (architecture, "unknown")]
        actual_records = []
        for start in range(0,len(selected),3):
            policy = InventoryRetention(architecture=architecture, page=start//3+1)
            result = parse_inventory_page(raw,context,policy,limits=limits)
            expected = selected[start:start+3]
            assert result.scan_complete and not result.truncated
            assert result.records_scanned == 24
            assert result.matching_count == len(selected)
            assert result.excluded_count == len(rows)-len(selected)
            assert result.omitted_count == len(selected)-len(expected)
            assert [entry.reference.logical_record for entry in result.entries] == [record for record,_ in expected]
            actual_records.extend(entry.reference.logical_record for entry in result.entries)
            local_seen = {}
            for entry,(record,row) in zip(result.entries, expected, strict=True):
                group = [other for other in rows if (other[0],other[3]) == (row[0],row[3])]
                contradicts = len({other[1] for other in group}) > 1 or len({other[2] for other in group}) > 1
                assert ("CONFLICTING_METADATA" in entry.diagnostics) == contradicts
                assert (entry.state == "conflicted") == contradicts
                assert entry.duplicate_of == local_seen.get(row)
                local_seen.setdefault(row,entry.entry_id)
                if contradicts:
                    witness = next(x for x in result.conflict_witnesses if x.conflict_group == entry.conflict_group)
                    left,right = rows[witness.first.logical_record-2],rows[witness.second.logical_record-2]
                    assert (left[0],left[3]) == (right[0],right[3]) == (row[0],row[3])
                    index = {"version_components":1,"size_bytes":2}[witness.field]
                    assert left[index] != right[index]
            assert parse_inventory_page(raw,context,policy,limits=limits) == result
            pages += 1
        assert actual_records == [record for record,_ in selected]
print(json.dumps({"sources":80,"architecture_policies":4,"pages_verified":pages,"global_conflict_oracle":"PASS","all_source_claims_reachable":"PASS","deterministic_replay":"PASS"},sort_keys=True))
