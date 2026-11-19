# Frozen consolidation evidence

The archive preserves complete paginated branch/PR observations, per-baseline
ancestry and patch residue, conflict paths, check/status/review snapshots,
historical focal review references, selective-port dependency maps, open-issue
bodies and independent combined controls. Its manifest binds every member.

Dates and source identities inside the records govern their scope. The original
317-branch snapshot precedes PR #318 and the stable publication. Historical
review or green check data do not certify a new source. No external worker
activity is inferred from branch age. No branch is deleted by this report.

`stable-combined.xml` records 145 focused passes at local `45d460ca`.
`native-harness-independent.xml` records the integrating reviewer’s 21 harness
controls at `87aebb19`; it is not real Ghidriff/native qualification. An earlier
root command named absent workflow test files and ran no tests.

Read without extracting arbitrary paths, for example:

```python
import json, zipfile
with zipfile.ZipFile("docs/audits/consolidation-20261119/inventory-and-integration-evidence.zip") as archive:
    branches = json.loads(archive.read("branch-residue.json"))
print(branches["baselines"])
```

Full historical QA, current feature receipts and the five audit records remain
in the repository. See `../final-consolidation-report.md` for operation updates.
