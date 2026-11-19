# Reviewed bootstrap pip transition

Source **0c004b6849c12e30eddc734f0242ec0753895eff**, tree
**5b9beec650b49542b35acca821c14270053a8cdc**. The explicit pip repair removes the
reported bootstrap advisories from both actual Linux product inventories while
retaining pip in the audited closure. Static scanning still fails with 79
diagnostics. Windows and integrated qualification remain open.

## Scope and source

Dedicated branch: `codex/scanner-bootstrap-20261118`; base is the fixed scanner
checkpoint `c48382a6af3562ed7fd729fba023ee96f555795a`. Only this follow-on's
commits are new: specification/red controls `f0e07d49`, implementation
`0c004b68`, and this QA checkpoint. The original six failed scan snapshots and
their sealed predecessor archive are unchanged.

The change is limited to the scanner helper, its contract and authored tests.
Workflow names, critical steps, release hold, application dependencies and
static detection policy are unchanged. No shared/system/user environment was
upgraded. Each new scanner/product environment records its original ensurepip
identity, inventory and pip-check before installing the reviewed pip wheel.

The selected pin is **pip 26.3**, released November 2, 2026. Official upstream
metadata requires Python >=3.10 and lists Python 3.12, matching this lane. Its
universal wheel has SHA-256
`f3b60b20ffaadd4415ed7957212a38ac63fa4c5fa375bd0f4a797777940fad13`.
The helper requires that exact hash and wheel origin, binary-only installation,
no dependency resolution, and a one-target pip installation report. A fresh
environment already using the pin is reinstalled with the same origin proof;
a newer/unrecognized bootstrap refuses rather than silently downgrading.

The bootstrap report is issued by the original pip version; its installed
target and immediate prepared inventory are pip 26.3. Final interpreter and
native environment ownership must still match the bootstrap. All subsequent
installation-report issuers and final installed/inspection pip versions must
be 26.3. The final product audit includes pip and every other non-owned package.
Missing, contradictory, wrong-hash, extra-target or failed transition evidence
blocks subsequent package installation and current qualification.

The lower-level installation API keeps its explicit historical behavior when
no transition is supplied: all installed/inspection/report/ensurepip versions
must agree. The current pipeline always requires transition receipts and pinned
requirements, so that compatibility path cannot qualify old evidence as a
current prepared run. The original six independent identity controls are
unchanged.

## Actual exact-source Linux results

| Profile | Audited product closure | pip remains included | Scanner and independent CLI validation |
| --- | ---: | --- | --- |
| Runtime + search/rules | 17 distributions | pip 26.3 | Both exit 0; zero reported vulnerabilities, skips or fixes |
| Packaging + dev/search/rules | 32 distributions | pip 26.3 | Both exit 0; zero reported vulnerabilities, skips or fixes |
| Static application source | — | Scanner bootstrap retained | Both exit 1; 79 untriaged diagnostics |

Each scanner and product environment records the actual **25.0.1 → 26.3**
transition. Comparing the complete final product inventories with their failed
`b61e1593` predecessors shows **pip is the only changed package version** in both
profiles. All other dependency names/versions remain the same. Nothing was
excluded or ignored to obtain the dependency results.

The static findings remain S608: 34, S105: 14, S110: 13, S101: 9, S310: 6,
S603: 1, S314: 1 and S108: 1. No static remediation or suppression is part of
this slice. These local results do not qualify a native Windows environment,
a separate frozen executable, external native tools, or publication.

## Verification

The specification and 31 failing controls preceded implementation. A further
malformed-hash control reproduced an uncontrolled type error and was repaired
to return a receipt refusal. Authored tests cover issuer/target separation,
required pinned hash and origin, missing/extra transition targets, changed
native environment/interpreter, newer bootstrap refusal, same-pin reinstall,
pip's continued inclusion, and refusal of complete predecessor receipts by the
current pipeline. Earlier authored positive fixtures now supply all real
transition fields; their assertions were retained. A positive call before each
mutated installation-provenance control confirms those negatives still test
the intended contradiction.

The exact-source affected gate reports **631 passed, 3 existing expected
failures**. The expected failures remain CODEX-1 action pinning, CODEX-5 pip
hashes and CODEX-6 corpus cache requirements. Whole-tree normal Ruff passes.
The full suite was not repeated; the predecessor's exit137 remains incomplete.

Root independently read the complete source/spec/test delta and ran the pinned
scanner/bootstrap tests with the unchanged six external identity controls:
**160 passed**. Root also checked literal source identity and revalidated all
three actual profiles: runtime and packaging accepted their complete data;
static correctly refused. `external-scanner-bootstrap-root-actual.json` records
root's raw-file hashes, and root's test log/JUnit are preserved separately.

## Primary advisory and pin evidence

The [PyPA advisory database](https://github.com/pypa/advisory-database) records
these fixed-version floors for the six distinct IDs observed in the original
failing inventories. The duplicated original service rows remain untouched.

| Advisory | Recorded fixed version | Primary record |
| --- | --- | --- |
| PYSEC-2026-1795 | 25.3 | [PyPA record](https://github.com/pypa/advisory-database/blob/main/vulns/pip/PYSEC-2026-1795.yaml) |
| PYSEC-2026-1796 | 26.0 | [PyPA record](https://github.com/pypa/advisory-database/blob/main/vulns/pip/PYSEC-2026-1796.yaml) |
| PYSEC-2026-2875 | 26.1 | [PyPA record](https://github.com/pypa/advisory-database/blob/main/vulns/pip/PYSEC-2026-2875.yaml) |
| PYSEC-2026-2876 | 26.1 | [PyPA record](https://github.com/pypa/advisory-database/blob/main/vulns/pip/PYSEC-2026-2876.yaml) |
| PYSEC-2026-196 | 26.1.2 | [PyPA record](https://github.com/pypa/advisory-database/blob/main/vulns/pip/PYSEC-2026-196.yaml) |
| PYSEC-2026-3721 | 26.2 | [PyPA record](https://github.com/pypa/advisory-database/blob/main/vulns/pip/PYSEC-2026-3721.yaml) |

Pin selection additionally used [pip's official changelog](https://pip.pypa.io/en/stable/news/),
the [26.3 project metadata](https://github.com/pypa/pip/blob/26.3/pyproject.toml),
[PyPI release page](https://pypi.org/project/pip/26.3/) and
[PyPI JSON](https://pypi.org/pypi/pip/26.3/json). The annotated
[tag reference](https://api.github.com/repos/pypa/pip/git/ref/tags/26.3) peels via
[this tag object](https://api.github.com/repos/pypa/pip/git/tags/a46183b0709ceefb8c1bd6c7b7b69c82a1b91411)
to `191854fba83d1c69534f974564af85632372d995`, matching the publishing commit
reported by PyPI. The GitHub signature-verification flag is false; no verified
tag-signature claim is made. Root independently checked the official PyPI
compatibility, hash and publishing-commit evidence.

These advisory/version observations do not prove every reported issue was
exploitable in the earlier environment or that the new version has no unknown
issues. The acceptance evidence here is the actual complete, zero-result
dependency audit against the selected service for the captured Linux source.

## Packet and remaining holds

The manifest verifies every archived member by size and SHA-256. The archive
contains primary-source observations, source snapshot, before/prepared/final
inventories, exact install reports and wheel digests, process outputs/exits,
raw scanner JSON, separate CLI validation and independent review. Environment
directories and caches are excluded; the original failing packet is unchanged.

Native Windows OS/profile scans, static finding remediation, Windows BinDiff
network-denial acceptance, final integrated testing and all publication gates
remain open. No release/tag/deploy, remote mutation, dispatch, target execution,
application dependency upgrade or scanner auto-fix occurred.
