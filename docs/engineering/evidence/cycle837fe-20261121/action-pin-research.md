# CODEX-1 verified upstream Action pin mapping

Baseline: `e5a531668ef523cd6faa26d5fec59aa552749134`. Read-only upstream resolution. Active 95fe-C3 ownership remains unchanged.

11 direct references, 176 uses across 21 workflow files.

| Existing reference | Matching upstream release tag | Commit pin | Uses |
| --- | --- | --- | ---: |
| `actions/checkout@v4` | v4.4.0 | [`11d5960a326750d5838078e36cf38b85af677262`](https://github.com/actions/checkout/commit/11d5960a326750d5838078e36cf38b85af677262) | 46 |
| `actions/setup-python@v5` | v5.6.0 | [`a26af69be951a213d495a4c3e4e4022e16d87065`](https://github.com/actions/setup-python/commit/a26af69be951a213d495a4c3e4e4022e16d87065) | 44 |
| `actions/upload-artifact@v4` | v4.6.2 | [`ea165f8d65b6e75b540449e92b4886f43607fa02`](https://github.com/actions/upload-artifact/commit/ea165f8d65b6e75b540449e92b4886f43607fa02) | 43 |
| `actions/cache@v4` | v4.3.0 | [`0057852bfaa89a56745cba8c7296529d2fc39830`](https://github.com/actions/cache/commit/0057852bfaa89a56745cba8c7296529d2fc39830) | 8 |
| `actions/download-artifact@v4` | v4.3.0 | [`d3f86a106a0bac45b974a628896c90dbdf5c8093`](https://github.com/actions/download-artifact/commit/d3f86a106a0bac45b974a628896c90dbdf5c8093) | 20 |
| `ilammy/msvc-dev-cmd@v1` | v1.13.0 | [`0b201ec74fa43914dc39ae48a89fd1d8cb592756`](https://github.com/ilammy/msvc-dev-cmd/commit/0b201ec74fa43914dc39ae48a89fd1d8cb592756) | 4 |
| `openai/codex-action@v1` | v1.14 | [`306c6a196a99dcc6582530c396a19d2672d5e9ec`](https://github.com/openai/codex-action/commit/306c6a196a99dcc6582530c396a19d2672d5e9ec) | 1 |
| `actions/setup-java@v4` | v4.9.1 | [`cf277c60eb25467037889841efdb72551f06f6c3`](https://github.com/actions/setup-java/commit/cf277c60eb25467037889841efdb72551f06f6c3) | 7 |
| `actions/configure-pages@v5` | v5.0.0 | [`983d7736d9b0ae728b81ab479565c72886d7745b`](https://github.com/actions/configure-pages/commit/983d7736d9b0ae728b81ab479565c72886d7745b) | 1 |
| `actions/upload-pages-artifact@v3` | v3.0.1 | [`56afc609e74202658d3ffba0e8f6dda462b719fa`](https://github.com/actions/upload-pages-artifact/commit/56afc609e74202658d3ffba0e8f6dda462b719fa) | 1 |
| `actions/deploy-pages@v4` | v4.0.5 | [`d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e`](https://github.com/actions/deploy-pages/commit/d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e) | 1 |

## Verification

Every observed major tag was resolved through the official upstream GitHub Git-ref API, checked against its Git-commit object, and matched to a version tag. Annotated tags were peeled to commit objects: the Codex v1 tag object is not a valid substitute for its peeled commit pin. Every action manifest was fetched at the full commit SHA and parsed with PyYAML. Raw API responses, manifests, source identities and digest receipts are retained. Signature fields report GitHub observations and are separate from the tag-to-commit identity checks.

## Candidate patch scope

After active ownership releases, replace the 176 direct `uses` references with their mapped commit SHAs and retain readable version comments. The change spans the workflow files listed in `pin-map.json`; no event, permission, runtime argument, release/deployment guard, or CI concurrency change is needed. Update the CODEX-1 contract/evidence and promote its strict expected failure only when the complete direct-reference check passes. Re-read current workflow source before applying any patch; do not overwrite the active cache, Linux smoke or Pages work.

## Transitive limits

- The exact upload-pages-artifact v3.0.1 manifest still contains `uses: actions/upload-artifact@v4`. Pinning the outer action leaves this nested reference mutable. A direct-reference test must not be described as a complete immutable action closure.
- Codex v1.14 already pins setup-node to `53b83947a5a98c8d113130e565377fae1a50d02f`; the upstream commit was verified. Its manifest uses node24, and the parent composite requests Node `24`, not a fixed patch.
- Codex installs the CLI and Responses API proxy using npm and the `codex-version` input. That input defaults to empty; the baseline PatchTrace workflow does not set it. Pinning the action does not lock those package versions or tarball integrity.
- Python/Java toolchain versions, runner images, service behavior and external downloads remain outside direct Action-source pinning. CODEX-5 hash locks and native packaging acceptance are independent gates.
- The mapped setup-java v4.9.1 commit is titled `Deprecate setup-java v4`. This mapping retains the existing major version rather than bundling a compatibility upgrade.

## Evidence

- `pin-map.json`: compact exact mapping, canonical/API URLs, per-action file scope, manifest digests and transitive limits.
- `baseline-census.json`: every direct mutable occurrence at the immutable baseline.
- `raw-upstream-evidence.json`: official API/tag/commit and source response records.
- `upstream-manifests/`: exact fetched action definitions, including the inspected composite steps.

No source files, refs, workflows or remote state were changed.
