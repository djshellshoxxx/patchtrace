# Direct GitHub Actions source pinning

## Contract (CODEX-1)

Every direct remote repository `uses:` reference in checked-in workflow YAML
must name a reviewed full 40-hex Git commit, with a readable release version
comment. Local actions and local reusable workflows keep their local paths.
Updating a pin requires resolving the upstream tag to a commit (including
peeling annotated tags), inspecting the action manifest at that exact commit,
and reviewing the source change and applicable workflow checks.

The 2026-11-21 candidate starts from PR #349 commit
`11f51c105bf63946f59373ae605b937c4fee607a`. It replaces 176 mutable uses of
11 references in 21 workflow files. The two existing immutable uses remain
unchanged. Only action source references and their version comments change:
triggers, job ordering, permissions, inputs, scripts, cache checks, execution
budgets, artifact handling and release/deployment conditions are preserved.

## Reviewed mapping

The official upstream Git-ref and Git-commit records were resolved on
2026-11-21. Each linked commit's exact `action.yml` was inspected. These
versions retain the existing major versions; pinning is not a major upgrade.

| Existing reference | Release comment | Reviewed commit |
| --- | --- | --- |
| `actions/checkout@v4` | `v4.4.0` | [`11d5960a326750d5838078e36cf38b85af677262`](https://github.com/actions/checkout/commit/11d5960a326750d5838078e36cf38b85af677262) |
| `actions/setup-python@v5` | `v5.6.0` | [`a26af69be951a213d495a4c3e4e4022e16d87065`](https://github.com/actions/setup-python/commit/a26af69be951a213d495a4c3e4e4022e16d87065) |
| `actions/upload-artifact@v4` | `v4.6.2` | [`ea165f8d65b6e75b540449e92b4886f43607fa02`](https://github.com/actions/upload-artifact/commit/ea165f8d65b6e75b540449e92b4886f43607fa02) |
| `actions/cache@v4` | `v4.3.0` | [`0057852bfaa89a56745cba8c7296529d2fc39830`](https://github.com/actions/cache/commit/0057852bfaa89a56745cba8c7296529d2fc39830) |
| `actions/download-artifact@v4` | `v4.3.0` | [`d3f86a106a0bac45b974a628896c90dbdf5c8093`](https://github.com/actions/download-artifact/commit/d3f86a106a0bac45b974a628896c90dbdf5c8093) |
| `ilammy/msvc-dev-cmd@v1` | `v1.13.0` | [`0b201ec74fa43914dc39ae48a89fd1d8cb592756`](https://github.com/ilammy/msvc-dev-cmd/commit/0b201ec74fa43914dc39ae48a89fd1d8cb592756) |
| `openai/codex-action@v1` | `v1.14` | [`306c6a196a99dcc6582530c396a19d2672d5e9ec`](https://github.com/openai/codex-action/commit/306c6a196a99dcc6582530c396a19d2672d5e9ec) |
| `actions/setup-java@v4` | `v4.9.1` | [`cf277c60eb25467037889841efdb72551f06f6c3`](https://github.com/actions/setup-java/commit/cf277c60eb25467037889841efdb72551f06f6c3) |
| `actions/configure-pages@v5` | `v5.0.0` | [`983d7736d9b0ae728b81ab479565c72886d7745b`](https://github.com/actions/configure-pages/commit/983d7736d9b0ae728b81ab479565c72886d7745b) |
| `actions/upload-pages-artifact@v3` | `v3.0.1` | [`56afc609e74202658d3ffba0e8f6dda462b719fa`](https://github.com/actions/upload-pages-artifact/commit/56afc609e74202658d3ffba0e8f6dda462b719fa) |
| `actions/deploy-pages@v4` | `v4.0.5` | [`d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e`](https://github.com/actions/deploy-pages/commit/d6db90164ac5ed86f2b6aed7e0febac5b3c0c03e) |

## Verification and limits

The maintained `test_remote_actions_are_immutable` gate must pass without its
historical CODEX-1 expected-failure mark. Workflow-specific allowlists retain
their allowed action identities and now require the exact reviewed commits.
Existing source-order and diagnostic-artifact checks must still pass with
those pins. The CODEX-5 package-hash gate remains a distinct expected failure.

This contract covers direct repository references. In the pinned
`upload-pages-artifact` composite, the nested `actions/upload-artifact@v4`
reference remains mutable. The pinned Codex action installs npm packages
through its `codex-version` input, and the existing workflow leaves that input
unset. Its requested Node major version also does not select an exact patch.
Runner images, Python/Java patch versions, package artifacts and external
downloads have separate qualification requirements. A passing direct-reference
test does not prove a fully immutable dependency closure or native acceptance.

Keep `[no release]` and `[no deploy]` controls effective when qualifying or
integrating this change. Hosted checks must run on the final combined source;
local source checks do not execute the upstream Actions or publish artifacts.
