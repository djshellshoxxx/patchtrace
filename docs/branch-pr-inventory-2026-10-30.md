# PatchTrace controlled branch and PR disposition inventory

Snapshot: **2026-10-30 UTC**, repository `djshellshoxxx/patchtrace`, default branch `main` at `a04f5a299a8d4afef023261e52e08d14678cf1e7`. Branch list API returned 126 rows (pagination 1–2; GitHub can lag after new branch creation). The dedicated `integration/controlled-consolidation-20261030` was created from `a04f5a299a8d4afef023261e52e08d14678cf1e7`. All upstream branches and PR heads remain untouched by this coordinator.

**Important:** Rows with BLOCKED are intentionally not called unmergeable: they are quarantined from the integration baseline pending content comparison, review/CI and active ownership checks. Recent draft updates are a conservative ownership signal, not proof of a worker's local session. Do not delete branches or close PRs from this snapshot. Squash merges mean ancestry alone may understate superseded code. Unpublished worktrees, dirty or untracked files cannot be seen by GitHub and are not verified by this audit.

## Branches — immutable snapshot and exact current operational disposition

| Branch | Observed SHA | Open PR | Disposition | Action / evidence still required |
| --- | --- | ---: | --- | --- |
| `main` | `a04f5a299a8d4afef023261e52e08d14678cf1e7` | — | BASELINE | Refetch before final merge |
| `access-test-noprefix` | `726a371ab34d4589b0456d059865ade6b82fac88` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `audit/ai-reports` | `dd6402b9c00d5aae79f152f4fe5ce0fa8597dc24` | — | EXPERIMENTAL_OR_DEFERRED | Audit/research; verify useful content and supersession before changing |
| `audit/core` | `fae13b2ed3043ddce00bbf387e386e93e7b3ee06` | — | EXPERIMENTAL_OR_DEFERRED | Audit/research; verify useful content and supersession before changing |
| `audit/desktop` | `4d5e48ab7df30f6318a8f3177b37ac98741e2b1f` | — | EXPERIMENTAL_OR_DEFERRED | Audit/research; verify useful content and supersession before changing |
| `audit/enrichment` | `cbc5b079ad2c8cdea4ec161b1afe9ac554b8ed39` | — | EXPERIMENTAL_OR_DEFERRED | Audit/research; verify useful content and supersession before changing |
| `audit/integration` | `f6505928d8264343caa33f878deb253626752944` | — | EXPERIMENTAL_OR_DEFERRED | Audit/research; verify useful content and supersession before changing |
| `audit/runtime` | `9f32a6ecbd056249373b82bc1e814bd938da8c70` | — | EXPERIMENTAL_OR_DEFERRED | Audit/research; verify useful content and supersession before changing |
| `chatgpt/corpus-1` | `b7a0f0a45d2de1462367d877b7386091b4d275ce` | #68 | DEPENDS_ON_OTHER_PR | Stacked on claude/instance-d-gui; test/reconcile parent first; preserve head |
| `chatgpt/deferred-audit-fixes-1` | `2174837f3172c3ff2a3c676da106f42b55648a70` | #67 | DEPENDS_ON_OTHER_PR | Stacked on claude/instance-d-gui; test/reconcile parent first; preserve head |
| `chatgpt/ghidriff-sequential-lock-fix-20261017` | `f6b7545bcc7a161440ab7119233c204510571370` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `chatgpt/help-docs-1` | `e5bee6fe157c90a40f2d9f458768e2169ce123e5` | #70 | DEPENDS_ON_OTHER_PR | Stacked on claude/instance-d-gui; test/reconcile parent first; preserve head |
| `chatgpt/java-probe-boundaries-20261016` | `09bb4519d7d8e9ff8f40abcba7e11cb297d8b61e` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `chatgpt/java-probe-ci-fix-20261016` | `0254841e3e635ed717e35abcf83021f001d7df29` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `chatgpt/java-probe-qa-fix-20261016` | `89500e12068656fa1958443ef634064effcbc40b` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `chatgpt/kb-fixtures-1` | `781b36fb60e775ce01bf0c114e6a17b609fdb475` | #69 | DEPENDS_ON_OTHER_PR | Stacked on claude/instance-d-gui; test/reconcile parent first; preserve head |
| `chatgpt/lbl30-prereg-guard-20261016` | `6ae2c079e6cafa2b7bd5396cac443cd34ba7138a` | #85 | DEPENDS_ON_OTHER_PR | Stacked on claude/instance-d-gui; test/reconcile parent first; preserve head |
| `chatgpt/lbl31-coff-quoted-rip-20261016` | `6e71bfabbf5ef75449b46981e9e822f7e555a6bf` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `chatgpt/lbl31-coff-symbol-mask-20261016` | `9622704d5c751d55700c4b642111131a7135d139` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `chatgpt/lbl31-output-persistence-20261015` | `2019a37fa65fc37f4758469143c2daadc07e0098` | #78 | DEPENDS_ON_OTHER_PR | Stacked on claude/instance-d-gui; test/reconcile parent first; preserve head |
| `chatgpt/lbl31-windows-qa-fixes-20261016-a` | `ddb2ff077a21c1f0053ba8079564f6f86c3e155f` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `chatgpt/lbl32-card-controls-20261016` | `9513bc05229dd7a8460fc229d7420154d61498db` | #79 | DEPENDS_ON_OTHER_PR | Stacked on chatgpt/lbl31-output-persistence-20261015; test/reconcile parent first; preserve head |
| `chatgpt/lbl32-recipe-aa-noise-20261016` | `eaa30013794a9bd0fedc9ec34bbe374d6db0cfc9` | #82 | DEPENDS_ON_OTHER_PR | Stacked on claude/instance-d-gui; test/reconcile parent first; preserve head |
| `chatgpt/merge-first-handoff-20261016` | `19153f10780e783bc931739dd26db97d8eaf2b92` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `chatgpt/nway-external-note-qa-20261016` | `8c7288276d3e49b7794b7fd80db4b02d5891cf00` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `chatgpt/panels-1` | `cfd7cfff52f4f9b8b1264e8b7d70ef1bbef2d63f` | #72 | DEPENDS_ON_OTHER_PR | Stacked on claude/instance-d-gui; test/reconcile parent first; preserve head |
| `chatgpt/patchwatch-reuse-roadmap-20261026` | `4eabf8dff2c4094681da70c7bd85ecd0da5aed9f` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `chatgpt/r5-calibration-research-20261030` | `4d9d9051aea87319847a0b321a14d37b95cb8abd` | #132 | ACTIVE_WORKER_OWNED | Recent live draft, do not change author branch |
| `chatgpt/semantic-analysis-r3-20261030` | `2698b9a04d33b2d04f49c1ab737636539c6ef6f7` | #129 | ACTIVE_WORKER_OWNED | Recent live draft, do not change author branch |
| `chatgpt/ue-r3-retain-decompiled-20261016` | `ebbd621d4f557905892aee5f7cf8cb7b0e2addc2` | #86 | DEPENDS_ON_OTHER_PR | Stacked on claude/instance-d-gui; test/reconcile parent first; preserve head |
| `chatgpt/ue-r7-p15-unresolved-20261016-a` | `292dc3953dd2b8f157752d12251aff68b6e5bda5` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `chatgpt/ue-r7-strict-worker-report-20261016-a` | `9c5f9a42b499133b842b14b9619bf8390010e1ff` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `chatgpt/unified-fixture-collection-fix-20261016` | `941c617b6854291e2448cad6d7d5710a24a8543d` | #90 | DEPENDS_ON_OTHER_PR | Stacked on chatgpt/unified-fixtures-1; test/reconcile parent first; preserve head |
| `chatgpt/unified-fixtures-1` | `161a88345efc6484f4d7809fc6963a0193bd0057` | #71 | DEPENDS_ON_OTHER_PR | Stacked on claude/instance-d-gui; test/reconcile parent first; preserve head |
| `chatgpt/unified-sort-perf-qa-20261016` | `27b0a48bb8007f504b4a127a099136a6ea5c00b7` | #94 | DEPENDS_ON_OTHER_PR | Stacked on chatgpt/lbl31-output-persistence-20261015; test/reconcile parent first; preserve head |
| `claude/access-test-1791773355` | `726a371ab34d4589b0456d059865ade6b82fac88` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `claude/audit-beta` | `c93ff945b9b523abe0b829247137105788a5ea27` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `claude/awesome-ramanujan-o3pxx3-ci` | `0bf1f8309e8425ba34199657009d3055215336f1` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `claude/awesome-ramanujan-o3pxx3-hostile` | `077b04e681ac74b20c0ff8bf367aa720c277f2d2` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `claude/awesome-ramanujan-o3pxx3-win1` | `7ac57759f3b9b332eaafb48c82f366566892f1b1` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `claude/bugfix-kbc-20261029` | `653f384d1ca60b7e943bd658698e0989d826b696` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `claude/bugfix-kev-acq-20261029` | `fbe58d800da27aff2544c6a478f0a591ff7dad3b` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `claude/bugfix-strings-pe-20261029` | `7ae041e79e419159299c32df98b8e69ab176e859` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `claude/bundle-license-gate` | `d3617acf9af7834582b4962a8c149969a7d55a22` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `claude/clever-clarke-s4nhi6` | `502402684b0d0aa35d7719bb5a3467de035982bc` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `claude/compassionate-goldberg-5uuqks` | `198eb21e8813b28de361422cfe3c002bdb9e3970` | #125 | ACTIVE_WORKER_OWNED | Recent live draft, do not change author branch |
| `claude/fix-deadline-test` | `22ff025a7710d07d7ad74be2c8f7cc0b4db0daf7` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `claude/instance-b-features` | `e492092ff360ee22d576ce6266a31dfe8d614ab4` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `claude/instance-c-research` | `cebf38a30ce3d4967ed00a4773f8f9898a9ea708` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `claude/instance-d-gui` | `2fa113889d1ffee6b68496993d3b3b6ebb0ba035` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `claude/java-version-retry-integration` | `45fa67ad7e924cb4e2df1cd487c04a2c0ddab381` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `claude/jolly-fermi-eghaxy` | `99f8328ce89d02f200cf9fbc5852d9801761af28` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `claude/modest-hamilton-kz2gta` | `8d958f0a1950a29c1d1cef9525a114654f4c9904` | #126 | ACTIVE_WORKER_OWNED | Recent live draft, do not change author branch |
| `claude/patchtrace-cli-dotpath-spec-er6hha` | `62b9a3de4d1036a6e4b9bd2618372f4042b15f7f` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `claude/patchtrace-features` | `66e9adc50fb118c04e5e24eacd0c221ca483a130` | #100 | EXPERIMENTAL_OR_DEFERRED | Draft: review unique changes and dependency acceptance, preserve branch |
| `claude/patchtrace-haiku-agent-motpbx` | `9fddf99e2635e28129b2deda0ff155b00d9ba471` | #102 | EXPERIMENTAL_OR_DEFERRED | Draft: review unique changes and dependency acceptance, preserve branch |
| `claude/quirky-curie-n5pxf5` | `a5593fa58b2ead6ecf6adfe045db242232cd52a3` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `claude/symbol-policy-isolated-settings` | `5db597257decc219db520c0dab8369b4d4e2ea5e` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `codex/agent-skills-spec56-20261014` | `4467d1f3c6e113a7da808a67e8dee9d4aa5083d8` | #61 | BLOCKED | Non-draft: require review, exact-head checks, and semantic diff before merge; policy docs require special scrutiny |
| `codex/audit-1` | `c2070cf8b4e7b0ade76cb000a5805009754eec55` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `codex/audit-2` | `08b12f1b279d917736cfc17d4b8e447c8f552616` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `codex/deep-review-consolidation-20261030` | `95e09548a82202ae4cfd9380522f36513da87a66` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `codex/essential-integration-20261029` | `5ed624e91468c410f2cf738ed4e36c2be3e0201d` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `codex/fix-pr110-ci-gates-20261029` | `c0d1c38aee74461969ff0a8b4d61179c3dbb9b0b` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `codex/gui-bounded-ambiguous-candidates-20261029` | `3287cb3d36052bd6e44420f631ed033baf939d64` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `codex/java-version-retry-20261015` | `8ee61c623fa37c5a219f912cf7870bfeddcb1f70` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `codex/patchtrace-beta` | `c7937246a5bf3f1a09c7d121c0d438088b02040c` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `codex/pr110-ci-repairs-20261029` | `bb42828d05b775c59b73a7bbd02c0113b9b9bb3b` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `codex/pr110-kb-arch-scope-20261029` | `40e02daf93c8e13a94b74f5b80d86c1680fea7ad` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `codex/pr110-persistence-feedback-20261029` | `3e9cedb012b4c82da3b0e5f9bc977ecd7313b64c` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `codex/pr110-qa-wbjson-diaphora-help-20261029` | `aba4c2001a6b093f7f8cdc8b0ac20ab074ed57b8` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `codex/pr111-bounded-nav-into-integration-20261029` | `025300f8e169556f84b6a8cfed20413e0a26b019` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `codex/r1-ground-truth-research-20261030` | `a02a1774a1617441072f4a8770348cc22038eeac` | #128 | ACTIVE_WORKER_OWNED | Recent live draft, do not change author branch |
| `codex/r2-unified-matching-research-20261030` | `c704a39c8ece56c3215c1d765d79e7f4780ddcbd` | #131 | ACTIVE_WORKER_OWNED | Recent live draft, do not change author branch |
| `codex/t9-qa-20261020` | `ecc4f2054c00dc2b324bb71134595c48dc4b6a18` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `codex/tier-w-fetch-20261015` | `5b7b2591e616e8c28c05c7070661b33e2ca0435c` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `codex/windows-setup-installer-20261017` | `9c5fe67bd10a5d1342440bb8ea6a524cca3ce1f2` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `docs/claude-autonomous-alpha-handoff-20261013` | `1038d3f13f214d55c28ceeb51c1c13c9b43b1d3f` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `docs/csaf-patch-intelligence-specs` | `24244831ec443fa19555586835e71da6dd4aac98` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `docs/diaphora-optional-engine-20261014` | `b75ac57d85c75e8d61c61af8d104119bb1c65587` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `docs/dockable-workspace-spec-20261030` | `6a1e3ce348a7e5f67bbabfe388315812cc830b03` | #127 | ACTIVE_WORKER_OWNED | Recent live draft, do not change author branch |
| `docs/nway-matches` | `f748cc48ea07b9af189d967979aa078610550eea` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `docs/readme-and-wiki` | `ad8fbe9f2f041653760c02e9d18a91a66dd11c39` | #98 | EXPERIMENTAL_OR_DEFERRED | Draft: review unique changes and dependency acceptance, preserve branch |
| `docs/semantic-ghidra-roadmap` | `8b9ebc01bb221a60ee65838dfdafd59d66e15f5d` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `docs/spec-31-kb-cve-correlation-20261014` | `9088bf0e2e452c5d792f2a9e6e879f417e9fc120` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `docs/spec-32-kb-patch-search-20261014` | `d0ceb56f30f81f881f1f25fb4d1dba772ff476b9` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `docs/specs-plan` | `a5194581396b67395a0ae8453d73eec5ab024e54` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `docs/workbench-search-graph-floss-20261014` | `af15701d13b516662a36f20a00ece01b8462160f` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/acquisition` | `293362a2d8cee7d5cc373439436945888b3b805a` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/acquisition-gui` | `7ae34d8fa26a6b6c8b7acf40f5c16d99643151ce` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/alpha-ui-integration` | `c7ed1d90a890afa9eb67c238f9f52f458db96432` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/artifact-bytes-seam` | `91b35d09afd29e9c78169a3b095d9ea3be6c31b1` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/byte-representations` | `303bc452d0bb6cd46ee67f731f64ec951e1ee215` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/enrichment-cache` | `0368fd9b5453ab50166c08cf8dfc493e57b0ee52` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/enrichment-contracts` | `010d809d2581d3a8ed8208e83325ba29f91b2419` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/enrichment-cve` | `49bf245583d040a8b29d80daee8666d8c7f7b8d4` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/enrichment-signals` | `e96441a1a90478d5b06e7b0d9b4320695a2018ed` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/enrichment-wil` | `9a6999a0e644ef03670d10fc0b08524345c6c709` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/local-runtime-discovery` | `b9198705ab4c144746214c1e42c15b6098063009` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/nway` | `44d431788bcc55429a033049ed997fa33c92289b` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/pe-overview` | `4b78a6d3c0015a5fd46d557cde6cc8f0a583795b` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/phase2-finish` | `86afe3f6563b71e1fff5ed56a907f29c6703b96e` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/phase3-batch` | `3581b520207b464b35a7baa39d188fb4f2a08cf1` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/profiles` | `d21b5917a66041cb1ffa4f46931e551e55f3165a` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/raw-cache` | `28bc476713fc9b77b876cfc8f5454760ea23d4e0` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/secondary` | `b932ae1a1c8916aeac7be2d49ce27c24717f2846` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/tooltip-registry` | `0a3843ea2abe37d42ff0291d621fa9a7c9744bbc` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feat/verified-offline-runtime-bundle` | `1724503d01be7aee13cb43a3a7a28b8a9ff54ece` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feature/alpha-file-overview-20261013` | `476016590be5cd1315613759af18ff61c7c27851` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feature/evidence-reconciliation-confidence` | `ddda35f40b94c145b2a9a9b68509b4ddb76a090a` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `feature/gui-inspection-preview` | `8b94227a81b71841c65783c775f704a538d35710` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `fix/backend-exit-diagnostics` | `bc00a6912dde57482a301bf64ef6fbc3f324cb92` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `fix/explicit-offline-symbol-policy` | `2e6618762ab6e15e5be0be60aec3fb8f56af44f3` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `fix/ghidra-dot-paths` | `5c3b1df94c0d2a908bb0459caceb336912527555` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `fix/isolate-ghidra-scratch` | `7ea7272311271a540a188e5d0de6d3aaa8864611` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `fix/pe-inspection-row-tooltips-20261013` | `0182a8035d64071fc88b5f299edc3ef3760946b5` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `fix/pr110-ci-regressions-20261029` | `979ddfad860c95ceabeb5b670b771900b5617098` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `haiku/cli-help-suppress-20261027` | `37940b706f117f9786109433aed7751eca4e52a6` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `haiku/phase2-handoff-import-20261027` | `4522030ff3ff76d720a5efc33953aaa5e5837398` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `haiku/skills-manifest-import-20261027` | `039b0ef8a5d0cb5136aca72be5c65d11867c19af` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `research/r4-vulnerability-correlation-20261030` | `ff570bdd784d02f745e4ad21d8aa7b4f1f776344` | #130 | ACTIVE_WORKER_OWNED | Recent live draft, do not change author branch |
| `research/r6-final-integration-engineering-notes-20261030` | `3010f289dbb46a1db62218a35cca03420090e306` | #133 | ACTIVE_WORKER_OWNED | Recent live draft, do not change author branch |
| `research/r7-advanced-binary-analysis-20261030` | `c0fd0834b60eb5e9431f84d58b08dae7d54ba1a3` | #134 | ACTIVE_WORKER_OWNED | Recent live draft, do not change author branch |
| `research/r8-deep-uncertainty-20261030` | `8267b42b32a85f6728b9ca4311915c12d1496c8f` | #135 | ACTIVE_WORKER_OWNED | Recent live draft, do not change author branch |
| `security/offline-bundle-no-overwrite-20261013` | `a39cab81de3e0eeadf57e6255d2fe3e131b3294a` | — | BLOCKED | Not yet verified against main by immutable compare, review, tests, and ownership |
| `integration/controlled-consolidation-20261030` | `a04f5a299a8d4afef023261e52e08d14678cf1e7` (creation) | — | INTEGRATION_BASELINE | New branch owned by integrator; exact SHA to be re-read after ledger commits |

## Open pull requests — initial operational disposition

| PR | Base ← head | Observed head SHA | Draft | Disposition / gate |
| --- | --- | --- | --- | --- |
| [#61](https://github.com/djshellshoxxx/patchtrace/pull/61) Add Caveman and PatchTrace agent skills with spec-first workflow (SPEC-56) | `main` ← `codex/agent-skills-spec56-20261014` | `4467d1f3c6e113a7da808a67e8dee9d4aa5083d8` | no | BLOCKED: Check semantic diff and exact-head tests/reviews |
| [#67](https://github.com/djshellshoxxx/patchtrace/pull/67) Deferred audit fixes: Ghidriff integrity, isolated launches and consent | `claude/instance-d-gui` ← `chatgpt/deferred-audit-fixes-1` | `2174837f3172c3ff2a3c676da106f42b55648a70` | yes | DEPENDS_ON_OTHER_PR: Verify parent dependency and stack before any merge |
| [#68](https://github.com/djshellshoxxx/patchtrace/pull/68) Corpus batch 1: 24 candidate recipes and continuation plan | `claude/instance-d-gui` ← `chatgpt/corpus-1` | `b7a0f0a45d2de1462367d877b7386091b4d275ce` | yes | DEPENDS_ON_OTHER_PR: Verify parent dependency and stack before any merge |
| [#69](https://github.com/djshellshoxxx/patchtrace/pull/69) Add synthetic KB patch-search fixtures and QA | `claude/instance-d-gui` ← `chatgpt/kb-fixtures-1` | `781b36fb60e775ce01bf0c114e6a17b609fdb475` | yes | DEPENDS_ON_OTHER_PR: Verify parent dependency and stack before any merge |
| [#70](https://github.com/djshellshoxxx/patchtrace/pull/70) docs: add first 25 Prompt 5 help topics | `claude/instance-d-gui` ← `chatgpt/help-docs-1` | `e5bee6fe157c90a40f2d9f458768e2169ce123e5` | yes | DEPENDS_ON_OTHER_PR: Verify parent dependency and stack before any merge |
| [#71](https://github.com/djshellshoxxx/patchtrace/pull/71) Draft: unified synthetic fixtures and gate evaluator tests (partial, unverified) | `claude/instance-d-gui` ← `chatgpt/unified-fixtures-1` | `161a88345efc6484f4d7809fc6963a0193bd0057` | yes | DEPENDS_ON_OTHER_PR: Verify parent dependency and stack before any merge |
| [#72](https://github.com/djshellshoxxx/patchtrace/pull/72) docs: specify Program E panels and coordinated build plan | `claude/instance-d-gui` ← `chatgpt/panels-1` | `cfd7cfff52f4f9b8b1264e8b7d70ef1bbef2d63f` | yes | DEPENDS_ON_OTHER_PR: Verify parent dependency and stack before any merge |
| [#78](https://github.com/djshellshoxxx/patchtrace/pull/78) LBL-31: persist Tier R engine outputs and transfer verified training artifacts | `claude/instance-d-gui` ← `chatgpt/lbl31-output-persistence-20261015` | `2019a37fa65fc37f4758469143c2daadc07e0098` | yes | DEPENDS_ON_OTHER_PR: Verify parent dependency and stack before any merge |
| [#79](https://github.com/djshellshoxxx/patchtrace/pull/79) LBL-32: run pinned recipe-card A/A and noise controls on both sides | `chatgpt/lbl31-output-persistence-20261015` ← `chatgpt/lbl32-card-controls-20261016` | `9513bc05229dd7a8460fc229d7420154d61498db` | yes | DEPENDS_ON_OTHER_PR: Verify parent dependency and stack before any merge |
| [#82](https://github.com/djshellshoxxx/patchtrace/pull/82) LBL-32: two-sided recipe A/A and noise cases in Tier R planner | `claude/instance-d-gui` ← `chatgpt/lbl32-recipe-aa-noise-20261016` | `eaa30013794a9bd0fedc9ec34bbe374d6db0cfc9` | yes | DEPENDS_ON_OTHER_PR: Verify parent dependency and stack before any merge |
| [#85](https://github.com/djshellshoxxx/patchtrace/pull/85) LBL-30: verify preregistration and enforce single-use final training | `claude/instance-d-gui` ← `chatgpt/lbl30-prereg-guard-20261016` | `6ae2c079e6cafa2b7bd5396cac443cd34ba7138a` | yes | DEPENDS_ON_OTHER_PR: Verify parent dependency and stack before any merge |
| [#86](https://github.com/djshellshoxxx/patchtrace/pull/86) UE-R3: persist bounded on-demand Ghidra C into unified result sidecars | `claude/instance-d-gui` ← `chatgpt/ue-r3-retain-decompiled-20261016` | `ebbd621d4f557905892aee5f7cf8cb7b0e2addc2` | yes | DEPENDS_ON_OTHER_PR: Verify parent dependency and stack before any merge |
| [#90](https://github.com/djshellshoxxx/patchtrace/pull/90) test: replace two defective unified fixture originals | `chatgpt/unified-fixtures-1` ← `chatgpt/unified-fixture-collection-fix-20261016` | `941c617b6854291e2448cad6d7d5710a24a8543d` | no | DEPENDS_ON_OTHER_PR: Verify parent dependency and stack before any merge |
| [#94](https://github.com/djshellshoxxx/patchtrace/pull/94) QA: make Unified 100k-row sort budget resilient to runner descheduling | `chatgpt/lbl31-output-persistence-20261015` ← `chatgpt/unified-sort-perf-qa-20261016` | `27b0a48bb8007f504b4a127a099136a6ea5c00b7` | no | DEPENDS_ON_OTHER_PR: Verify parent dependency and stack before any merge |
| [#98](https://github.com/djshellshoxxx/patchtrace/pull/98) Add wiki pages and link them from README | `main` ← `docs/readme-and-wiki` | `ad8fbe9f2f041653760c02e9d18a91a66dd11c39` | yes | EXPERIMENTAL_OR_DEFERRED: Retain draft; verify complete content, exact-head CI and reviews |
| [#100](https://github.com/djshellshoxxx/patchtrace/pull/100) SPEC-53 local symbol mode + launcher; SPEC-DA-01 Diaphora Mode A import | `main` ← `claude/patchtrace-features` | `66e9adc50fb118c04e5e24eacd0c221ca483a130` | yes | EXPERIMENTAL_OR_DEFERRED: Retain draft; verify complete content, exact-head CI and reviews |
| [#102](https://github.com/djshellshoxxx/patchtrace/pull/102) Windows alpha: exe version resource and icon, CI split, release integrity and parser hardening, SPEC-26 A tooltips | `main` ← `claude/patchtrace-haiku-agent-motpbx` | `9fddf99e2635e28129b2deda0ff155b00d9ba471` | yes | EXPERIMENTAL_OR_DEFERRED: Retain draft; verify complete content, exact-head CI and reviews |
| [#125](https://github.com/djshellshoxxx/patchtrace/pull/125) docs: next-milestone dev prompt for integrated essential alpha | `main` ← `claude/compassionate-goldberg-5uuqks` | `198eb21e8813b28de361422cfe3c002bdb9e3970` | yes | ACTIVE_WORKER_OWNED: Retain draft; verify complete content, exact-head CI and reviews |
| [#126](https://github.com/djshellshoxxx/patchtrace/pull/126) docs: integrated essential alpha milestone ledger and handoff | `main` ← `claude/modest-hamilton-kz2gta` | `8d958f0a1950a29c1d1cef9525a114654f4c9904` | yes | ACTIVE_WORKER_OWNED: Retain draft; verify complete content, exact-head CI and reviews |
| [#127](https://github.com/djshellshoxxx/patchtrace/pull/127) Specify modular dockable workspaces and simpler default layouts | `main` ← `docs/dockable-workspace-spec-20261030` | `6a1e3ce348a7e5f67bbabfe388315812cc830b03` | yes | ACTIVE_WORKER_OWNED: Retain draft; verify complete content, exact-head CI and reviews |
| [#128](https://github.com/djshellshoxxx/patchtrace/pull/128) R1: research and validate the ground-truth binary corpus | `main` ← `codex/r1-ground-truth-research-20261030` | `a02a1774a1617441072f4a8770348cc22038eeac` | yes | ACTIVE_WORKER_OWNED: Retain draft; verify complete content, exact-head CI and reviews |
| [#129](https://github.com/djshellshoxxx/patchtrace/pull/129) R3 research: semantic-change proofs, compiler noise and guarded PE comparisons | `main` ← `chatgpt/semantic-analysis-r3-20261030` | `2698b9a04d33b2d04f49c1ab737636539c6ef6f7` | yes | ACTIVE_WORKER_OWNED: Retain draft; verify complete content, exact-head CI and reviews |
| [#130](https://github.com/djshellshoxxx/patchtrace/pull/130) R4 research: CVE/KB/product/build/binary provenance and function evidence | `main` ← `research/r4-vulnerability-correlation-20261030` | `ff570bdd784d02f745e4ad21d8aa7b4f1f776344` | yes | ACTIVE_WORKER_OWNED: Retain draft; verify complete content, exact-head CI and reviews |
| [#131](https://github.com/djshellshoxxx/patchtrace/pull/131) R2: unified matching research, evidence preservation and measured scaling fixes | `main` ← `codex/r2-unified-matching-research-20261030` | `c704a39c8ece56c3215c1d765d79e7f4780ddcbd` | yes | ACTIVE_WORKER_OWNED: Retain draft; verify complete content, exact-head CI and reviews |
| [#132](https://github.com/djshellshoxxx/patchtrace/pull/132) R5: calibration research, statistical validation audit and developer handoff | `main` ← `chatgpt/r5-calibration-research-20261030` | `4d9d9051aea87319847a0b321a14d37b95cb8abd` | yes | ACTIVE_WORKER_OWNED: Retain draft; verify complete content, exact-head CI and reviews |
| [#133](https://github.com/djshellshoxxx/patchtrace/pull/133) R6: comprehensive engineer-ready final integration and release acceptance notes | `main` ← `research/r6-final-integration-engineering-notes-20261030` | `3010f289dbb46a1db62218a35cca03420090e306` | yes | ACTIVE_WORKER_OWNED: Retain draft; verify complete content, exact-head CI and reviews |
| [#134](https://github.com/djshellshoxxx/patchtrace/pull/134) R7 research: bounded semantic slicing and evidence-grounded security interpretation | `main` ← `research/r7-advanced-binary-analysis-20261030` | `c0fd0834b60eb5e9431f84d58b08dae7d54ba1a3` | yes | ACTIVE_WORKER_OWNED: Retain draft; verify complete content, exact-head CI and reviews |
| [#135](https://github.com/djshellshoxxx/patchtrace/pull/135) R8 (draft): adversarial proof and literal-type normalization research | `main` ← `research/r8-deep-uncertainty-20261030` | `8267b42b32a85f6728b9ca4311915c12d1496c8f` | yes | ACTIVE_WORKER_OWNED: Retain draft; verify complete content, exact-head CI and reviews |

## Special integration constraints

- Code changes: `QT_QPA_PLATFORM=offscreen python -m pytest -q`; `python -m ruff check src tests tools`; appropriate schema regeneration; Linux + Windows exact-head QA; native Ghidriff / secondary tool checks for applicable changes; frozen package smoke for UI/release work. A cancelled, pending, queued, skipped or unexecuted check is not passing evidence.
- Do not modify recent R1–R8 draft research heads or external Claude PR #102. Evaluate overlapping changes against latest main before selective porting.
- Historically stacked label-training fixes #78/#79/#82/#85 and fixtures #71/#90 are NOT standalone merges to main without dependency/supersession review.
- All unique work remains on original remote branches, regardless of disposition. A complete local-worktree/dirty-file inventory is blocked by lack of access to contributors' checkouts; do not infer absence.
- Keep a single integration lane and add substantive updates to `docs/qa.md` and `tasks/todo.md` as checks are actually run or blocked.
