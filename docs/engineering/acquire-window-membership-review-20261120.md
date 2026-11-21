# Generation 25 — coordinator adversarial source inspection (not independent approval)

The reviewer role here is the same engineering coordinator, not a fresh independent worker. No independent signoff is claimed.

- Prior implementation chose the first `sha256 + file_name` record, regardless of `kb` or `version_key`, so the persisted newer evidence could misidentify BASE or a different KB body. The code was identical in inspected main, PR325, PR335 and retained `work/winbindex-publication-20261105`.
- The repaired caller derives the newer target from the resolver `PairProposal.window_id`, not from a user-added independent label. It requires an index-key and KB/BASE body; malformed/other windows refuse `PT-KBC-INPUT`.
- Shared `other_versions` source rows are admitted only with explicit exact-key membership. A native body takes precedence over a copied body, consistent with existing `lineage.index_rows` semantics. A string masquerading as `other_versions` is not treated as a container.
- The source now binds this selected normalized newer body into `AcquisitionSource` and its plan digest before network consent. Changed source metadata requires another preview/consent. No new network requests or destination writes were added.
- **Unresolved:** The older predecessor's exact original KB/version body is not included in `PairProposal` and is still SHA-first. The complete original Winbindex index/raw entry and full timeline are not persisted. Malicious or inconsistent raw source rows, concurrently changing files and native Windows behavior need genuine independent tests. This candidate is one narrow correctness improvement, not a solution to full resolver input membership or any publication race.
