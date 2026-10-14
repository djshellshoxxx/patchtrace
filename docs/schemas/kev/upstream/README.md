# Vendored upstream KEV schema

`known_exploited_vulnerabilities_schema.json` is CISA's own JSON Schema (draft-07) for the KEV catalog, copied byte for byte (3,623 bytes, LF).

- Source: `https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities_schema.json` (CISA's mirror), fetched 2026-10-14.
- SHA-256: `0d5865c98694c5bfba2c78a26caf814f406b3fce8bfb81bef79e99c7f288b0e7`
- Licence: CC0 1.0 (CISA KEV repository). Not endorsed by CISA or DHS.
- Purpose: reference for the hand-written tolerant parser and for the live-probe drift check (slice K6). It is never used to validate at run time and is not a PatchTrace contract; PatchTrace's own `kev/1` schemas live one directory up.
- The upstream schema requires only the first 8 entry fields; `knownRansomwareCampaignUse`, `forensicTriage`, `notes` and `cwes` are optional there. The schema does not describe the catalog `title`.
