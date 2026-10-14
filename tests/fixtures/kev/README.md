# KEV test fixtures

Network-free sources for the `kev/1` tests. Both files are LF, UTF-8, no BOM (pin `eol=lf` in `.gitattributes`: integrator ask A10).

| file | provenance | SHA-256 | bytes |
|---|---|---|---|
| `kev-real-trimmed.json` | VERIFIED real CISA data, trimmed (below) | `0e20b283b9ed08ef10acf033a429b671f425ea07b74279e07708005ce62d9eef` | 13607 |
| `kev-synthetic-2099.json` | SYNTHETIC, hand-written, every CVE ID and text invented (IDs are CVE-2099-*, hosts are `example.invalid`) | `a8315f6df29ecf96cfcbcce5f122597df677bc8ee1038ca4ceea58c96bcb59a9` | 3000 |

## kev-real-trimmed.json

- Source: `https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json` (CISA's own mirror), fetched 2026-10-14, catalogVersion `2026.10.13`, 1,780,479 bytes, SHA-256 `136904f12e4c6762e526352e3a67ed7b28cd21b4d82bed9c91719ff2e94f2f28` (matches plan fact F1).
- Licence: CC0 1.0 (CISA KEV data). Not endorsed by CISA or DHS.
- Transformation: kept the 12 entries below, verbatim (all strings, key order and spacing untouched), in the order listed; `count` rewritten from 1741 to 12; other top-level fields (`title`, `catalogVersion`, `dateReleased`) unchanged; re-serialised exactly as upstream is (4-space indent, ASCII `\uXXXX` escapes, `/` written as `\/`, no trailing newline); this serialisation was checked to reproduce the full 1,780,479-byte upstream file byte for byte. U+FFFD therefore appears as the escape `\ufffd`.
- Entries and the quirk each carries: CVE-2021-38648 (earliest dateAdded), CVE-2021-34527, CVE-2017-0144, CVE-2024-30088 (trailing space in `product`), CVE-2021-41773 (U+FFFD), CVE-2017-9841 (angle brackets), CVE-2013-2597 (malformed `https:/` URL in notes), CVE-2026-104935 and CVE-2026-96951 (forensicTriage Yes), CVE-2019-1068 (empty cwes; forensicTriage Yes), CVE-2021-44228 (three CWEs), CVE-2025-60710 (ransomware Known).
- Entry order in the file is the order of the list above, not upstream order.

## kev-synthetic-2099.json

UNVERIFIED by construction: invented data for state, freshness (year 2099 is always in the future), hostile-text and delta tests. It carries no real provenance and must never be presented as CISA data. Entries: 10001 (ransomware Known, CWE-416), 10002 (forensicTriage Yes, empty cwes), 10003 (HTML, bidi, ANSI, file URL, pipe and backtick text), 10004 (trailing space, added on the release day).
