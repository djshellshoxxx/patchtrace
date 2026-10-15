# KEV fixtures (slice K0)

Offline test data for the `kev/1` package (`docs/specs/program-e/KEV-integration-plan.md`, sections 5, 6 and 9). Nothing here is fetched at test time. Every file is LF-only (`tests/fixtures/kev/** text eol=lf` in `.gitattributes`); the tests assert that no `\r` is present.

## Inventory

| file | bytes | SHA-256 | entries | origin |
|---|---|---|---|---|
| `kev-real-trimmed.json` | 13,607 | `4c717f83d3779498760b4db14a2e406fba749430fb406c190fb87076cb5066c3` | 12 | twelve real entries of CISA catalog 2026.10.13, copied verbatim; only `count` was rewritten (1741 to 12) |
| `kev-synthetic-2099.json` | 3,121 | `55828190427ce880d3588070910f7be74427d364d3640facd6a66bf0ba80f247` | 4 | synthetic, written for the known-answer scenario of plan section 5; not CISA data |

## kev-real-trimmed.json

- Source: https://raw.githubusercontent.com/cisagov/kev-data/main/known_exploited_vulnerabilities.json (CISA's own repository), retrieved 2026-10-14, 1,780,479 bytes, SHA-256 `136904f12e4c6762e526352e3a67ed7b28cd21b4d82bed9c91719ff2e94f2f28`.
- Licence: Creative Commons 0 1.0 (the repository's `LICENSE`, SHA-256 `8dfcf2d0cba33bede386eb470daf2ac08caf6540fc2516baab10dd546f90938a`). The data may be used in any legal manner; use does not authorize use of the CISA Logo or DHS Seal and is not an endorsement by CISA or DHS.
- How it was made: the `vulnerabilities` array of the source was walked with `json.JSONDecoder().raw_decode`, the twelve entries below were kept in the source order (newest `dateAdded` first), and their text was copied unchanged (four-space indentation, `\/` and `\uXXXX` escapes included). The header lines `title`, `catalogVersion` and `dateReleased` are the source's, `count` is 12, and the file has no trailing newline, like the source.
- To check an entry: slice the source entry from its `{` to its `}` with `raw_decode`, encode it as UTF-8 and hash it; the result must equal the SHA-256 in the table.

| CVE | added | what the tests use it for | entry SHA-256 |
|---|---|---|---|
| CVE-2026-104935 | 2026-10-13 | forensic triage Yes (due 3 days after added); malformed `https:/` URL in notes; non-Microsoft vendor | `ada174b78a5b95493d30b719aa5873c49d55f4942156e0a0fdc43b649f8ab87b` |
| CVE-2026-96951 | 2026-10-13 | forensic triage Yes; Microsoft Windows; CWE-77 | `c844c4b7acdf4cbac09d4b6f822957c34f6e0470b27754b24514cac5f33134e1` |
| CVE-2019-1068 | 2026-08-26 | empty `cwes` list; forensic triage Yes on an old CVE | `57b921679315185dbad67da79f955675172cdd141629b53cd2067ea436803f54` |
| CVE-2025-60710 | 2026-04-13 | known ransomware campaign use; due 14 days after added | `1934732eb437f8a371381c208a28fccede1f607ccdace9faa5ccff8abb627e08` |
| CVE-2024-30088 | 2024-10-15 | `product` "Windows " and a `shortDescription` with surrounding spaces | `6a7d35d10ca6ec2c18d41cc661deb139e77f4a78fa2951de3c77f810be1c47ef` |
| CVE-2013-2597 | 2022-09-15 | malformed `https:/` URL in notes | `d79e2f1f5e69d01dcebc5c47dfe2dfb1da8fac18dabcfaac0219e085b0746dbd` |
| CVE-2017-9841 | 2022-02-15 | angle brackets (`<?php`) in the description | `454d957ec1a669bc5b2a777e721df48f7a9f2f98c42a21ffeecdd39e293bebd2` |
| CVE-2017-0144 | 2022-02-10 | known ransomware campaign use; Microsoft SMBv1 | `6fd71b1189b073c829fa6d075d3da557d2be55e9ddc8cbb3580233acbea7700a` |
| CVE-2021-44228 | 2021-12-10 | three CWEs (`CWE-20`, `CWE-400`, `CWE-502`) | `2a82da923724aa5e2646389e4dd04a9c6370599c11677287efaaaaa213736d02` |
| CVE-2021-41773 | 2021-11-03 | U+FFFD replacement characters (written as `�`) in the description | `4b62b98e631ef5ba4d2fff29eaf1670d7db9ce1308b7f83b74bf691e880cddda` |
| CVE-2021-34527 | 2021-11-03 | known ransomware campaign use; due 181 days after added | `15b666c86cfd13974599d1df6efff35ad16436440ab4d9794fdf8e19babdc652` |
| CVE-2021-38648 | 2021-11-03 | earliest `dateAdded` of the catalog; CWE-1390; due 14 days after added | `43ebbd1373eda1f3dcf45660f96f706767067279b7425b12bf3cf95c335de639` |

## kev-synthetic-2099.json

Catalog `2099.03.01`, released `2099-03-01T18:00:00.0000Z`, `count` 4; the `title` says it is synthetic. All hosts are `example.invalid`. Entries are listed newest first, like the real file.

| CVE | vendor / product | added | due | ransomware | forensic triage | CWE | role in the scenario |
|---|---|---|---|---|---|---|---|
| CVE-2099-10010 | Example Networks / "Router " | 2099-02-27 | 2099-03-13 | absent | absent | absent | padded product text; the four optional fields are missing on purpose |
| CVE-2099-10004 | Microsoft / Windows | 2099-02-20 | 2099-03-13 | Unknown | No | CWE-416 | listed, no ransomware flag, CWE without a detector |
| CVE-2099-10009 | Adobe / Reader | 2099-02-15 | 2099-03-08 | Unknown | No | CWE-125 | decoy: listed but in no KB |
| CVE-2099-10001 | Microsoft / Windows | 2099-02-10 | 2099-02-13 | Known | Yes | CWE-787 | listed, ransomware known, forensic triage required |

The scenario's KB side (KB5000001 released 2099-02-11, CVE-2099-10002 not in this catalog) belongs to the later synergy test; CVE-2099-10002 is deliberately absent here.
