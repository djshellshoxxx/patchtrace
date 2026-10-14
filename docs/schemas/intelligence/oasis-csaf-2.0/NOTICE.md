# OASIS CSAF 2.0 schemas (vendored reference copies)

These two files are unmodified copies of the CSAF 2.0 OASIS Standard JSON schemas. PatchTrace uses them only as build-time input: `tools/generate_intelligence_schemas.py` derives the validation constraint table `src/patchtrace/intelligence/csaf/schema_data.py` from `csaf_json_schema.json`, and `tests/test_intel_schemas.py` checks that the derived table is current and that these files still have the pinned hashes.

| File | Upstream | Retrieved | SHA-256 |
|---|---|---|---|
| `csaf_json_schema.json` | `https://raw.githubusercontent.com/oasis-tcs/csaf/master/csaf_2.0/json_schema/csaf_json_schema.json` (`$id` `https://docs.oasis-open.org/csaf/csaf/v2.0/csaf_json_schema.json`) | 2026-10-14 | `29c114b35b0a30831f1674f2ab8b3ed9b2890cfeaa63b924ac6ed9d70ef44262` |
| `provider_json_schema.json` | `https://raw.githubusercontent.com/oasis-tcs/csaf/master/csaf_2.0/json_schema/provider_json_schema.json` (`$id` `https://docs.oasis-open.org/csaf/csaf/v2.0/provider_json_schema.json`) | 2026-10-14 | `0270d0cfadf5202ff83a63502012a407e0e8ec3194a07296f13641c9f5630aba` |

`docs.oasis-open.org` was not reachable from the authoring sandbox (egress policy), so the copies were taken from the OASIS CSAF Technical Committee's own repository. Re-verify both hashes against `https://docs.oasis-open.org/csaf/csaf/v2.0/os/schemas/` when that host is reachable.

## OASIS notice (applies to the two schema files and to the derived constraint table)

Copyright © OASIS Open 2022. All Rights Reserved.

All capitalized terms in the following text have the meanings assigned to them in the OASIS Intellectual Property Rights Policy (the "OASIS IPR Policy"). The full Policy may be found at the OASIS website.

This document and translations of it may be copied and furnished to others, and derivative works that comment on or otherwise explain it or assist in its implementation may be prepared, copied, published, and distributed, in whole or in part, without restriction of any kind, provided that the above copyright notice and this section are included on all such copies and derivative works. However, this document itself may not be modified in any way, including by removing the copyright notice or references to OASIS, except as needed for the purpose of developing any document or deliverable produced by an OASIS Technical Committee (in which case the rules applicable to copyrights, as set forth in the OASIS IPR Policy, must be followed) or as required to translate it into languages other than English.

The limited permissions granted above are perpetual and will not be revoked by OASIS or its successors or assigns.

This document and the information contained herein is provided on an "AS IS" basis and OASIS DISCLAIMS ALL WARRANTIES, EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO ANY WARRANTY THAT THE USE OF THE INFORMATION HEREIN WILL NOT INFRINGE ANY OWNERSHIP RIGHTS OR ANY IMPLIED WARRANTIES OF MERCHANTABILITY OR FITNESS FOR A PARTICULAR PURPOSE.
