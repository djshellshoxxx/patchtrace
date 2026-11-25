# Staged backup verification

**Independent technical approval** for `0f1bd044685e05b710ef6702a1c6c319edc1c8cd`, tree `dfc9d87d4817d219055fe487aac6b4d9f62332b3`. Both findings raised during the review are resolved. This review covers the staged backup and published CLI verification changes relative to `cca6ce4a0d20725e8a421421cd2e0fddb8313bf7`.

| Independent replay on the final source | Outcome |
|---|---|
| Change a copied run setting from JSON boolean true to integer 1 and recompute the copy's self-hash | The staged copy failed verification and was removed. Changing the published copy caused CLI exit 3 with its path and preserved it for inspection. |
| Interrupt the published read transaction start, interrupt its final digest SELECT, or interrupt the final source digest SELECT after publication | Each real SQLite progress-callback interruption returned exit 3 and PT-STORAGE, named the exact retained destination, and emitted no verified result. |
| Back up a project from earliest v1 writer `8b5ae1e9`; separately omit a valid default field and change JSON whitespace | The historical payload was copied byte for byte. The CLI verified the omitted-default fixture and preserved its original payload and SHA-256, although reserializing the current model would differ. |
| Commit a changed setting from another SQLite connection between validation and digest comparison on a WAL-mode copy | Both reads saw one consistent snapshot. A fresh verification detected the new persisted value. |
| Focused Linux tests for verification, cleanup, public locking, CLI, history, recovery and URI handling | 64 passed, 88 unrelated cases deselected in 2.71 seconds. |

The service verifies the current persisted snapshot and its registered artifact/raw hashes before publication. The source uses its cooperative writer lock. A private stage omits the project lock, and a public verifier obtains it. SQLite may create empty WAL and shared-memory bookkeeping on a verified WAL-mode copy. Optional unregistered files and every historical row do not receive an independent content comparison. Hosted Windows and release acceptance require their own evidence.

The replay used Python 3.12.14 and real SQLite 3.53.1. The review made no source or GitHub changes.
