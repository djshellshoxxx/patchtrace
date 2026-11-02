# Independent backup Windows stat review

Reviewed clean `7b238d1c28055eeed5811872057b2356a9b22c33` against `ad63416348c122ade8419b11686164be09bb2af3`. No blocking finding in this bounded repair. Only cross-API ctime equality was removed: full per-API before/after snapshots, native ChangeTime, fresh digest, file identity, SQLite checks and nonreplacing publication remain required.

Fresh independent checks: 35 focused tests passed; changed-file Ruff and whitespace check passed. An additional mutation replaced the pathname with identical bytes and restored size/mtime immediately after hashing the original bytes. The fingerprint was refused despite equal digest inputs; both copies remained.

This is helper review evidence, not GitHub APPROVE or native Windows/full-suite acceptance. Later integrations require source equivalence and their own applicable gates.
