// patchtrace-rule-export/1
// Rule PT_7cc90c78866e_newer version 1, label "Length check added"
// Built by PatchTrace 0.1.0 with YARA-X 1.21.0 (BSD-3-Clause) and iced-x86 1.21.0
// Project proj-1, analysis run run-1
// Older build older.dll sha256 3271263489d95559dde44805e55c471c8ed4a60423fcf90c3e841e6537ef915f; newer build newer.dll sha256 943f9914f8dae5dc8f79d6b09e51933dad3e90a6ad5070f7ba6e68984bb05425
// Source change: modified function at older RVA 0x1000 and newer RVA 0x1000, reviewed as material; function names omitted
// Accepted 2026-10-14T10:00:00Z. Tested 2026-10-14T10:30:00Z: 2 builds, 1 clean files, 0 unexpected matches, 0 not scanned
// Advisory anchors given by the analyst and not checked by this rule: CVE-2026-0001
// Origin: byte patterns copied from the analysed files on the analyst's computer. If those files are third-party software, check its licence before sharing this rule or committing it to a repository.
// A match means a file contains this pattern. It does not show whether the file is affected by a flaw.

import "pe"

rule PT_7cc90c78866e_newer: patchtrace newer_side {
  meta:
    patchtrace_rule_id    = "7cc90c78866e.v1"
    patchtrace_version    = 1
    patchtrace_project_id = "proj-1"
    older_sha256          = "3271263489d95559dde44805e55c471c8ed4a60423fcf90c3e841e6537ef915f"
    newer_sha256          = "943f9914f8dae5dc8f79d6b09e51933dad3e90a6ad5070f7ba6e68984bb05425"
    side                  = "newer"
    change                = "modified"
    function_older        = 0x1000
    function_newer        = 0x1000
    cve                   = "CVE-2026-0001"
    analyst_label         = "Length check added"
    statement             = "Pattern present in the newer build and absent from the older build when analysed by PatchTrace. A match shows that a file contains the pattern and nothing else."

  strings:
    $t0 = "PatchTrace synthetic: index %u exceeds length %u" ascii

  condition:
    uint16(0) == 0x5A4D and
    pe.is_pe and
    pe.machine == pe.MACHINE_AMD64 and
    all of ($t*)
}
