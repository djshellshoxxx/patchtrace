// patchtrace-rule-export/1
// Rule PT_c71ccafacf84_older version 1, label "Terminate removed"
// Built by PatchTrace 0.1.0 with YARA-X 1.21.0 (BSD-3-Clause) and iced-x86 standin
// Project proj-r5, analysis run run-1
// Older build older.dll sha256 239639d1c9f4c181e535763c515d768193d79e42d52fa9552f495f85f9e88805; newer build newer.dll sha256 e7ed617adeac5f301b0dcca7b0d47d10e01e9493281d9203755ba07e1bf11054
// Source change: removed function at older RVA 0x104d, reviewed as material; function names omitted
// Accepted 2026-10-14T09:00:00+00:00. Tested 2026-10-14T10:00:00+00:00: 4 builds, 4 clean files, 0 unexpected matches, 0 not scanned
// Advisory anchors given by the analyst and not checked by this rule: CVE-2026-0001 KB5034123
// Origin: byte patterns copied from the analysed files on the analyst's computer. If those files are third-party software, check its licence before sharing this rule or committing it to a repository.
// A match means a file contains this pattern. It does not show whether the file is affected by a flaw.

import "pe"

rule PT_c71ccafacf84_older: patchtrace older_side {
  meta:
    patchtrace_rule_id    = "c71ccafacf84.v1"
    patchtrace_version    = 1
    patchtrace_project_id = "proj-r5"
    older_sha256          = "239639d1c9f4c181e535763c515d768193d79e42d52fa9552f495f85f9e88805"
    newer_sha256          = "e7ed617adeac5f301b0dcca7b0d47d10e01e9493281d9203755ba07e1bf11054"
    side                  = "older"
    change                = "removed"
    function_older        = "0x104d"
    cve                   = "CVE-2026-0001"
    kb                    = "KB5034123"
    capability            = "terminate process"
    analyst_label         = "Terminate removed"
    statement             = "A match means a file contains this pattern. It does not show whether the file is affected by a flaw."

  strings:
    $b = { 48 83 EC 28 48 C7 C1 FF FF FF FF 31 D2 FF 15 ?? ?? ?? ?? 48 83 C4 28 C3 }

  condition:
    uint16(0) == 0x5A4D and pe.is_pe and pe.machine == pe.MACHINE_AMD64
    and for any s in pe.sections: (s.characteristics & pe.SECTION_MEM_EXECUTE != 0 and $b in (s.raw_data_offset..s.raw_data_offset + s.raw_data_size))
    and pe.imports("KERNEL32.dll", "TerminateProcess")
    and for any i in (1..8): (
      i <= #b
      and for any d in pe.import_details: (
        d.library_name iequals "KERNEL32.dll"
        and for any f in d.functions: (
          f.name == "TerminateProcess"
          and f.rva == pe.sections[pe.section_index(@b[i])].virtual_address + @b[i] + 19 - pe.sections[pe.section_index(@b[i])].raw_data_offset + int32(@b[i] + 15)
        )
      )
    )
}
