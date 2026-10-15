import "pe"

rule PT_0123456789ab_newer: patchtrace newer_side {
  meta:
    patchtrace_rule_id    = "0123456789ab.v2"
    patchtrace_version    = 2
    patchtrace_project_id = "project-1"
    older_sha256          = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    newer_sha256          = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    side                  = "newer"
    change                = "modified"
    function_older        = "0x104d"
    function_newer        = "0x108d"
    cve                   = "CVE-2099-10001"
    kb                    = "KB5099001"
    cwe                   = "CWE-404"
    analyst_label         = "Example label"
    statement             = "A match means a file contains this pattern. It does not show whether the file is affected by a flaw."

  strings:
    $b  = { 48 83 EC 28 31 C9 BA 01 00 00 00 48 FF 15 ?? ?? ?? ?? 90 48 FF 15 ?? ?? ?? ?? 48 83 C4 28 C3 }
    $s1 = "Example string" ascii

  condition:
    uint16(0) == 0x5A4D and pe.is_pe and pe.machine == pe.MACHINE_AMD64
    and for any s in pe.sections: (s.characteristics & pe.SECTION_MEM_EXECUTE != 0 and $b in (s.raw_data_offset..s.raw_data_offset + s.raw_data_size))
    and $s1
    and for any i in (1..8): (
      i <= #b
      and for any d in pe.import_details: (
        d.library_name iequals "KERNEL32.dll"
        and for any f in d.functions: (
          f.name == "TerminateProcess"
          and f.rva == pe.sections[pe.section_index(@b[i])].virtual_address + @b[i] + 18 - pe.sections[pe.section_index(@b[i])].raw_data_offset + int32(@b[i] + 14)
        )
      )
      and for any d in pe.import_details: (
        d.library_name iequals "KERNEL32.dll"
        and for any f in d.functions: (
          f.name == "CloseHandle"
          and f.rva == pe.sections[pe.section_index(@b[i])].virtual_address + @b[i] + 26 - pe.sections[pe.section_index(@b[i])].raw_data_offset + int32(@b[i] + 22)
        )
      )
    )
}
