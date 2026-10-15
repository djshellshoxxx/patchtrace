import "pe"

rule PT_0123456789ab_older: patchtrace older_side {
  meta:
    patchtrace_rule_id    = "0123456789ab.v1"
    patchtrace_version    = 1
    patchtrace_project_id = "project-1"
    older_sha256          = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    newer_sha256          = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    side                  = "older"
    change                = "removed"
    function_older        = "0x104d"
    statement             = "A match means a file contains this pattern. It does not show whether the file is affected by a flaw."

  strings:
    $b = { 48 83 EC 28 31 C9 BA 01 00 00 00 90 48 FF 15 ?? ?? ?? ?? 48 83 C4 28 C3 }

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
