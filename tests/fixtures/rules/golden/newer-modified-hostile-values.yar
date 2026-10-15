import "pe"

rule PT_0123456789ab_newer: patchtrace newer_side {
  meta:
    patchtrace_rule_id    = "0123456789ab.v3"
    patchtrace_version    = 3
    patchtrace_project_id = "a\"b\\c\n}*/ import \"x\" condition: true // ?end\x00?"
    older_sha256          = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    newer_sha256          = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    side                  = "newer"
    change                = "modified"
    function_older        = "0x104d a\"b\\c\n}*/ import \"x\" condition: true // ?end\x00?"
    function_newer        = "0x108d a\"b\\c\n}*/ import \"x\" condition: true // ?end\x00?"
    cve                   = "a\"b\\c\n}*/ import \"x\" condition: true // ?end\x00?"
    kb                    = "a\"b\\c\n}*/ import \"x\" condition: true // ?end\x00?"
    cwe                   = "a\"b\\c\n}*/ import \"x\" condition: true // ?end\x00?"
    capability            = "a\"b\\c\n}*/ import \"x\" condition: true // ?end\x00?"
    analyst_label         = "a\"b\\c\n}*/ import \"x\" condition: true // ?end\x00?"
    statement             = "A match means a file contains this pattern. It does not show whether the file is affected by a flaw."

  strings:
    $b  = { 48 83 EC 28 31 C9 BA 01 00 00 00 48 FF 15 ?? ?? ?? ?? 90 48 FF 15 ?? ?? ?? ?? 48 83 C4 28 C3 }
    $s1 = "Hostile \x00\"\\ bytes \xff" ascii wide

  condition:
    uint16(0) == 0x5A4D and pe.is_pe and pe.machine == pe.MACHINE_AMD64
    and for any s in pe.sections: (s.characteristics & pe.SECTION_MEM_EXECUTE != 0 and $b in (s.raw_data_offset..s.raw_data_offset + s.raw_data_size))
    and $s1
    and pe.imports("a\"b\\c\n}*/ import \"x\" condition: true // end\x00", "a\"b\\c\n}*/ import \"x\" condition: true // end\x00")
    and pe.imports("a\"b\\c\n}*/ import \"x\" condition: true // end\x00", 12) > 0
    and pe.imports("a\"b\\c\n}*/ import \"x\" condition: true // end\x00z", "a\"b\\c\n}*/ import \"x\" condition: true // end\x00")
    and for any d in pe.delayed_import_details: (d.library_name iequals "a\"b\\c\n}*/ import \"x\" condition: true // end\x00" and for any f in d.functions: (f.name == "a\"b\\c\n}*/ import \"x\" condition: true // end\x00"))
    and for any d in pe.delayed_import_details: (d.library_name iequals "a\"b\\c\n}*/ import \"x\" condition: true // end\x00" and for any f in d.functions: (f.ordinal == 7))
    and for any i in (1..8): (
      i <= #b
      and for any d in pe.import_details: (
        d.library_name iequals "a\"b\\c\n}*/ import \"x\" condition: true // end\x00"
        and for any f in d.functions: (
          f.name == "a\"b\\c\n}*/ import \"x\" condition: true // end\x00"
          and f.rva == pe.sections[pe.section_index(@b[i])].virtual_address + @b[i] + 18 - pe.sections[pe.section_index(@b[i])].raw_data_offset + int32(@b[i] + 14)
        )
      )
      and for any d in pe.import_details: (
        d.library_name iequals "a\"b\\c\n}*/ import \"x\" condition: true // end\x001"
        and for any f in d.functions: (
          f.name == "a\"b\\c\n}*/ import \"x\" condition: true // end\x00"
          and f.rva == pe.sections[pe.section_index(@b[i])].virtual_address + @b[i] + 26 - pe.sections[pe.section_index(@b[i])].raw_data_offset + int32(@b[i] + 22)
        )
      )
    )
}
