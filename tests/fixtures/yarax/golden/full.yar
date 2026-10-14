import "pe"

rule PT_0123456789ab_older: patchtrace older_side {
  meta:
    patchtrace_rule_id    = "0123456789ab.v3"
    patchtrace_version    = 3
    patchtrace_project_id = "proj \"x\""
    patchtrace_status     = "unvetted"
    older_sha256          = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
    newer_sha256          = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
    side                  = "older"
    change                = "removed"
    function_older        = 0x104d
    function_older_name   = "FuncA"
    cve                   = "CVE-2024-0001"
    kb                    = "KB5000001"
    cwe                   = "CWE-20 CWE-787"
    capability            = "terminate process"
    analyst_label         = "Older build only"
    statement             = "Pattern present in the older build and absent from the newer build when analysed by PatchTrace. A match shows that a file contains the pattern and nothing else."

  strings:
    $b  = { C3 48 83 EC 28 48 8D 0D 70 10 00 00 FF 15 ?? ?? ?? ?? 48 89 C1 48 8D 15 }
    $t0 = "PATCHTRACE" ascii

  condition:
    uint16(0) == 0x5A4D and
    pe.is_pe and
    pe.machine == pe.MACHINE_AMD64 and
    for any s in pe.sections: (s.characteristics & pe.SECTION_MEM_EXECUTE != 0 and $b in (s.raw_data_offset..s.raw_data_offset + s.raw_data_size)) and
    for any i in (1..8): (i <= #b and for any d in pe.import_details: (d.library_name iequals "KERNEL32.dll" and for any f in d.functions: (f.name == "GetModuleHandleA" and pe.sections[pe.section_index(@b[i])].virtual_address + @b[i] - pe.sections[pe.section_index(@b[i])].raw_data_offset + 18 + int32(@b[i] + 14) == f.rva))) and
    for any i in (1..8): (i <= #b and for any d in pe.import_details: (d.library_name iequals "ntdll.dll" and for any f in d.functions: (f.name == "NtClose" and pe.sections[pe.section_index(@b[i])].virtual_address + @b[i] - pe.sections[pe.section_index(@b[i])].raw_data_offset + 18 + int32(@b[i] + 14) == f.rva))) and
    all of ($t*) and
    pe.imports("KERNEL32.dll", "TerminateProcess") and
    for any d in pe.import_details: (for any f in d.functions: (f.name == "ExitProcess")) and
    for any d in pe.import_details: (for any f in d.functions: (f.name == "TerminateProcess"))
}
