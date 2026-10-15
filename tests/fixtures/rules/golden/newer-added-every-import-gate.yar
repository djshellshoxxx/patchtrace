import "pe"

rule PT_0123456789ab_newer: patchtrace newer_side {
  meta:
    patchtrace_rule_id    = "0123456789ab.v1"
    patchtrace_version    = 1
    patchtrace_project_id = "project-1"
    older_sha256          = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
    newer_sha256          = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
    side                  = "newer"
    change                = "added"
    function_newer        = "0x108d ExampleAdded"
    statement             = "A match means a file contains this pattern. It does not show whether the file is affected by a flaw."

  condition:
    uint16(0) == 0x5A4D and pe.is_pe and pe.machine == pe.MACHINE_AMD64
    and pe.imports("KERNEL32.dll", "WriteFile")
    and pe.imports("KERNEL32.dll", 12) > 0
    and for any d in pe.delayed_import_details: (d.library_name iequals "DELAY.dll" and for any f in d.functions: (f.name == "LoadIt"))
    and for any d in pe.delayed_import_details: (d.library_name iequals "DELAY.dll" and for any f in d.functions: (f.ordinal == 7))
}
