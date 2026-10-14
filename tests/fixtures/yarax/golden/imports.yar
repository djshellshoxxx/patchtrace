import "pe"

rule PT_0123456789ab_older: patchtrace older_side {
  meta:
    patchtrace_rule_id    = "0123456789ab.v1"
    patchtrace_version    = 1
    patchtrace_project_id = "proj-1"
    older_sha256          = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
    newer_sha256          = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
    side                  = "older"
    change                = "modified"
    function_older        = 0x104d
    function_newer        = 0x108d
    statement             = "Pattern present in the older build and absent from the newer build when analysed by PatchTrace. A match shows that a file contains the pattern and nothing else."

  condition:
    uint16(0) == 0x5A4D and
    pe.is_pe and
    pe.machine == pe.MACHINE_AMD64 and
    pe.imports("KERNEL32.dll", "TerminateProcess") and
    pe.imports("ntdll.dll", 7) != 0 and
    for any d in pe.delayed_import_details: (d.library_name iequals "ADVAPI32.dll" and for any f in d.functions: (f.name == "RegOpenKeyExW")) and
    for any d in pe.delayed_import_details: (d.library_name iequals "SHELL32.dll" and for any f in d.functions: (f.ordinal == 12))
}
