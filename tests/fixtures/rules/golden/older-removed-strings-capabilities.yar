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
    capability            = "create process"
    capability            = "terminate process"
    statement             = "A match means a file contains this pattern. It does not show whether the file is affected by a flaw."

  strings:
    $s1 = "Both \xe9\xff*/ }" ascii wide
    $s2 = "Wide text" wide
    $s3 = "say \"hello\" \\ world" ascii

  condition:
    uint16(0) == 0x5A4D and pe.is_pe and pe.machine == pe.MACHINE_AMD64
    and $s1
    and $s2
    and $s3
    and pe.imports("ADVAPI32.dll", "CreateProcessAsUserW")
    and pe.imports("KERNEL32.dll", "CreateProcessW")
    and pe.imports("KERNEL32.dll", "TerminateProcess")
}
