import "pe"

rule PT_0123456789ab_newer: patchtrace newer_side {
  meta:
    patchtrace_rule_id    = "0123456789ab.v1"
    patchtrace_version    = 1
    patchtrace_project_id = "proj-1"
    older_sha256          = "a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1a1"
    newer_sha256          = "b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2b2"
    side                  = "newer"
    change                = "added"
    function_newer        = 0x108d
    statement             = "Pattern present in the newer build and absent from the older build when analysed by PatchTrace. A match shows that a file contains the pattern and nothing else."

  strings:
    $t0 = "Beep\x00\xff\"\\" ascii wide
    $t1 = "kernel32.dll" wide

  condition:
    uint16(0) == 0x5A4D and
    pe.is_pe and
    pe.machine == pe.MACHINE_AMD64 and
    all of ($t*) and
    pe.imports("KERNEL32.dll", "WriteFile")
}
