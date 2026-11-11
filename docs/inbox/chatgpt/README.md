# ChatGPT output inbox

Drop the raw text of each ChatGPT answer here (one file per prompt, for example `prompt1-panel-specs.md`; paste all of that
prompt's messages one after another). Claude then runs `python tools/split_chatgpt_output.py <file> --apply`, which writes
each `=== FILE: <path> ===` block to its path (docs/, tests/, tools/calibration/ only; never overwrites), and workers verify,
lint and integrate the result. Nothing here is trusted until verified: every SHA, CVE id and licence in the corpus output is
checked against the real source before it is used.
