# Windows output-path expectations

At bb98bae, Windows full QA had exactly two failures: JSON paths intentionally use forward slashes, while expectations used native backslashes. The two assertions now use the existing as_posix contract. Production code, validation, credit and overwrite rules are unchanged.

This is exactly the two-file subset from reviewed 4edf8f4. Independent reviewer checked full file byte identity and the two-line diff against bb98bae. Root selection: 71 passed in 2.04 s. Whole Ruff/diff checks pass. Original Windows logs/JUnit retained. Fresh hosted Windows/Qt/package/Sonar qualification required; no old result is extended to this head.
