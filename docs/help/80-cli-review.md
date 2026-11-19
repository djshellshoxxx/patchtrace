# `patchtrace review`

Review existing records through the same project service used by the desktop:

```console
patchtrace review match PROJECT --match ID --status accepted --json
patchtrace review finding PROJECT --finding ID --status needs-review --conclusion "Check the evidence" --json
patchtrace review note PROJECT --target ID --text "Analyst observation" --json
```

Use `--help` for allowed states and note kinds. A finding conclusion is preserved when omitted; an empty string clears it. Notes must be nonblank and at most 32767 characters. Targets must belong to the project. Service-owned correction and validation records cannot be created through the note command. Input text is data, never executed.

Opening a project for these commands does not repair interrupted jobs. Invalid input changes no project state. Exit codes: 0 success; 2 invalid input; 3 storage or lock failure; 5 cancelled. `--json` emits one `enrichment-cli/1` envelope.
