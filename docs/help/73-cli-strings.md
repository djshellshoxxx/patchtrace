# `patchtrace strings`

Compares the strings of the two builds. The built-in scan reads the bytes of both files and does not run them. FLOSS is a separate tool, and this verb does not start it.

```
patchtrace strings list ...      # changed strings in review order
patchtrace strings delta ...     # the whole strings-delta/1 document
patchtrace strings explain ...   # links, reasons and provenance of one changed string
patchtrace strings scan ...      # built-in scan of both artifacts (no FLOSS)
patchtrace strings export ...    # write the delta to a JSON or CSV file (redacted by default)
```

- Strings that look like secrets are redacted unless you pass `--show-secrets`.
- Compare the extraction settings of both sides before you call a string added or removed. Incompatible settings leave the comparison unknown.
- A string in a file is not proof that a function uses it.

Desktop equivalent: the [Strings panel](25-strings-panel.md).

Sources: `src/patchtrace/strings/cli.py`, `src/patchtrace/cli_commands/strings.py`, top-level `patchtrace --help`.
