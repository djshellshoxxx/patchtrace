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
- Export to a new filename to preserve an existing report. On Linux, an existing or concurrently created destination is refused even with `--force`; the command returns an error and leaves that destination intact. On Windows, `--force` requests replacement through the held-source publisher.
- Compare the extraction settings of both sides before you call a string added or removed. Incompatible settings leave the comparison unknown.
- A string in a file is not proof that a function uses it.

`list`, `delta`, `explain` and `export` accept `--source auto|floss|builtin`.
Automatic selection uses admitted stored FLOSS evidence independently for each
side and falls back to the built-in scan when that side has no usable result.
Explicit `floss` requires both sides; `builtin` does not read stored tools. A
storage integrity or capture-budget failure reports an error rather than hiding
that failure behind a fallback scan.

Use `--anchors FILE` to supply an optional local AnchorSet JSON file. The same
bounded strict reader and comparison rules are used by the dock. Anchor matches
are advisory hints and do not establish a vulnerability.

Desktop equivalent: the [Strings panel](25-strings-panel.md).

Sources: `src/patchtrace/strings/cli.py`, `src/patchtrace/cli_commands/strings.py`, top-level `patchtrace --help`.
