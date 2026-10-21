# `patchtrace rules`

Detection rules are proposed from one accepted changed-function pair, tested against builds you name, and exported only when you ask. Proposing a rule does not accept it. Accepting a rule stores a version. It does not write a file.

```
patchtrace rules probe ...     # check that the rule engine starts here (no project needed)
patchtrace rules propose ...   # propose rules for one accepted changed-function pair; nothing is accepted
patchtrace rules show ...      # show the stored candidates and versions, or one of them
patchtrace rules decide ...    # accept, reject, defer or archive ONE candidate
patchtrace rules test ...      # scan builds with ONE rule version: the grid of matches and expectations
patchtrace rules export ...    # save ONE rule version as a .yar file on this computer; nothing is uploaded
patchtrace rules history ...   # decisions, versions, tests and exports in time order
```

- `decide` with accept needs `--label`.
- A test cell reads `Match`, `No match`, `Timed out`, `Error` or `Not scanned`. A file that could not be read or was too large stays `Not scanned`.
- A match on a local test set does not show general selectivity.

Desktop equivalent: the [Detection rules panel](28-detection-rules-panel.md). It shows proposed rules, the test grid and saved versions. It copies rule text and goes to the changed function. Decisions are made with `decide`.

Sources: `src/patchtrace/rules/cli.py`, `src/patchtrace/cli_commands/rules.py`, `src/patchtrace/rules/qt_panel.py`, top-level `patchtrace --help`.
