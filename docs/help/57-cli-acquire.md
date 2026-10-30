# `patchtrace acquire`

Gets two builds from the Microsoft symbol server and makes a project from them. Network use is explicit: a request needs a consent value that names the exact hosts.

```
patchtrace acquire search ...   # list Winbindex x64 build candidates (metadata only)
patchtrace acquire fetch ...    # download, verify and create a two-artifact project
```

- `search` asks the metadata host for candidate builds. It downloads no binaries and creates no project.
- `fetch` downloads both files, verifies them, and creates a project with the two artifacts. Its `--consent-hosts` value must name exactly `winbindex.m417z.com,msdl.microsoft.com`. `search` needs exactly `winbindex.m417z.com`. Any other value stops the command before a request.

Downloaded files are verified against the metadata before use and are never executed. Desktop equivalent: **File > Download from Microsoft symbol server…** (the Project menu). Its consent prompt is titled `Consent · Microsoft symbol server` and defaults to No. See [consent prompts](52-troubleshooting.md#consent-prompts).

Sources: `src/patchtrace/cli.py` (`acquire` parser, `cmd_acquire`), `src/patchtrace/ui.py` (menu label and consent text), `src/patchtrace/acquisition/transport.py`.
