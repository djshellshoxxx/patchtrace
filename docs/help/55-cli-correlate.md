# `patchtrace correlate`

Reranks a project's changed functions with CVE context. The base ranking from [`rank`](53-cli-rank.md) is not changed. Each candidate is ordered against the CVE you name.

```
patchtrace correlate <project> --cve CVE-YYYY-NNNN [--snapshot FILE] [--fetch] [--providers LIST] [--consent-providers LIST] [--api-key-env NAME] [--save-snapshot FILE] [--run RUN] [--profile NAME|FILE] [--dry-run] [--json]
```

- **Offline (default with `--snapshot`).** `--snapshot FILE` reads a CVE snapshot JSON that you saved earlier. No request is made.
- **Online (`--fetch`).** Retrieves the CVE from the providers. It needs `--consent-providers` with the same list as `--providers`. The default providers are `nvd,msrc`. Without a matching consent list the command does not contact a provider.
- **NVD key.** `--api-key-env` names an environment variable that holds an NVD API key. The key is read from that variable for the request.
- `--save-snapshot FILE` writes the normalized snapshots so that a later run can use `--snapshot`.

CVE context ranks candidates for reading. It does not establish that a function implements the CVE's fix. See [advisory context](51-glossary.md) and [KB and CVE](29-kb-and-cve-investigation-panel.md).

Sources: `src/patchtrace/cli.py` (`correlate` parser, `cmd_correlate`, `_normalize_available`), top-level `patchtrace --help`.
