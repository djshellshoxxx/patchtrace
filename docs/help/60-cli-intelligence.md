# `patchtrace intelligence`

Works with advisory (CSAF 2.0) documents. Advisory facts are vendor claims with their source attached. Rule hypotheses are search guidance. Neither is verification that a function contains a vulnerability.

```
patchtrace intelligence import ...   # store a local CSAF 2.0 JSON file as an advisory source
patchtrace intelligence fetch ...    # download a CSAF advisory from msrc.microsoft.com (needs consent), or replay a cache
patchtrace intelligence explain ...  # explain a CVE for the older and newer artifacts from stored advisories (offline)
```

- `import` reads a file you already have. It makes no request.
- `fetch` contacts `msrc.microsoft.com` only with `--consent-hosts msrc.microsoft.com`. `--offline` uses only `--cache-dir` and needs no consent.
- `explain` reads stored advisories and sends nothing.

Read the source of every advisory statement before you use it. See [KB and CVE](29-kb-and-cve-investigation-panel.md) and [privacy and consent](17-network-use-and-consent.md).

Sources: `src/patchtrace/intelligence/cli.py` (`import`, `fetch`, `explain` registrations), top-level `patchtrace --help`.
