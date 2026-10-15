# Privacy and consent

Comparison, stored-evidence review, and local report creation do not require AI or automatic uploads. Network-capable operations require their own approval. Opening a project is not permission to fetch advisories or send selected code.

Before approving a request, read the exact host and preview. Downloading build metadata, obtaining public binaries, fetching advisory catalogs, and sending an AI interpretation request are different operations with different data. The [network guide](../guide/17-privacy-and-network.md) lists the repository's documented destinations and limitations; no live endpoint was verified here.

Interpret selection first builds a bounded context. Review the prompt, supplied records, omissions, endpoint, and model. Sending to a remote provider transmits the displayed text to that service. Cancelling a preview sends nothing; cancellation after transmission cannot recall data already sent.

Credentials are intended to remain session-only. Provider kind, model, and endpoint preferences can persist. Do not put a credential into a non-secret model or note field.

Projects retain local artifacts, raw analysis, notes, and interpretation material. Excluding code from a report does not remove it from the project. Inspect reports and sanitized logs before sharing.

External Ghidra, Java, and tool processes are outside an application-level network guard. A genuine air gap needs operating-system or network isolation.

Sources: [privacy guide](../guide/17-privacy-and-network.md) and [README](../../README.md). **UNVERIFIED:** transport enforcement, credential retention, log redaction, and external-process network behavior were not exercised here.
