Understand local data and privacy
A project stores more information than the visible comparison panes. Its contents include copied target inputs, a SQLite database, comparison output, run records, reviews, and notes.
Interpretation can also retain the exact context and raw provider response. These records can contain decompiled code even when an exported report excludes function code. PatchTrace does not encrypt project storage.
Desktop settings retain backend paths, window preferences, recent-project paths, and non-secret provider preferences. The documented interpretation credential is held in memory for the request and is not saved in settings or project records.
Before sharing a report:
1. Choose the intended finding scope.
2. Check Include function code, which defaults to off.
3. Check Include analyst notes, which defaults to on.
4. Read the exact preview.
5. Inspect names, notes, and technical details that remain.
The documented report exporter redacts absolute source paths and excludes raw provider responses, API keys, and complete context payloads. These exclusions do not establish that every remaining field is appropriate for your recipient.
Only selected findings limits the finding section. It does not anonymize all project or comparison metadata.
A full backup includes the underlying project material. Treat it according to the copied binaries, retained code, and research notes it contains.
Planned: separate user-facing export redaction controls are described as future work in the core UI specification.
Sources: README.md, “Export and share results” and “Projects, backups, and data handling”; docs/specs/ui.md.
