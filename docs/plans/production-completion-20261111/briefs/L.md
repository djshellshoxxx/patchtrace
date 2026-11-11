# WORKSTREAM L - Documentation and developer experience
Scope: <main checkout>/README.md, docs/README.md, install.md, RUN.md, user-guide.md, cli-reference.md, concepts.md,
internals.md and docs/internals/, linux.md, windows.md, offline-backend.md, privacy.md, release-process.md,
version-history.md, notices.md, docs/guide/, docs/help/ (L6 lane: read-only), help/, site/ (GitHub Pages), docs/runbooks/,
SECURITY.md, CLAUDE.md, AGENTS.md, docs/audits/20261015-docs-drift.md,
docs/research/workspace-docs-reconciliation-20261106.md.
Wiki: the GitHub wiki cannot be reached from this sandbox; branch origin/docs/readme-and-wiki (PR #98) holds proposed wiki
pages - report what it contains (`git -C <main checkout> diff --stat origin/main...origin/docs/readme-and-wiki`).

Verify at least 40 specific, checkable claims across README.md, install.md, RUN.md, user-guide.md and cli-reference.md
against the real code/CLI (commands, flags, file paths, version numbers, supported platforms, default settings, feature
availability). Check commands with
`PYTHONPATH=<main checkout>/src QT_QPA_PLATFORM=offscreen python -m patchtrace <cmd> --help`.
Record each discrepancy as a defect with doc file:line, what the doc says and what is true.

Map the directive's required documents to what exists (path) / partial / missing: README; installation instructions;
quick-start guides; developer setup; architecture documentation; CLI reference; GUI user guide; API reference; adapter
documentation; CVE correlation specifications; patch recommendation specifications; troubleshooting; benchmark methodology;
security model; release notes; changelog; master TODO; development handoffs; wiki sections for Users (installation, getting
started, GUI workflows, CLI workflows, understanding comparison results, CVE and patch analysis, troubleshooting) and for
Developers (architecture, local setup, build procedures, testing, adapter development, database schemas, API contracts,
contribution guidelines, release process).
What is the current version string in code, the latest prerelease tag (`git -C <main checkout> tag --sort=-creatordate | head -3`),
and what does docs/version-history.md say?
actionable_now: doc fixes for verified discrepancies and genuinely missing documents (never duplicates of existing docs).
