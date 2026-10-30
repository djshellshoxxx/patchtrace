# PatchTrace help

PatchTrace compares an explicitly chosen older and newer Windows binary. These pages explain each panel, each command-line verb, and the states you will see. Panel titles and button labels are written as the desktop shows them.

Start with [Start here](01-start-here.md). For longer procedures, see the [repository guide](../guide/00-index.md).

## Getting started and projects

- [Start here](01-start-here.md) - Start here
- [Open PatchTrace on Windows](02-windows-first-launch.md) - Open PatchTrace on Windows
- [Explore the sample](03-explore-the-sample.md) - Explore the sample
- [Create a comparison project](04-create-a-comparison-project.md) - Create a comparison project
- [Run a native comparison](05-run-a-comparison.md) - Run a native comparison
- [Import an existing Ghidriff comparison](06-import-ghidriff-results.md) - Import an existing Ghidriff comparison
- [Navigate the workspace](07-navigate-the-workspace.md) - Navigate the workspace
- [Read older and newer code](08-read-paired-code.md) - Read older and newer code
- [Review and correct function relationships](09-review-and-correct-matches.md) - Review and correct function relationships
- [Save, reopen, and back up a project](10-save-reopen-and-back-up.md) - Save, reopen, and back up a project

## Backend, data and privacy

- [Configure the analysis backend](11-configure-the-analysis-backend.md) - Configure the analysis backend
- [Find existing runtime installations](12-find-existing-runtime-installations.md) - Find existing runtime installations
- [Install an offline backend bundle](13-install-an-offline-backend-bundle.md) - Install an offline backend bundle
- [Backend and desktop settings](14-backend-and-desktop-settings.md) - Backend and desktop settings
- [Use analysis profiles](15-analysis-profiles.md) - Use analysis profiles
- [Understand local data and privacy](16-local-data-and-privacy.md) - Understand local data and privacy

## Network, findings and evidence

- [Understand network use and consent](17-network-use-and-consent.md) - Understand network use and consent
- [Preview interpretation context](18-preview-and-send-interpretation-context.md) - Preview interpretation context
- [Review findings and record conclusions](19-review-findings-and-record-conclusions.md) - Review findings and record conclusions
- [Follow evidence and check provenance](20-follow-evidence-and-check-provenance.md) - Follow evidence and check provenance

## Panels

Each built panel is a dock. Open it from the **View** menu, or with its shortcut.

- [Engine evidence panel](21-engine-evidence-panel.md) - `Engine evidence` (`Ctrl+Shift+E`)
- [Unified panel](22-unified-panel.md) - `Unified` (`Ctrl+Shift+U`)
- [Search panel](23-search-panel.md) - `Search` (`Ctrl+Shift+F`)
- [Calls panel](24-call-graph-panel.md) - `Calls` (`Ctrl+Shift+G`)
- [Strings panel](25-strings-panel.md) - `Strings` (`Ctrl+Shift+T`)
- [Capabilities panel](26-capabilities-panel.md) - `Capabilities` (`Ctrl+Shift+A`)
- [Build environment panel](27-build-environment-panel.md) - `Build environment` (`Ctrl+Shift+B`)
- [Detection rules panel](28-detection-rules-panel.md) - `Detection rules` (`Ctrl+Shift+R`)
- [KB and CVE panel](29-kb-and-cve-investigation-panel.md) - `KB and CVE` (`Ctrl+Shift+K`)
- [Exploitation context panel](30-kev-context-panel.md) - `Exploitation context` (`Ctrl+Shift+X`)
- [Leads panel](31-leads-panel.md) - `Leads` (`Ctrl+Shift+L`)
- [Series panel](32-series-panel.md) - `Series` (no shortcut)
- [Files panel](33-files-panel.md) - `Files` (no shortcut)
- [Guide panel](34-guide-panel.md) - `Guide` (reserved; not built in this build)

## Reading results and states

- [Attention ranking and change signals](35-attention-ranking-and-change-signals.md) - Attention ranking and change signals
- [Read calibration and confidence labels](36-read-calibration-and-confidence-labels.md) - Read calibration and confidence labels
- [Distinguish pairing from change classification](37-pairing-and-change-classifications.md) - Distinguish pairing from change classification
- [Understand stale results](38-stale-results.md) - Understand stale results
- [Understand partial and missing evidence](39-partial-and-missing-evidence.md) - Understand partial and missing evidence
- [Resolve blocked and unsupported states](40-blocked-and-unsupported-states.md) - Resolve blocked and unsupported states
- [Read idle, loading, and ready states](41-idle-loading-and-ready-states.md) - Read idle, loading, and ready states
- [Handle errors, retries, and cancellation](42-errors-retries-and-cancellation.md) - Handle errors, retries, and cancellation
- [Read limits, truncation, and empty results](43-limits-truncation-and-empty-results.md) - Read limits, truncation, and empty results

## Settings, tools and navigation

- [Configure secondary comparison engines](44-configure-secondary-engines.md) - Configure secondary comparison engines
- [Check BinExport identity and orientation](45-check-binexport-identity-and-orientation.md) - Check BinExport identity and orientation
- [Read Hex, Binary, and Base64 views](46-read-hex-binary-and-base64.md) - Read Hex, Binary, and Base64 views
- [Preview and export reports](47-preview-and-export-reports.md) - Preview and export reports
- [Adjust display and accessibility preferences](48-display-and-accessibility-preferences.md) - Adjust display and accessibility preferences
- [Navigate panels with the keyboard](49-keyboard-and-command-navigation.md) - Navigate panels with the keyboard
- [Arrange and recover panel layout](50-panel-layout-and-recovery.md) - Arrange and recover panel layout

## Reference

- [Glossary](51-glossary.md) - Meanings of the terms used in these pages
- [Troubleshooting](52-troubleshooting.md) - Offline use, consent prompts, locked projects and `PT-` error codes

## Command-line verbs

Every verb is also listed by `patchtrace --help`. Each page gives the verb's subcommands and the matching desktop control, when one exists.

- [`rank`](53-cli-rank.md) - rank changed functions
- [`flags`](54-cli-flags.md) - WIL feature-flag transitions
- [`correlate`](55-cli-correlate.md) - rerank with CVE context
- [`cache`](56-cli-cache.md) - inspect or maintain the derived cache
- [`acquire`](57-cli-acquire.md) - download two builds from the Microsoft symbol server
- [`series`](58-cli-series.md) - build series over adjacent pairs
- [`secondary`](59-cli-secondary.md) - BinDiff, rz-diff and BinExport checks
- [`intelligence`](60-cli-intelligence.md) - advisory (CSAF) import, fetch and explain
- [`unified`](61-cli-unified.md) - derived, experimental unified result
- [`intel-tools`](62-cli-intel-tools.md) - capa, FLOSS and Detect It Easy evidence
- [`backend`](63-cli-backend.md) - bundled analysis runtime checks
- [`build-env`](64-cli-build-env.md) - build environment of each file
- [`fabric`](65-cli-fabric.md) - read stored anchors
- [`graph`](66-cli-graph.md) - call-graph explorer over stored call lists
- [`kb`](67-cli-kb.md) - KB and CVE correlation
- [`kev`](68-cli-kev.md) - CISA KEV catalog
- [`panels`](69-cli-panels.md) - list and check the panel manifest
- [`pilot`](70-cli-pilot.md) - ordered leads for changed pairs
- [`rules`](71-cli-rules.md) - detection rules
- [`search`](72-cli-search.md) - offline search of a project
- [`strings`](73-cli-strings.md) - string changes between the builds
- [`diaphora`](74-cli-diaphora.md) - import optional Diaphora result evidence
