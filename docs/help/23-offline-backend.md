# Offline backend and disconnected work

The desktop package includes its own Python and Qt for project review. Native comparison additionally needs an analysis runtime. A prepared offline backend ZIP and a complete zero-download distribution are separate packaging paths.

Setup > Install offline backend ZIP consumes a local prepared archive. The repository describes inventory verification, bounded extraction, cancellation, and atomic installation. An independently obtained archive digest provides a separate integrity check; hashes stored inside an archive are not a signature of its publisher.

After installation, verify the selected backend Python, Ghidra root, and private Java paths in Setup. Diagnose dependencies checks prerequisites; it does not establish that every target pair can be compared. Preserve the prior runtime if verification or installation fails.

The existing guide states that a complete official runtime archive has not been accepted and that disconnected Windows acceptance remains open. Do not infer availability from the presence of an importer or builder. Read the release's actual artifact inventory before transferring a package.

On a disconnected machine, local sample review and stored output can still be useful without a backend. For native comparison, obtain a complete compatible runtime through the approved packaging workflow. Do not expect the app to download missing pieces silently.

Sources: [Windows setup](../windows.md) and [getting started](../guide/10-getting-started.md). **UNVERIFIED:** official bundle availability, component compatibility, installation rollback, relocation, and disconnected-VM comparison were not checked here.
