# Build environment

**Planned:** the Build environment dock is reserved at Ctrl+Shift+B, tabbed with Engine evidence. The inspected branch has no buildenv panel implementation. The DIE plan describes build-environment observations and a pre-flight notice; these must not be presented as existing graphical controls.

Build facts help explain why two builds differ. A changed compiler, packer hint, section layout, or debug identity can introduce comparison noise. Such observations provide context for matching and decompilation limits; they do not establish the intention of a patch.

Use the existing [Files dock](18-files-panel.md) to inspect recorded hashes and available PE fields. The current tool guide also documents explicit Detect It Easy runs through intel-tools. A detector's compiler or packer identification is a tool observation with limitations, not an authoritative reconstruction of the build environment.

Read each side independently. If one tool run is missing or incompatible, the environment comparison is partial. Identical headers do not establish identical code, and a different timestamp does not prove which build is newer.

Do not confuse the planned Build environment dock with the separate Build facts modules noted as not fully wired in the existing guide. Their names describe related but distinct integration work.

Sources: [DIE plan](../specs/program-e/DIE-integration-plan.md) and [Files guide](../guide/15-files-and-pe-overview.md). **UNVERIFIED:** proposed pre-flight copy, graphical integration, native detector output, and Windows rendering were not checked here.
