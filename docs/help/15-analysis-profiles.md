Use analysis profiles
Analysis profiles control enrichment and ranking options. Open the Profiles tab in Setup, then select a profile to inspect its configuration.
The default profile is read-only. Use New to start from default settings or Duplicate to copy a selected profile. Give the editable profile a name of up to 64 characters.
The documented fields include:
Field	Meaning
Detector enabled	Whether the detector contributes to ranking
Detector weight	Integer weight from 0 to 100
Windows Feature IDs	Comma-separated unsigned 32-bit IDs; empty means all
Symbol policy	Disabled or online
Maximum snapshot age	Integer from 1 to 3,650 days
Cache directory	Absolute directory; empty means no cache
Cache budget	Integer from 1 to 1,024 GiB
NVD provider	Whether the profile uses NVD advisory context
MSRC provider	Whether the profile uses Microsoft advisory context


Select Save profile to validate and write the edited profile. Resolve validation errors before relying on its settings. Saving Setup with unsaved profile edits prompts you to save those edits first.
Deleting a profile requires confirmation. The default profile cannot be deleted.
Weights affect attention ordering. They do not convert detector output into a calibrated estimate of a security property.
Selecting an advisory provider does not authorize an immediate network request. Online operations still require their documented explicit action.
UNVERIFIED: precedence between profile symbol policy and the backend symbol setting is not established by the reviewed user-facing descriptions. Check the effective run provenance.
Sources: docs/specs/ui.md; src/patchtrace/tooltips.py; README.md.
