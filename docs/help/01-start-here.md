Start here
PatchTrace compares an explicitly chosen older and newer Windows binary. Use it to inspect changed functions, examine the evidence behind a proposed relationship, and record your conclusions.
The documented desktop target is Windows 11 x64. The initial input contract accepts PE AMD64 executables, DLLs, and drivers. A filename extension does not establish the file format or architecture. PatchTrace validates the input headers.
Choose your starting point:
Your starting material	Start with
No comparison data	Sample
Two versions of one binary	New, then Run comparison
An existing PatchTrace project	Open
Raw Ghidriff JSON for your exact binary pair	Open the corresponding project, then Import JSON


The desktop package includes its Python and Qt runtime. Running a native comparison requires a separately configured analysis backend. You can explore the sample, review imported results, and export reports without that backend.
PatchTrace performs static analysis. It does not launch either target binary or install a driver input. External analysis tools run as separate processes.
Keep three questions separate: whether functions correspond, what changed, and whether that change supports your research hypothesis. A matching score, attention score, or generated explanation does not answer all three.
UNVERIFIED: availability of newer panels in a particular downloadable release must be checked against that release. Repository implementation records do not establish that every recorded feature is packaged.
Sources: README.md; docs/windows.md; docs/modules.md; docs/qa.md.
