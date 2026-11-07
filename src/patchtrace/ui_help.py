"""Static copy for the desktop workflow/dependency help dialog.

Kept outside the MainWindow host to preserve GUI seam budget without changing visible wording.
"""
from __future__ import annotations

WORKFLOW_HELP_TEXT = (
    '1. Create a project with explicit older and newer PE AMD64 artifacts, or open the synthetic sample.\n'
    '2. Import a Ghidriff JSON, or configure external dependencies and run comparison.\n'
    '3. Search and filter function matches. Inspect decompiled code, assembly and metadata.\n'
    '4. Review matches, correct relationships, and save analyst notes.\n'
    '5. Optionally select matches and Interpret. Review exact context before Send.\n'
    '6. Follow evidence, assess alternatives and unknowns, save an independent analyst conclusion.\n'
    '7. Export a report after reviewing its exact preview. Code is excluded by default.\n\n'
    'Dependency setup\n'
    'Use an external Python environment with the supported Ghidriff version installed. Select its\n'
    'python executable and the unpacked Ghidra installation in Setup. Ghidra requires a compatible\n'
    'Java installation. Diagnose reports dependency failures without running either target artifact.\n'
    'Ghidriff and Ghidra are not bundled and no dependency is downloaded automatically.\n\n'
    'Interpretation is optional. Ollama must use a loopback endpoint; OpenAI-compatible providers\n'
    'require HTTPS. API keys remain in memory for the current request and are never saved.\n'
    'Model assessments, match quality and review status do not establish vulnerability validity.\n'
    'Stale findings retain their original context and cannot navigate into a different analysis run.'
)
