"""The user-visible text of the build-environment feature, in one place (DIE plan s8).

Wording rules: "may", "can", "matched by signature"; never a claim about how a file was built, never colour only
(`[!]` caution, `[i]` notice, ASCII). Untrusted values (`{name}`, `{hint}`, `{reason}`) are filled in by callers
through `display_text`. The banned-word sweep in the tests reads `deck_texts()`.
"""
from __future__ import annotations

from .contracts import FactKey, FactSource, TeachHook

DISCLAIMER = 'Names come from signatures and header fields; they are not proof of how a file was built.'

STATES = {
    'B0': 'Open a project to see the build environment.',
    'B1': 'Reading build environment: {side} ({done} of {total})...',
    'B2': ('Detect It Easy is not set up. Showing the checks PatchTrace makes itself (headers, Rich header, '
           'sections, imports). Names of compilers, packers and protectors need Detect It Easy.'),
    'B3': ('No toolchain change detected between OLDER and NEWER. Compiler options such as the optimization level '
           'cannot be read from a file, so code can still differ without source edits.'),
    'B4': ('Toolchain differs between OLDER and NEWER: {summary}. Some code differences can come from the build '
           "rather than from source edits. Matching rows are marked 'Build differs'; none are hidden."),
    'B5': 'The toolchain could not be compared: {reason}. Unknown is not treated as a difference.',
    'B6': 'Build environment is incomplete for {side}: {reason}. The other side is shown.',
    'B7': ('These build-environment results belong to a different file or tool setup and are shown for reference '
           'only.'),
    'B8': 'Build environment could not be read ({code}). Earlier results are unchanged.',
    'B9': ('Detect It Easy {version} is not supported by this PatchTrace build (accepted: 3.21). Showing the '
           'checks PatchTrace makes itself.'),
}

# variant -> (summary after the severity prefix, detail)
NOTICES = {
    'packed': ('{SIDE} looks packed ({name}, matched by signature).',
               'Function-level results may be incomplete or misleading for this file. PatchTrace does not unpack '
               'files.'),
    'packed-hint': ('{SIDE} may be packed (hint: {name}).',
                    'Hints from section layout or entropy can be wrong. Function-level results may be incomplete.'),
    'packed-one-side': ('only {SIDE} looks packed.',
                        'Comparing a packed file with an unpacked one does not show source changes.'),
    'protected': ('{SIDE} shows signs of a protector or obfuscator ({name}, matched by signature).',
                  'Results may be incomplete or misleading.'),
    'managed': ('{SIDE} is a .NET assembly with managed code only.',
                'PatchTrace compares native x64 code, so function results will be empty or misleading.'),
    'managed-mixed': ('{SIDE} is a .NET image that also holds native code.', 'Only the native part is compared.'),
    'installer': ('{SIDE} looks like an installer or self-extracting archive ({name}).',
                  'The program code may be inside its payload, which is not analyzed.'),
    'overlay-large': ('{SIDE} has {size} of data after its last section.', 'That data is not analyzed.'),
    'toolchain': ('the toolchain differs between OLDER and NEWER ({name}).',
                  'Some code differences may come from the build, not from source edits.'),
    'tool-unavailable': ("Detect It Easy is not set up, so only PatchTrace's own checks ran.", ''),
    'heuristic-only': ('{n} weak hints on {SIDE} were found and are not used as evidence.', ''),
    'stale-evidence': ('Detect It Easy results for OLDER and NEWER come from different tool setups and are not '
                       'compared.', ''),
    'sources-disagree': ('header checks and Detect It Easy disagree about the toolchain, so it is reported as '
                         'unknown.', ''),
}
GLYPHS = {'caution': '[!] Caution: ', 'notice': '[i] Notice: '}

ROW_CHIP = 'Build differs'
ROW_CHIP_DETAIL = ("This row's change classes ({classes}) can appear without a source edit when the toolchain "
                   'differs. Context only: the verdict is unchanged and the row is not hidden.')
NOISE_WHY = {
    'order': 'Change classes that often come from register allocation, layout or unwind data when the toolchain '
             'differs; the row may be listed after rows without such a cause.',
    'tag': 'Change classes that can come from code generation when the toolchain differs; the row is only marked.'}
TIMELINE_TOOLS_DIFFER = 'tool versions differ'
SUMMARY_TEXT = '{n} of {total} review rows are of kinds a toolchain change can produce'

REASONS = {
    'die-not-run': 'Detect It Easy has not run on both files',
    'die-one-side': 'Detect It Easy results exist for one file only',
    'die-versions-differ': 'Detect It Easy results come from different tool setups',
    'headers-unreadable': "a file's headers could not be read",
    'sources-disagree': 'header checks and Detect It Easy disagree',
    'header-only': 'only header fields differ, and those can be forged',
    'no-comparable-facts': 'no toolchain facts exist on both sides'}

FACT_LABELS: dict[FactKey, str] = {
    'compiler': 'Compiler', 'compiler_version': 'Compiler version', 'linker': 'Linker', 'linker_field': 'Linker field',
    'linker_rich': 'Linker (Rich header)', 'build_tool': 'Build tool', 'runtime_family': 'Runtime',
    'language': 'Language', 'target_os': 'Target system', 'subsystem': 'Subsystem',
    'os_version_field': 'OS version field', 'subsystem_version_field': 'Subsystem version field',
    'image_version_field': 'Image version field', 'rich_signature': 'Rich header', 'packer': 'Packer',
    'protector': 'Protector', 'installer': 'Installer', 'obfuscator': 'Obfuscator', 'managed': '.NET',
    'gs_cookie': 'Stack cookie', 'cfg': 'Control Flow Guard', 'aslr': 'ASLR', 'repro': 'Reproducible build',
    'debug_entry_types': 'Debug entry types', 'entropy_exec': 'Code entropy', 'overlay': 'Overlay bytes'}
STATUS_TEXT = {'changed': 'changed', 'added': 'added', 'removed': 'removed', 'unchanged': 'same',
               'one-sided-unknown': 'unknown (one side)'}
BASIS_TEXT: dict[FactSource, str] = {
    'pe-header': 'PE header field', 'rich-header': 'Rich header', 'debug-directory': 'Debug directory',
    'load-config': 'Load configuration', 'imports': 'Import names', 'clr-header': 'CLR header',
    'sections': 'Section layout', 'diec': 'Detect It Easy {version}, signature'}

TEACH = {hook.id: hook for hook in (
    TeachHook(id='build.toolchain_differs', meaning='Code can differ because the build tools differ.',
              next_steps=('Read rows marked Material first.', 'Open the Build environment card to see what changed.',
                          'If a pair built with the same toolchain exists, compare that pair too.')),
    TeachHook(id='build.packed', meaning='A packed file stores its code in compressed or encrypted form.',
              next_steps=('Treat function results as incomplete.',
                          'Look for unpacked builds of the same file; PatchTrace never runs or unpacks it.')),
    TeachHook(id='build.managed', meaning='A .NET assembly holds intermediate language, not native code.',
              next_steps=('Use a .NET-aware tool for the managed part.',
                          'Native results cover only the native part.')),
    TeachHook(id='build.installer', meaning='An installer carries the program in a payload.',
              next_steps=('Compare the installed files instead of the installer.',)),
    TeachHook(id='build.unknown', meaning='No toolchain information could be read for one side.',
              next_steps=('Set up Detect It Easy for names.', 'Unknown is not a difference.')),
    TeachHook(id='build.tool_missing', meaning='Names of compilers and packers come from Detect It Easy.',
              next_steps=('Open Setup and choose the console program.',)))}


def deck_texts() -> tuple[str, ...]:
    """Every fixed user-visible string, for the banned-word sweep."""
    flat = [DISCLAIMER, ROW_CHIP, ROW_CHIP_DETAIL, SUMMARY_TEXT, TIMELINE_TOOLS_DIFFER, *STATES.values(), *NOISE_WHY.values(),
            *REASONS.values(), *FACT_LABELS.values(), *STATUS_TEXT.values(), *BASIS_TEXT.values(), *GLYPHS.values()]
    flat += [text for pair in NOTICES.values() for text in pair]
    flat += [text for hook in TEACH.values() for text in (hook.meaning, *hook.next_steps)]
    return tuple(flat)
