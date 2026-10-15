"""Fixed wording of the Strings panel (spec WB3 s8): states, labels and teach text. Pure data, no model, no Qt.

Every visible sentence avoids the words banned for evidence views (`test_banned_words`); a string is a reading
aid, never a finding.
"""
from __future__ import annotations

CHANGE_LABELS: dict[str, str] = {
    'only-newer': '+ Only in newer',
    'only-older': '- Only in older',
    'edited': '~ Edited',
    'both': '= In both',
    'representation-changed': '~ Stored differently',
    'not-compared': '? Not compared',
    'indeterminate': '? Not established',
}
TYPE_LABELS: dict[str, str] = {'static': 'Static', 'stack': 'Stack', 'tight': 'Tight loop', 'decoded': 'Decoded',
                               'language': 'Language'}
TYPE_NOUNS: dict[str, str] = {'static': 'Static string', 'stack': 'Stack string', 'tight': 'Tight-loop string',
                              'decoded': 'Decoded string', 'language': 'Language string'}
CUE_LABELS: dict[str, str] = {
    'message': 'Message', 'format': 'Format specifier', 'path': 'Path', 'registry': 'Registry key', 'url': 'URL',
    'guid': 'GUID', 'api-name': 'API name', 'dynamic-api': 'Dynamic API name', 'dll-name': 'DLL name',
    'pdb-path': 'PDB path', 'version': 'Version', 'identifier': 'Identifier', 'advisory-text': 'Advisory text',
    'advisory-api': 'Advisory API', 'lookalike': 'Look-alike', 'secret-like': 'Secret-like', 'resource': 'Resource',
    'noise-like': 'Noise-like'}
PAIR_LABELS: dict[str, str] = {'added': 'added', 'removed': 'removed', 'modified': 'modified',
                               'unchanged': 'unchanged', 'ambiguous': 'ambiguous', 'unknown': 'unmatched'}

STATES: dict[str, str] = {
    'no-project': 'Open a project to compare the strings of two builds.',
    'no-data': 'No strings have been extracted for this pair yet. The built-in scan needs no setup and reads both '
               'files without running them.',
    'running': 'Reading strings from the {side} build ({n} of 2)... {elapsed}. Cancel stops after the current '
               'file; nothing is saved from a cancelled run.',
    'ready': '{n} strings differ between the older and newer build. They are listed in review order, which is a '
             'reading order and not a finding.',
    'ready-none': 'No string differences found with these settings. Text this scan cannot extract (non-ASCII wide '
                  'text, compressed or encrypted data) is not covered.',
    'blocked': "These two scans used different settings, so differences would be misleading: {reason}. Re-scan the "
               "older build with the newer build's settings.",
    'incomplete': "The {side} scan stopped at the {limit} string limit. Added and removed marks are shown as '?' "
                  'because strings may be missing from that side.',
    'failed': 'String extraction stopped: {code}. {message} Earlier results were not changed.',
    'stale': 'The project changed after these strings were loaded. Reload to see the current results.',
    'floss-missing': 'FLOSS is not set up. You do not need it for plain strings. It is only needed for stack, '
                     'tight and decoded strings.',
    'floss-unsupported': 'This FLOSS build is not supported: {reason}. PatchTrace is tested with FLOSS 3.1.1.',
}
# Button labels. The card's "Copy safe" is "Copy escaped" here: the banned-word sweep rejects "safe".
ACTIONS: dict[str, str] = {
    'no-data': 'Scan both builds', 'blocked': 'Re-scan older', 'stale': 'Reload', 'copy-escaped': 'Copy escaped',
    'copy-exact': 'Copy exact...', 'open-function': 'Open function', 'open-hex': 'Open in hex',
    'hide-noise': 'Hide noise-like strings ({n} hidden)'}
SCOPES: dict[str, str] = {'differences': 'Differences', 'all': 'All strings'}

_CUE_TEACH = {
    'message': ('A message is readable text a program shows or logs.',
                'Compare it with the other build and open the function that uses it.'),
    'format': ('A format string shows which values a message prints or copies.',
               'Open the function and look at what the new specifier or width limit sits next to.'),
    'path': ('A path names a file, folder or device the program touches.',
             'Check which function opens it and whether the other build used the same path.'),
    'registry': ('A registry key names a setting store the program reads or writes.',
                 'Find the function that uses the key and compare how its result is handled.'),
    'url': ('A URL names a network address the program may contact.',
            'Check which function builds the request; PatchTrace never contacts it.'),
    'guid': ('A GUID names an interface, class or object by a unique identifier.',
             'Search the other build for the same GUID to see whether it moved.'),
    'api-name': ('An API name is the text of a system function the program may look up.',
                 'Open the function that holds it and see how the name is resolved.'),
    'dynamic-api': ('A dynamic API name is a function name the program can resolve while it runs.',
                    'Compare the imports of both builds; the call may not show in the import table.'),
    'dll-name': ('A DLL name is the library the program may load.',
                 'Check which function loads it and whether the other build loaded the same library.'),
    'pdb-path': ('A PDB path is the build-time location of debug symbols stored in the file.',
                 'Use it as build information only; it says nothing about behavior.'),
    'version': ('A version string identifies a build or component.',
                'Compare it with the other build to confirm which release each file is.'),
    'identifier': ('An identifier looks like a name from source code, such as a function or class.',
                   'Search the function list for the same name.'),
    'advisory-text': ('Advisory text shares wording with an advisory you imported for this project.',
                      'Read the advisory sentence next to the string; shared wording is a lead, not a finding.'),
    'advisory-api': ('An advisory API is a function name an imported advisory mentions.',
                     'Open the function that references it and compare both builds.'),
    'lookalike': ('A look-alike string differs from another only by characters that appear alike.',
                  'Read the code point list in the detail view to see which characters differ.'),
    'secret-like': ('A secret-like string resembles a key or token and is hidden by default.',
                    'Keep it hidden unless you need the exact text; copy it only on purpose.'),
    'resource': ('A resource string comes from the resource section, usually interface text.',
                 'Treat it as display text; it rarely shows how code behaves.'),
    'noise-like': ('A noise-like string has little structure and may be data rather than text.',
                   'Skip it unless a linked function makes it interesting.'),
}
_REASON_TEACH = {
    'pair-modified': ('The function that uses this string changed between the builds.',
                      'Open the function pair and read the change around the string.'),
    'pair-added': ('The function that uses this string exists only in the newer build.',
                   'Read the whole new function; there is no older version to compare.'),
    'pair-removed': ('The function that uses this string exists only in the older build.',
                     'Check whether the newer build moved its work somewhere else.'),
    'relocated': ('The string is in both builds but sits at a different place.',
                  'Check the linked functions to see whether the use also moved.'),
    'representation': ('The same text is stored in a different form, such as another encoding.',
                       'Open the detail view to see how each build stores it.'),
    'lookalike': ('The two strings look the same but use different characters.',
                  'Compare the code points in the detail view.'),
    'format-spec': ('The edit changes a format specifier or its width.',
                    'Open the function and read what receives the formatted value.'),
    'emulation': ('The string was found by running code in an emulator, which can miss or invent strings.',
                  'Treat absence as unknown and confirm the string in the code.'),
    'noise': ('The string has little structure, so it is listed last.',
              'Skip it unless a link makes it relevant.'),
    'resource': ('The string comes from resource data, so it is listed last.',
                 'Skip it unless you are reading interface text.'),
    'api': ('The string names an API, path, key or address.',
            'Open the function that uses it and see what it does with the name.'),
    'not-established': ('One scan was incomplete, so this difference cannot be confirmed.',
                        'Re-scan with a higher limit before reading anything into it.'),
    'other-difference': ('The string differs between the builds and no rule ranks it higher.',
                         'Read it in context if a linked function is of interest.'),
}
_LINK_TEACH = {
    'L1': ('A Ghidra reference lists this string in the function.',
           'Open the function to see where the reference sits.'),
    'L2': ('An intermediate-representation reference ties the string to the function.',
           'Open the function and follow the reference.'),
    'L3': ('A capability rule ties the string to the function.',
           'Open the function and read the matched rule.'),
    'L4': ('The decompiled code of the function contains this text as a literal.',
           'Open the function and find the literal in the code.'),
    'L5': ('A FLOSS call frame names the function that produced the string.',
           'Open the function; the string came from running it in an emulator.'),
    'L6': ('A manual link was added by you.',
           'Check the note you left for the reason.'),
}
_STATE_TEACH = {
    'no-project': ('No project is open, so there are no builds to compare.', 'Open a project, then scan.'),
    'no-data': ('Nothing has been extracted for this pair.', 'Run the built-in scan on both builds.'),
    'running': ('A scan is reading one build.', 'Wait, or cancel to discard the run.'),
    'ready': ('The scans are comparable and the differences are listed in review order.',
              'Start at the top and open linked functions.'),
    'ready-none': ('The scans found no difference in the text they can read.',
                   'Do not read this as no change; other text is not covered.'),
    'blocked': ('The two scans used different settings.', "Re-scan the older build with the newer one's settings."),
    'incomplete': ('One scan hit its string limit.', 'Treat added and removed marks as unknown for that build.'),
    'failed': ('Extraction stopped with an error.', 'Read the code and message, then retry.'),
    'stale': ('The project changed after loading.', 'Reload the results.'),
    'floss-missing': ('FLOSS is optional.', 'Set its path only if you need stack, tight or decoded strings.'),
    'floss-unsupported': ('This FLOSS build is not one PatchTrace tests.', 'Use the pinned build.'),
}
TEACH: dict[str, tuple[str, str]] = {
    **{f'strings.cue.{key}': value for key, value in _CUE_TEACH.items()},
    **{f'strings.reason.{key}': value for key, value in _REASON_TEACH.items()},
    **{f'strings.link.{key}': value for key, value in _LINK_TEACH.items()},
    **{f'strings.state.{key}': value for key, value in _STATE_TEACH.items()},
}
