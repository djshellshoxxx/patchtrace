"""CWE-driven patch hypotheses (SPEC-28 section H). Pure and deterministic.

Each rule describes the shapes a fix for one weakness family commonly takes: the expected patch operations,
the input sources and sinks involved, typical guards, API names worth searching for, and counterexamples
that look similar but are not fixes. A hypothesis is search guidance for the analyst and for SPEC-30; it is
never evidence that a function is vulnerable or fixed. ``required_observations`` and ``contradictions`` are
labelled data that SPEC-30 may evaluate against verified binary observations; 28b does not evaluate them.
"""
from __future__ import annotations

from ..enrichment.identity import domain_id
from .contracts import CweProfile, HypothesisSet, PatchHypothesis, Rule

RULES_VERSION = 'patch-rules/1'
CAVEAT = ('Patches need not follow common motifs: absence of these operations neither refutes the advisory nor '
          'the product mapping, and their presence does not establish the weakness in a function.')
LIMITATIONS = ('Hypotheses describe common fix shapes for a weakness class; they are search guidance only.',
               'Advisory CWE values and vocabulary matches are claims or interpretations, not binary observations.')
_NEGATIONS = ('does not allow', 'is not affected', 'not vulnerable')


def _rule(rule_id: str, family: str, cwes: tuple[str, ...], *, ops: tuple[str, ...], sources: tuple[str, ...] = (),
          sinks: tuple[str, ...] = (), guards: tuple[str, ...] = (), apis: tuple[str, ...] = (),
          observe: tuple[str, ...] = (), contra: tuple[str, ...] = (), counter: tuple[str, ...]) -> Rule:
    return Rule(id=rule_id, revision=1, family=family, cwe_patterns=cwes, negations=_NEGATIONS,
                required_observations=observe, contradictions=contra, expected_operations=ops, sources=sources,
                sinks=sinks, guards=guards, api_hints=apis, counterexamples=counter, caveat=CAVEAT)


_REFACTOR = 'existing check moved or duplicated by refactoring, inlining or compiler reordering'
RULES: tuple[Rule, ...] = (
    _rule('R-MEMORY-WRITE', 'memory-write', ('CWE-787', 'CWE-120', 'CWE-121', 'CWE-122', 'CWE-123'),
          ops=('new comparison of an index, length or count against the destination capacity before a copy, '
               'index or store', 'copy length clamped or recomputed from the destination size',
               'allocation size recomputed with checked arithmetic', 'early error return added before the write'),
          sources=('length, count or offset fields parsed from input', 'sizes supplied by user mode or the network'),
          sinks=('memory copy into a fixed or computed buffer', 'indexed array store', 'pointer-arithmetic write'),
          guards=('bounds check: index < capacity, offset + length <= size',
                  'checked arithmetic before the size is used', 'error status returned for oversize input'),
          apis=('memcpy', 'memmove', 'memcpy_s', 'RtlCopyMemory', 'RtlMoveMemory', 'RtlSizeTAdd', 'RtlULongMult',
                'ExAllocatePool2', 'ExAllocatePoolWithTag'),
          observe=('new or tightened comparison dominating a write in the changed function',
                   'value flow from the compared quantity to the write size or index'),
          contra=('the changed function performs no memory writes', 'only constants, strings or logging changed'),
          counter=('check added only for telemetry or logging', _REFACTOR)),
    _rule('R-MEMORY-READ', 'memory-read', ('CWE-125', 'CWE-126', 'CWE-127'),
          ops=('new comparison of an offset or length against the source size before a read or copy-out',
               'read length clamped to the available data', 'early error return added before the read'),
          sources=('offsets and lengths parsed from input',),
          sinks=('indexed load', 'memory copy from a buffer of computed size', 'string scan without a bound'),
          guards=('bounds check before the read', 'length-limited string functions'),
          apis=('memcpy', 'RtlCopyMemory', 'ProbeForRead', 'RtlStringCbLengthW', 'strnlen'),
          observe=('new comparison dominating a read of input-derived length',),
          contra=('the changed function performs no reads of the affected buffer',),
          counter=('bounds check added in unrelated parsing code', _REFACTOR)),
    _rule('R-BOUNDS', 'bounds', ('CWE-119', 'CWE-129', 'CWE-131', 'CWE-805'),
          ops=('bounds check added before an indexed access (read or write)', 'buffer size calculation corrected',
               'length parameter validated against the buffer it describes'),
          sources=('indices and lengths from input',), sinks=('indexed access', 'copy with a length parameter'),
          guards=('index < count', 'computed size compared with the allocation'),
          apis=('memcpy', 'RtlCopyMemory', 'RtlSizeTMult'),
          observe=('new comparison of an index or length dominating an access',),
          counter=('size constant changed for an unrelated feature', _REFACTOR)),
    _rule('R-LIFETIME', 'lifetime', ('CWE-416', 'CWE-415', 'CWE-672', 'CWE-825'),
          ops=('reference acquired before use and released after the last use',
               'pointer cleared or ownership transferred after release', 'release moved after the last use',
               'lock held across the use of the shared object', 'state flag checked before the object is reused'),
          sources=('object pointer or handle reachable from another thread or callback after release',),
          sinks=('free or release call', 'use of the object on a path that follows a release'),
          guards=('reference counting', 'null assignment after free', 'lock or rundown protection'),
          apis=('ObReferenceObject', 'ObDereferenceObject', 'ExFreePoolWithTag', 'ExFreePool', 'free',
                'InterlockedIncrement', 'InterlockedDecrement', 'ExAcquireRundownProtection',
                'ExReleaseRundownProtection'),
          observe=('new reference acquisition or release ordering change around the object',),
          contra=('no allocation, release or reference counting in the changed functions',),
          counter=('release moved for performance without changing reachability', 'logging of object state')),
    _rule('R-NULL-DEREF', 'null-deref', ('CWE-476',),
          ops=('NULL check added before a dereference', 'error path returns before the pointer is used',
               'allocation or lookup failure handled'),
          sources=('lookup or allocation that can fail', 'optional pointer from input'),
          sinks=('pointer dereference',), guards=('pointer != NULL check', 'status check of the producing call'),
          observe=('new NULL comparison dominating a dereference',),
          counter=('defensive NULL checks added across many unrelated functions',)),
    _rule('R-POINTER', 'pointer', ('CWE-822', 'CWE-824'),
          ops=('pointer validated before dereference (range, ownership or probe)', 'pointer initialized on every path',
               'user-mode pointer captured and checked according to the previous processor mode'),
          sources=('pointers supplied by user mode or embedded in input',), sinks=('dereference of the pointer',),
          guards=('ProbeForRead or ProbeForWrite in a try block', 'previous-mode check'),
          apis=('ProbeForRead', 'ProbeForWrite', 'ExGetPreviousMode', 'MmIsAddressValid'),
          observe=('new probe or mode check before the dereference',),
          counter=('structured exception handling added without a validation change',)),
    _rule('R-INTEGER', 'integer', ('CWE-190', 'CWE-191', 'CWE-197', 'CWE-681'),
          ops=('overflow-checked arithmetic replaces plain addition, subtraction or multiplication',
               'range check before the arithmetic', 'operand type widened', 'subtraction guarded against underflow'),
          sources=('counts, lengths and offsets from input',),
          sinks=('allocation size', 'loop bound', 'copy length', 'array index'),
          guards=('overflow-checked arithmetic helpers', 'comparison of operands before subtraction'),
          apis=('RtlULongAdd', 'RtlULongSub', 'RtlULongMult', 'RtlSizeTAdd', 'RtlSizeTMult', 'ULongAdd', 'SizeTMult',
                'UIntAdd'),
          observe=('new arithmetic check whose result guards a size, bound or index',),
          counter=('type change for an unrelated API signature', _REFACTOR)),
    _rule('R-TYPE', 'type', ('CWE-843', 'CWE-704'),
          ops=('object type or tag checked before a cast', 'discriminator of a variant or union validated',
               'object size validated for the expected type'),
          sources=('handles and objects supplied by callers',), sinks=('cast and member access',),
          guards=('object type parameter in a reference-by-handle call', 'tag comparison'),
          apis=('ObReferenceObjectByHandle', 'ObReferenceObjectByPointer'),
          observe=('new type or tag comparison before the member access',),
          counter=('type annotation changes without a runtime check',)),
    _rule('R-RACE', 'race', ('CWE-362', 'CWE-367'),
          ops=('lock acquired or widened around the shared state', 'interlocked operation replaces a read-modify-write',
               'user buffer captured once and validated (double fetch removed)',
               'reference taken before the lock is released'),
          sources=('state shared between threads, processes or user and kernel mode',),
          sinks=('check and use of the same state at different times',),
          guards=('lock', 'interlocked compare-exchange', 'single capture of user data'),
          apis=('ExAcquireFastMutex', 'KeAcquireSpinLock', 'ExAcquirePushLockExclusive', 'AcquireSRWLockExclusive',
                'InterlockedCompareExchange', 'EnterCriticalSection'),
          observe=('new synchronization around the state that is checked and later used',),
          counter=('lock added for performance statistics only', _REFACTOR)),
    _rule('R-AUTHN', 'authentication', ('CWE-287', 'CWE-290', 'CWE-306'),
          ops=('authentication decision added or tightened', 'credential or token validation added',
               'early deny path on failed authentication',
               'authentication state checked before the privileged operation'),
          sources=('credentials, tokens or session state from the client',),
          sinks=('privileged operation reachable without authentication',),
          guards=('authentication result checked', 'session state validated'),
          apis=('AcceptSecurityContext', 'LsaLogonUser', 'ImpersonateSecurityContext', 'QueryContextAttributesW'),
          observe=('new authentication check on the path to the operation',),
          counter=('authentication logging or telemetry changes',)),
    _rule('R-AUTHZ', 'authorization', ('CWE-284', 'CWE-285', 'CWE-269', 'CWE-732', 'CWE-862', 'CWE-863'),
          ops=('access check added before the operation', 'caller mode or privilege validated',
               'security descriptor or permissions tightened', 'impersonation added around the operation'),
          sources=('requests from less privileged callers',), sinks=('operation crossing a privilege boundary',),
          guards=('access check against a security descriptor', 'privilege check', 'previous-mode check'),
          apis=('SeAccessCheck', 'AccessCheck', 'SeSinglePrivilegeCheck', 'ExGetPreviousMode', 'RpcImpersonateClient',
                'ImpersonateNamedPipeClient'),
          observe=('new access or privilege check on the path to the operation',),
          counter=('permission changes on unrelated objects', 'audit-only changes')),
    _rule('R-PATH', 'path', ('CWE-22', 'CWE-59', 'CWE-73'),
          ops=('path canonicalized and checked against an allowed root', 'reparse points or symbolic links refused',
               'file opened while impersonating the caller', 'traversal components rejected'),
          sources=('file names and paths from callers or archives',), sinks=('file open, create, move or delete',),
          guards=('canonical prefix check', 'reparse-point refusal flags', 'impersonation'),
          apis=('ZwCreateFile', 'NtCreateFile', 'CreateFileW', 'GetFinalPathNameByHandleW', 'PathCchCanonicalizeEx',
                'RtlDosPathNameToNtPathName_U'),
          observe=('new path validation or open flags on the file operation',),
          counter=('path string changes for a renamed feature',)),
    _rule('R-INFO', 'info-exposure', ('CWE-200', 'CWE-209'),
          ops=('output buffer zeroed or fully initialized before copy-out', 'amount of data returned reduced',
               'sensitive fields removed from error messages'),
          sources=('kernel or service memory', 'error details'), sinks=('copy to the caller or the network',),
          guards=('zeroing before copy-out', 'length limited to initialized data'),
          apis=('RtlZeroMemory', 'RtlSecureZeroMemory', 'memset'),
          observe=('new zeroing or reduced copy length on a copy-out path',),
          counter=('message text edits without data flow changes',)),
    _rule('R-UNINIT', 'uninitialized', ('CWE-457', 'CWE-908', 'CWE-909'),
          ops=('variable or structure initialized on every path', 'allocation zeroed', 'padding cleared before copy-out'),
          sources=('stack or pool memory',), sinks=('use or copy-out of the uninitialized value',),
          guards=('initializer or zeroing call',), apis=('RtlZeroMemory', 'memset', 'ExAllocatePool2'),
          observe=('new initialization of the value before its use',),
          counter=('compiler-introduced initialization (InitAll) differences between builds',)),
    _rule('R-RESOURCE', 'resource', ('CWE-400', 'CWE-401', 'CWE-674', 'CWE-770', 'CWE-772', 'CWE-835'),
          ops=('limit, quota or depth bound added', 'resource released on error paths', 'loop exit condition corrected',
               'recursion depth bounded'),
          sources=('requests whose count or size the client controls',), sinks=('allocation, loop or recursion',),
          guards=('counter compared with a limit', 'cleanup on every exit path'),
          apis=('ExFreePoolWithTag', 'CloseHandle', 'ObDereferenceObject'),
          observe=('new limit or cleanup on the path that consumes the resource',),
          counter=('tuning of an existing constant limit',)),
    _rule('R-INPUT', 'input', ('CWE-20', 'CWE-1284'),
          ops=('validation added for a parsed field, size or count', 'value checked against protocol limits'),
          sources=('fields parsed from input',), sinks=('use of the parsed value',),
          guards=('comparison of the parsed value with allowed bounds',),
          observe=('new comparison on a parsed field',),
          counter=('generic hardening unrelated to the advisory', 'validation of unrelated fields')),
    _rule('R-INJECTION', 'injection', ('CWE-77', 'CWE-78', 'CWE-79', 'CWE-89', 'CWE-94'),
          ops=('input escaped or quoted before command, query or markup construction',
               'allowlist of commands or characters added', 'parameterized interface replaces string building'),
          sources=('strings from callers or documents',), sinks=('command, query or markup construction',),
          guards=('escaping or allowlist',), apis=('CreateProcessW', 'ShellExecuteW', 'system'),
          observe=('new escaping or allowlist on the string that reaches the sink',),
          counter=('string resource or localization changes',)),
    _rule('R-DESERIALIZATION', 'deserialization', ('CWE-502',),
          ops=('type allowlist or binder restriction added', 'deserialization of untrusted input removed or guarded'),
          sources=('serialized data from files or the network',), sinks=('object deserialization',),
          guards=('type allowlist',), observe=('new type restriction before deserialization',),
          counter=('serialization format version bump without restriction',)),
    _rule('R-SEARCH-PATH', 'search-path', ('CWE-426', 'CWE-427'),
          ops=('library loaded by absolute path', 'restricted search flags (system directory only) added',
               'default DLL directories restricted at startup'),
          sources=('current directory or writable search path entries',), sinks=('library or executable load',),
          guards=('search flags restricting the load to the system directory',),
          apis=('LoadLibraryExW', 'LoadLibraryW', 'SetDefaultDllDirectories', 'SetDllDirectoryW'),
          observe=('changed load flags or absolute path on the library load',),
          counter=('new optional dependency loaded the same way as before',)),
    _rule('R-CRYPTO-VERIFY', 'crypto-verify', ('CWE-295', 'CWE-347'),
          ops=('certificate chain or signature verification added or tightened',
               'verification result checked before the data is used'),
          sources=('certificates, signatures and signed data from the network or files',),
          sinks=('use of the data after verification',), guards=('verification status checked',),
          apis=('CertVerifyCertificateChainPolicy', 'CertGetCertificateChain', 'WinVerifyTrust', 'BCryptVerifySignature'),
          observe=('new verification call or result check before use',),
          counter=('algorithm list or policy constant changes only',)),
)
_BY_FAMILY = {rule.family: rule for rule in RULES}


def rules_digest() -> str:
    return domain_id('patch-rules', 1, [rule.model_dump(mode='json') for rule in RULES])


def rule_for(family: str) -> Rule | None:
    return _BY_FAMILY.get(family)


def hypotheses_for(profile: CweProfile) -> HypothesisSet:
    """One hypothesis per usable classification (explicit or phrase-match); weak, unmapped or missing CWEs
    become explicit unknowns instead of guesses."""
    hypotheses: list[PatchHypothesis] = []
    unknowns: list[str] = []
    for item in profile.classifications:
        if item.confidence == 'weak':
            unknowns.append(f'weak vocabulary match for {item.cwe_id} was not used for hypotheses')
            continue
        rule = _BY_FAMILY.get(item.family)
        if rule is None:
            unknowns.append(f'{item.cwe_id}: no curated rule for this weakness; no expected patch motif')
            continue
        hypotheses.append(PatchHypothesis(
            hypothesis_id=domain_id('patch-hypothesis', 1, {'cve': profile.cve, 'cwe': item.cwe_id, 'rule': rule.id,
                                                            'revision': rule.revision, 'basis': item.basis}),
            cwe_id=item.cwe_id, family=rule.family, rule_id=rule.id, rule_revision=rule.revision, basis=item.basis,
            expected_operations=rule.expected_operations, sources=rule.sources, sinks=rule.sinks, guards=rule.guards,
            api_hints=rule.api_hints, counterexamples=rule.counterexamples,
            required_observations=rule.required_observations, contradictions=rule.contradictions,
            caveat=rule.caveat))
    if not hypotheses:
        unknowns.insert(0, 'no usable CWE (explicit or confident vocabulary match): no expected patch motif')
    return HypothesisSet(cve=profile.cve, rules_version=RULES_VERSION, rules_digest=rules_digest(),
                         hypotheses=tuple(hypotheses), unknowns=tuple(unknowns), limitations=LIMITATIONS)
