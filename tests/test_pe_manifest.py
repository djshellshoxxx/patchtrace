"""RT_MANIFEST reader: facts, namespace strictness, encodings, DTD and entity refusal, caps, malformed XML."""
from __future__ import annotations

import codecs
import hashlib
import json
import socket
import tempfile
import time
from dataclasses import asdict
from pathlib import Path

import pytest
from hypothesis import HealthCheck, given, settings
from hypothesis import strategies as st
from pe_rsrc_builder import (
    LANG_EN_US,
    RT_MANIFEST,
    Data,
    mutate,
    open_pe,
    real_launchers,
    rsrc_pe,
    tree,
)

from patchtrace.artifact_bytes import ArtifactBytesError
from patchtrace.pe_overview._common import Cancelled
from patchtrace.pe_overview.manifest import (
    AssemblyIdentity,
    ManifestFile,
    observe_manifest,
    parse_manifests,
)
from patchtrace.pe_overview.resources import (
    DEFAULT_RESOURCE_LIMITS,
    ResourceLeaf,
    ResourceLimits,
    parse_resources,
)

FAST = settings(deadline=None, suppress_health_check=[HealthCheck.too_slow], max_examples=150)
LEAF = ResourceLeaf(RT_MANIFEST, 'RT_MANIFEST', 1, LANG_EN_US, 0x2000, 0, 0, 0x400)
V1 = 'urn:schemas-microsoft-com:asm.v1'
V3 = 'urn:schemas-microsoft-com:asm.v3'
COMPAT = 'urn:schemas-microsoft-com:compatibility.v1'
WS = 'http://schemas.microsoft.com/SMI/{}/WindowsSettings'

FULL = f'''<?xml version="1.0" encoding="UTF-8" standalone="yes"?>
<assembly xmlns="{V1}" manifestVersion="1.0">
  <assemblyIdentity type="win32" name="Example.App" version="1.2.3.4" processorArchitecture="amd64"
                    publicKeyToken="0123456789abcdef"/>
  <dependency>
    <dependentAssembly>
      <assemblyIdentity type="win32" name="Microsoft.Windows.Common-Controls" version="6.0.0.0"
                        processorArchitecture="*" publicKeyToken="6595b64144ccf1df" language="*"/>
    </dependentAssembly>
  </dependency>
  <trustInfo xmlns="{V3}">
    <security><requestedPrivileges>
      <requestedExecutionLevel level="asInvoker" uiAccess="false"/>
    </requestedPrivileges></security>
  </trustInfo>
  <compatibility xmlns="{COMPAT}">
    <application>
      <supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}"/>
      <supportedOS Id="{{1F676C76-80E1-4239-95BB-83D0F6D0DA78}}"/>
    </application>
  </compatibility>
  <application xmlns="{V3}">
    <windowsSettings>
      <dpiAware xmlns="{WS.format(2005)}">true/pm</dpiAware>
      <dpiAwareness xmlns="{WS.format(2016)}">PerMonitorV2, PerMonitor</dpiAwareness>
      <longPathAware xmlns="{WS.format(2016)}">true</longPathAware>
      <activeCodePage xmlns="{WS.format(2019)}">UTF-8</activeCodePage>
    </windowsSettings>
  </application>
  <file name="helper.dll" hash="da39a3ee5e6b4b0d3255bfef95601890afd80709" hashalg="SHA1"/>
</assembly>
'''


def observe(text: str | bytes, limits=DEFAULT_RESOURCE_LIMITS):
    raw = text.encode('utf-8') if isinstance(text, str) else text
    return observe_manifest(LEAF, raw, limits=limits)


def shell(body: str) -> str:
    return f'<assembly xmlns="{V1}" manifestVersion="1.0">{body}</assembly>'


def run(tmp_path, root, limits=DEFAULT_RESOURCE_LIMITS, stage_limits=None):
    """Observations and warning codes; `stage_limits` apply to the manifest stage only."""
    data, _info = rsrc_pe(root)
    with open_pe(tmp_path, data) as pe:
        inventory = parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size, limits)
        return parse_manifests(pe.ctx, pe.smap, inventory, stage_limits or limits), pe.codes()


def empty(observation) -> bool:
    return (observation.execution_level, observation.ui_access, observation.supported_os, observation.dpi_awareness,
            observation.long_path_aware, observation.active_code_page, observation.identity,
            observation.dependencies, observation.files) == (None, None, (), None, None, None, None, (), ())


# -- facts --------------------------------------------------------------------------------------------------------


def test_a_typical_manifest_yields_every_fact():
    obs = observe(FULL)
    assert obs.warnings == () and obs.leaf is LEAF
    assert obs.sha256 == hashlib.sha256(FULL.encode()).hexdigest()
    assert obs.identity == AssemblyIdentity('Example.App', '1.2.3.4', 'amd64', '0123456789abcdef', 'win32')
    assert obs.dependencies == (AssemblyIdentity('Microsoft.Windows.Common-Controls', '6.0.0.0', '*',
                                                 '6595b64144ccf1df', 'win32'),)
    assert (obs.execution_level, obs.ui_access) == ('asInvoker', False)
    assert obs.supported_os == ('{1f676c76-80e1-4239-95bb-83d0f6d0da78}', '{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}')
    assert (obs.dpi_awareness, obs.long_path_aware, obs.active_code_page) == ('PerMonitorV2, PerMonitor', True, 'UTF-8')
    assert obs.files == (ManifestFile('helper.dll', 'da39a3ee5e6b4b0d3255bfef95601890afd80709', 'SHA1'),)


def test_an_elevated_ui_access_manifest():
    body = f'''<trustInfo xmlns="{V3}"><security><requestedPrivileges>
        <requestedExecutionLevel level="requireAdministrator" uiAccess="TRUE"/></requestedPrivileges></security></trustInfo>'''
    obs = observe(shell(body))
    assert (obs.execution_level, obs.ui_access) == ('requireAdministrator', True)


def test_a_bare_manifest_has_only_what_it_declares():
    obs = observe(shell('<assemblyIdentity type="win32" name="Bare" version="1.0.0.0"/>'))
    assert obs.warnings == () and obs.identity == AssemblyIdentity('Bare', '1.0.0.0', None, None, 'win32')
    assert (obs.execution_level, obs.ui_access, obs.supported_os, obs.dpi_awareness, obs.long_path_aware,
            obs.active_code_page, obs.dependencies, obs.files) == (None, None, (), None, None, None, (), ())


def test_legacy_dpi_aware_is_used_when_dpi_awareness_is_absent():
    body = f'<application xmlns="{V3}"><windowsSettings><dpiAware xmlns="{WS.format(2005)}">True/PM</dpiAware>' \
           f'</windowsSettings></application>'
    assert observe(shell(body)).dpi_awareness == 'True/PM'


def test_prefixed_elements_and_mixed_trust_namespaces_are_read():
    text = f'''<assembly xmlns="{V1}" xmlns:asmv3="{V3}" manifestVersion="1.0">
      <trustInfo xmlns="urn:schemas-microsoft-com:asm.v2"><security>
        <requestedPrivileges xmlns="{V3}"><requestedExecutionLevel level="highestAvailable" uiAccess="false"/>
        </requestedPrivileges></security></trustInfo>
      <asmv3:application><asmv3:windowsSettings xmlns:ws2="{WS.format(2016)}">
        <ws2:longPathAware>true</ws2:longPathAware></asmv3:windowsSettings></asmv3:application></assembly>'''
    obs = observe(text)
    assert (obs.execution_level, obs.long_path_aware, obs.warnings) == ('highestAvailable', True, ())


@pytest.mark.parametrize('body,field', [
    (f'<application xmlns="{V3}"><windowsSettings><longPathAware xmlns="{WS.format(2005)}">true</longPathAware>'
     f'</windowsSettings></application>', 'long_path_aware'),
    (f'<application xmlns="{V3}"><windowsSettings><dpiAwareness xmlns="{WS.format(2005)}">system</dpiAwareness>'
     f'</windowsSettings></application>', 'dpi_awareness'),
    ('<trustInfo xmlns="urn:schemas-microsoft-com:asm.v1"><security><requestedPrivileges><requestedExecutionLevel '
     'level="requireAdministrator"/></requestedPrivileges></security></trustInfo>', 'execution_level'),
    (f'<trustInfo xmlns="{V3}"><requestedPrivileges><requestedExecutionLevel level="requireAdministrator"/>'
     f'</requestedPrivileges></trustInfo>', 'execution_level'),
    (f'<compatibility xmlns="{V1}"><application><supportedOS Id="{{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}}"/>'
     f'</application></compatibility>', 'supported_os'),
    (f'<application xmlns="{V3}"><longPathAware xmlns="{WS.format(2016)}">true</longPathAware></application>',
     'long_path_aware'),
], ids=['setting-in-wrong-year', 'awareness-in-2005', 'trust-in-v1', 'trust-path-incomplete', 'compat-in-v1',
        'setting-outside-windowssettings'])
def test_elements_in_the_wrong_place_are_not_reported(body, field):
    value = getattr(observe(shell(body)), field)
    assert value in (None, ())


@pytest.mark.parametrize('text', [
    '<assembly manifestVersion="1.0"/>', f'<html xmlns="{V1}"/>', '<assembly xmlns="urn:example:other"/>',
], ids=['no-namespace', 'wrong-root', 'wrong-namespace'])
def test_a_document_that_is_not_an_assembly_manifest_is_invalid(text):
    obs = observe(text)
    assert obs.warnings == ('manifest_xml_invalid',) and empty(obs)


def test_unusable_values_are_not_guessed():
    body = f'''<trustInfo xmlns="{V3}"><security><requestedPrivileges>
        <requestedExecutionLevel level="asInvoker" uiAccess="maybe"/></requestedPrivileges></security></trustInfo>
        <compatibility xmlns="{COMPAT}"><application><supportedOS Id="not-a-guid"/><supportedOS/>
        <supportedOS Id="8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a"/></application></compatibility>
        <application xmlns="{V3}"><windowsSettings><longPathAware xmlns="{WS.format(2016)}">yes</longPathAware>
        </windowsSettings></application>'''
    obs = observe(shell(body))
    assert (obs.execution_level, obs.ui_access, obs.supported_os, obs.long_path_aware) == ('asInvoker', None, (), None)


def test_attribute_text_is_cleaned_and_capped():
    name = 'Evil\u202eexe.\u0085app\u2028' + 'N' * 400
    obs = observe(shell(f'<assemblyIdentity type="win32" name="{name}" version="1.0.0.0"/>'))
    assert obs.identity.name.startswith('Evilexe.app') and len(obs.identity.name) == 256 and obs.warnings == ()


def test_supported_os_is_sorted_and_deduplicated():
    ids = [f'{{{n:08x}-0000-0000-0000-00000000000{n % 10}}}' for n in (0x9a, 0x1f, 0xc3, 0x07, 0xe1, 0x55, 0x2b, 0xd8,
                                                                       0x68, 0x4c, 0xb0, 0x93)]
    items = ''.join(f'<supportedOS Id="{guid.upper()}"/>' for guid in ids + ids[:3])
    obs = observe(shell(f'<compatibility xmlns="{COMPAT}"><application>{items}</application></compatibility>'))
    assert obs.supported_os == tuple(sorted(ids)) and len(obs.supported_os) == 12


def test_application_identity_is_a_direct_child_of_the_assembly():
    nested_first = shell('<dependency><dependentAssembly><assemblyIdentity name="Dep" version="1.0.0.0"/>'
                         '</dependentAssembly></dependency><assemblyIdentity name="App" version="2.0.0.0"/>')
    obs = observe(nested_first)
    assert obs.identity.name == 'App' and [d.name for d in obs.dependencies] == ['Dep']
    only_nested = shell('<dependency><dependentAssembly><assemblyIdentity name="Dep"/></dependentAssembly></dependency>')
    assert observe(only_nested).identity is None


def test_identities_under_the_wrong_parent_are_not_dependencies():
    body = ('<dependency><assemblyIdentity name="Bare"/></dependency>'
            '<dependency><dependentAssembly><wrapper><assemblyIdentity name="Deep"/></wrapper></dependentAssembly>'
            '<dependentAssembly/></dependency>')
    assert observe(shell(body)).dependencies == ()


def test_list_facts_are_capped_and_reported():
    files = ''.join(f'<file name="f{i}.dll"/>' for i in range(300))
    obs = observe(shell(files))
    assert len(obs.files) == 256 and obs.warnings == ('manifest_over_cap',)
    guids = ''.join(f'<supportedOS Id="{{00000000-0000-0000-0000-{i:012d}}}"/>' for i in range(300))
    obs = observe(shell(f'<compatibility xmlns="{COMPAT}"><application>{guids}</application></compatibility>'))
    assert len(obs.supported_os) == 256 and obs.warnings == ('manifest_over_cap',)


# -- encodings --------------------------------------------------------------------------------------------------------

ENCODINGS = {
    'utf8': lambda text: text.encode('utf-8'),
    'utf8-bom': lambda text: codecs.BOM_UTF8 + text.encode('utf-8'),
    'utf16le-bom': lambda text: codecs.BOM_UTF16_LE + text.encode('utf-16-le'),
    'utf16be-bom': lambda text: codecs.BOM_UTF16_BE + text.encode('utf-16-be'),
    'utf16le': lambda text: text.encode('utf-16-le'),
    'utf16be': lambda text: text.encode('utf-16-be'),
}


@pytest.mark.parametrize('encoding', list(ENCODINGS))
def test_supported_encodings_give_the_same_facts(encoding):
    obs = observe(ENCODINGS[encoding](FULL))
    assert obs.warnings == () and obs.identity.name == 'Example.App' and obs.long_path_aware is True
    assert obs.sha256 == hashlib.sha256(ENCODINGS[encoding](FULL)).hexdigest()


@pytest.mark.parametrize('raw', [
    b'<assembly xmlns="' + V1.encode() + b'"><!-- \xc3\x28 --></assembly>',
    codecs.BOM_UTF32_LE + FULL.encode('utf-32-le'),
    codecs.BOM_UTF32_BE + FULL.encode('utf-32-be'),
    codecs.BOM_UTF16_LE + FULL.encode('utf-16-le')[:-1],
    codecs.BOM_UTF16_LE + b'<\x00\x00\xd8>\x00',
    b'<?xml version="1.0" encoding="windows-1252"?><assembly xmlns="' + V1.encode() + b'" a="\xe9"/>',
], ids=['invalid-utf8', 'utf32-le', 'utf32-be', 'odd-utf16', 'lone-surrogate-utf16', 'latin1-declared'])
def test_other_encodings_and_undecodable_bytes_are_unsupported(raw):
    obs = observe(raw)
    assert obs.warnings == ('manifest_encoding_unsupported',) and empty(obs) and obs.sha256 == hashlib.sha256(raw).hexdigest()


def test_the_declared_encoding_is_ignored_because_the_text_was_decoded_here():
    obs = observe(FULL.replace('encoding="UTF-8"', 'encoding="utf-16"'))
    assert obs.warnings == () and obs.identity.name == 'Example.App'


@pytest.mark.parametrize('encoding', list(ENCODINGS))
def test_trailing_nul_padding_is_tolerated(encoding):
    unit = 2 if encoding.startswith('utf16') else 1
    assert observe(ENCODINGS[encoding](FULL) + b'\0' * 3 * unit).warnings == ()


# -- DTD and entity refusal -------------------------------------------------------------------------------------------

DANGEROUS = {
    'billion-laughs': ('<?xml version="1.0"?><!DOCTYPE l [<!ENTITY a "' + 'x' * 1000 + '"><!ENTITY b "' + '&a;' * 10
                       + '"><!ENTITY c "' + '&b;' * 10 + '"><!ENTITY d "' + '&c;' * 10 + '">]>'
                       + shell('<assemblyIdentity type="win32" name="&d;" version="1.0.0.0"/>')),
    'external-file': ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
                      + shell('<description>&x;</description>')),
    'external-http': ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "http://invalid.example/x">]>'
                      + shell('<description>&x;</description>')),
    'parameter-entity': ('<?xml version="1.0"?><!DOCTYPE r [<!ENTITY % p SYSTEM "http://invalid.example/p.dtd"> %p;]>'
                         + shell('')),
    'doctype-system': '<?xml version="1.0"?><!DOCTYPE assembly SYSTEM "http://invalid.example/x.dtd">' + shell(''),
    'doctype-only': '<!DOCTYPE assembly>' + shell(''),
    'lower-case': '<!doctype assembly>' + shell(''),
    'entity-in-comment': shell('<!-- <!ENTITY x "y"> -->'),
    'doctype-in-cdata': shell('<description><![CDATA[<!DOCTYPE x>]]></description>'),
}


@pytest.mark.parametrize('encoding', list(ENCODINGS))
@pytest.mark.parametrize('name', list(DANGEROUS))
def test_documents_with_a_dtd_or_entity_are_refused_before_parsing(name, encoding):
    raw = ENCODINGS[encoding](DANGEROUS[name])
    started = time.perf_counter()
    obs = observe(raw)
    assert time.perf_counter() - started <= 0.5
    assert obs.warnings == ('manifest_dtd_rejected',) and empty(obs)
    assert obs.sha256 == hashlib.sha256(raw).hexdigest()


def test_the_dtd_scan_covers_the_whole_document():
    text = shell('<!--' + ' ' * 1_500_000 + '<!ENTITY q "z">-->')
    obs = observe(text)
    assert obs.warnings == ('manifest_dtd_rejected',) and empty(obs)


def test_parsing_touches_neither_the_network_nor_other_files(monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError('network access attempted')
    monkeypatch.setattr(socket, 'socket', forbidden)
    monkeypatch.setattr(socket, 'getaddrinfo', forbidden)
    monkeypatch.setattr(socket, 'create_connection', forbidden)
    text = (f'<?xml-stylesheet href="http://invalid.example/s.xsl"?><assembly xmlns="{V1}" manifestVersion="1.0" '
            'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:schemaLocation="urn:x http://invalid.example/x.xsd" '
            'xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="file:///etc/passwd"/>'
            '<assemblyIdentity type="win32" name="Inert" version="1.0.0.0"/></assembly>')
    obs = observe(text)
    assert obs.warnings == () and obs.identity.name == 'Inert'


# -- malformed XML ------------------------------------------------------------------------------------------------------

MALFORMED = {
    'truncated': shell('<assemblyIdentity type="win32" name="x" version="1.0.0.0"/>')[:-5],
    'mismatched-tags': f'<assembly xmlns="{V1}"><a></b></assembly>',
    'text-only': 'not xml at all',
    'empty': '',
    'whitespace-only': ' \r\n\t ',
    'nul-in-the-middle': shell('<a\0/>'),
    'undefined-entity': shell('<description>&nope;</description>'),
    'zero-char-ref': shell('<description>&#0;</description>'),
    'huge-char-ref': shell('<description>&#x110000;</description>'),
    'control-character': shell('<description>\x01</description>'),
    'duplicate-attribute': shell('<assemblyIdentity name="a" name="b"/>'),
    'unbound-prefix': shell('<x:y/>'),
    'two-roots': shell('') + shell(''),
    'leading-whitespace-before-declaration': '\n<?xml version="1.0"?>' + shell(''),
    'unterminated-comment': shell('<!-- x'),
    'bad-cdata': shell('<![CDATA[ x'),
}


@pytest.mark.parametrize('name', list(MALFORMED))
def test_malformed_xml_is_reported_never_raised(name):
    obs = observe(MALFORMED[name])
    assert obs.warnings == ('manifest_xml_invalid',) and empty(obs)


@pytest.mark.parametrize('raw', [codecs.BOM_UTF8, codecs.BOM_UTF16_LE, codecs.BOM_UTF16_BE, b'\0\0\0'],
                         ids=['utf8-bom', 'utf16le-bom', 'utf16be-bom', 'nul-padding'])
def test_documents_with_no_content_are_invalid(raw):
    obs = observe(raw)
    assert obs.warnings == ('manifest_xml_invalid',) and empty(obs)


SHAPES = {  # each stays under the 2 MiB cap
    'deep': f'<assembly xmlns="{V1}">' + '<a>' * 100_000 + '</a>' * 100_000 + '</assembly>',
    'wide': f'<assembly xmlns="{V1}">' + '<a/>' * 400_000 + '</assembly>',
    'attributes': f'<assembly xmlns="{V1}" ' + ' '.join(f'a{i}="v"' for i in range(100_000)) + '/>',
    'long-text': shell('<description>' + 'T' * 1_900_000 + '</description>'),
    'prefixed-wide': f'<assembly xmlns="{V1}" xmlns:p="urn:x">' + '<p:a/>' * 300_000 + '</assembly>',
    'unique-tags': f'<assembly xmlns="{V1}">' + ''.join(f'<t{i}/>' for i in range(150_000)) + '</assembly>',
    'xmlns-flood': f'<assembly xmlns="{V1}" ' + ' '.join(f'xmlns:p{i}="urn:x"' for i in range(60_000)) + '/>',
    'many-dependencies': f'<assembly xmlns="{V1}">' + '<dependency/>' * 150_000 + '</assembly>',
    'namespace-per-level': ''.join(f'<a xmlns="urn:n{i}">' for i in range(40_000)) + '</a>' * 40_000,
}


@pytest.mark.parametrize('shape', list(SHAPES))
def test_large_but_in_cap_documents_parse_within_budget(shape):
    raw = SHAPES[shape].encode()
    assert len(raw) <= DEFAULT_RESOURCE_LIMITS.max_manifest_bytes
    started = time.perf_counter()
    obs = observe(raw)
    assert time.perf_counter() - started <= 5.0  # measured 0.03 to 0.5 s; this catches a quadratic regression
    assert empty(obs) and obs.warnings in ((), ('manifest_xml_invalid',))
    if shape != 'namespace-per-level':
        assert obs.warnings == ()


def test_mutated_manifests_never_raise_and_stay_json_serializable():
    for encoding in ('utf8', 'utf16le-bom'):
        base = ENCODINGS[encoding](FULL)
        for seed in range(150):
            obs = observe(mutate(base, seed, flips=1 + seed % 12))
            assert set(obs.warnings) <= {'manifest_xml_invalid', 'manifest_encoding_unsupported',
                                         'manifest_dtd_rejected', 'manifest_over_cap'}
            json.dumps(asdict(obs))


@FAST
@given(st.binary(min_size=0, max_size=600))
def test_arbitrary_bytes_never_raise(raw):
    assert isinstance(observe(raw).warnings, tuple)


@FAST
@given(st.text(max_size=300), st.sampled_from(list(ENCODINGS)))
def test_arbitrary_text_in_any_supported_encoding_never_raises(text, encoding):
    try:
        raw = ENCODINGS[encoding](text)
    except UnicodeEncodeError:
        return
    assert isinstance(observe(raw).warnings, tuple)


# -- in a PE: reading, caps, budgets --------------------------------------------------------------------------------------


def test_manifests_are_read_from_the_pe_in_resource_order(tmp_path):
    first, second = FULL.replace('Example.App', 'First'), FULL.replace('Example.App', 'Second')
    root = tree({RT_MANIFEST: {2: {LANG_EN_US: second.encode()}, 1: {0x407: first.encode(), LANG_EN_US: first.encode()}}})
    found, codes = run(tmp_path, root)
    assert codes == set()
    assert [(o.leaf.name, o.leaf.lang, o.identity.name) for o in found] == [
        (1, 0x407, 'First'), (1, LANG_EN_US, 'First'), (2, LANG_EN_US, 'Second')]
    assert found[0].sha256 == hashlib.sha256(first.encode()).hexdigest()


def test_no_manifest_gives_an_empty_result(tmp_path):
    found, codes = run(tmp_path, tree({10: {1: {0: b'x'}}}))
    assert found == () and codes == set()


def test_a_manifest_at_the_cap_is_parsed_and_one_byte_over_is_not_read(tmp_path):
    limit = DEFAULT_RESOURCE_LIMITS.max_manifest_bytes
    head, tail = f'<assembly xmlns="{V1}" manifestVersion="1.0"><!--', '--></assembly>'
    exact = (head + 'x' * (limit - len(head) - len(tail)) + tail).encode()
    assert len(exact) == limit
    found, codes = run(tmp_path, tree({RT_MANIFEST: {1: {0: exact}}}))
    assert found[0].warnings == () and found[0].sha256 == hashlib.sha256(exact).hexdigest() and codes == set()
    over = exact + b' '
    data, _info = rsrc_pe(tree({RT_MANIFEST: {1: {0: over}}}))
    with open_pe(tmp_path, data) as pe:
        lengths = []
        original = pe.reader.read
        pe.reader.read = lambda offset, length, **kw: lengths.append(length) or original(offset, length, **kw)
        inventory = parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size)
        (obs,) = parse_manifests(pe.ctx, pe.smap, inventory)
    assert obs.warnings == ('manifest_over_cap',) and obs.sha256 is None and empty(obs)
    assert max(lengths) < 1 << 16 and 'manifest_over_cap' in pe.codes()


def test_a_huge_declared_size_is_over_the_cap_and_not_read(tmp_path):
    found, codes = run(tmp_path, tree({RT_MANIFEST: {1: {0: Data(b'<assembly/>', size=0xFFFFFFF0)}}}))
    assert found[0].warnings == ('manifest_over_cap',) and found[0].sha256 is None and 'manifest_over_cap' in codes


def test_total_bytes_read_are_bounded(tmp_path):
    text = shell('<assemblyIdentity type="win32" name="x" version="1.0.0.0"/>').encode()
    root = tree({RT_MANIFEST: {1: {lang: text for lang in (1, 2, 3, 4)}}})
    limits = ResourceLimits(max_hash_bytes=len(text) * 2 + 1)
    found, codes = run(tmp_path, root, limits)
    assert [o.warnings for o in found] == [(), (), ('manifest_over_cap',), ('manifest_over_cap',)]
    assert [o.sha256 is not None for o in found] == [True, True, False, False] and 'manifest_over_cap' in codes


def test_only_sixteen_manifests_are_read(tmp_path):
    text = shell('').encode()
    found, codes = run(tmp_path, tree({RT_MANIFEST: {1: {lang: text for lang in range(1, 21)}}}))
    assert len(found) == 16 and 'manifest_over_cap' in codes


def test_unbacked_and_partly_backed_manifests_have_no_hash(tmp_path):
    root = tree({RT_MANIFEST: {1: {0: Data(b'', rva=0xFFFF0000, size=50)}, 2: {0: Data(b'<assembly', size=400)}}})
    found, codes = run(tmp_path, root)
    assert [o.warnings for o in found] == [('manifest_xml_invalid',), ('manifest_xml_invalid',)]
    assert [o.sha256 for o in found] == [None, None] and 'manifest_xml_invalid' in codes


def test_an_empty_manifest_is_invalid(tmp_path):
    found, _codes = run(tmp_path, tree({RT_MANIFEST: {1: {0: b''}}}))
    assert found[0].warnings == ('manifest_xml_invalid',) and found[0].sha256 == hashlib.sha256(b'').hexdigest()


def test_time_budget_stops_the_stage(tmp_path):
    root = tree({RT_MANIFEST: {1: {lang: shell('').encode() for lang in (1, 2, 3)}}})
    found, codes = run(tmp_path, root, stage_limits=ResourceLimits(time_budget_s=0.0))
    assert found == () and codes == {'metadata_time_budget'}


def test_cancel_is_polled_for_every_manifest(tmp_path):
    data, _info = rsrc_pe(tree({RT_MANIFEST: {1: {0: shell('').encode()}}}))
    stop = [False]
    with open_pe(tmp_path, data, cancel=lambda: stop[0]) as pe:
        inventory = parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size)
        stop[0] = True
        with pytest.raises(Cancelled):
            parse_manifests(pe.ctx, pe.smap, inventory)


def test_real_launcher_manifests_match_pefile_bytes_and_parse_cleanly(tmp_path):
    pefile = pytest.importorskip('pefile')
    launchers = real_launchers()
    if not launchers:
        pytest.skip('this pip carries no distlib launcher executables')
    for launcher in launchers:
        data = launcher.read_bytes()
        pe = pefile.PE(data=data)
        with open_pe(tmp_path, data) as opened:
            inventory = parse_resources(opened.ctx, opened.smap, opened.resource.rva, opened.resource.size)
            found = parse_manifests(opened.ctx, opened.smap, inventory)
        assert found, launcher.name
        for obs in found:
            stored = pe.get_data(obs.leaf.rva, obs.leaf.size)
            assert obs.sha256 == hashlib.sha256(stored).hexdigest() and obs.warnings == (), launcher.name
            assert obs.execution_level in ('asInvoker', 'requireAdministrator', 'highestAvailable'), launcher.name


def test_cancel_is_polled_even_when_no_manifest_is_read(tmp_path):
    data, _info = rsrc_pe(tree({RT_MANIFEST: {1: {0: Data(b'x', size=0xFFFFFFF0)}}}))
    stop = [False]
    with open_pe(tmp_path, data, cancel=lambda: stop[0]) as pe:
        inventory = parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size)
        stop[0] = True
        with pytest.raises(Cancelled):
            parse_manifests(pe.ctx, pe.smap, inventory)


def test_reader_errors_propagate(tmp_path):
    data, _info = rsrc_pe(tree({RT_MANIFEST: {1: {0: shell('').encode()}}}))
    with open_pe(tmp_path, data) as pe:
        inventory = parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size)
        pe.reader.close()
        with pytest.raises(ArtifactBytesError) as exc:
            parse_manifests(pe.ctx, pe.smap, inventory)
    assert exc.value.code == 'closed'


@FAST
@given(st.binary(min_size=0, max_size=400))
def test_arbitrary_manifest_resources_never_raise(raw):
    data, _info = rsrc_pe(tree({RT_MANIFEST: {1: {0: Data(raw)}}}))
    with tempfile.TemporaryDirectory() as folder, open_pe(Path(folder), data) as pe:
        inventory = parse_resources(pe.ctx, pe.smap, pe.resource.rva, pe.resource.size)
        (obs,) = parse_manifests(pe.ctx, pe.smap, inventory)
        assert isinstance(obs.warnings, tuple)
