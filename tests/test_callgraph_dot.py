"""WB2 G4: DOT export (7.6) and the paired JSON export. Pure: snapshots come from the synthetic fixtures."""
from __future__ import annotations

import re
from pathlib import Path

import pytest
from callgraph_graph_support import snapshot

from patchtrace.callgraph.contracts import MoreMarker
from patchtrace.callgraph.dot import GRAPH_ID, escape_label, render_dot
from patchtrace.callgraph.export_json import GraphExport, build_export, default_name, to_json, write_export
from patchtrace.callgraph.limits import GraphError
from patchtrace.callgraph.query import find_node, neighbourhood
from patchtrace.callgraph.text import one_line

GOLDEN = Path(__file__).resolve().parent / 'fixtures' / 'callgraph' / 'golden' / 'svc_p.dot'
ATTRIBUTES = {'label', 'shape', 'style', 'color', 'fillcolor', 'penwidth', 'fontname', 'rankdir', 'constraint',
              'arrowhead'}
FORBIDDEN = ('URL', 'href', 'tooltip', 'xlabel', 'fontpath', 'image', 'Mrecord', 'record', '<')


def match_of(snap, label: str) -> str:
    return next(e.match_id for e in snap.data.entries if e.label == label)


def export_of(name: str = 'svc_pair', label: str = 'FUN_1400018c0', depth: int = 1, **kwargs) -> GraphExport:
    snap = snapshot(name, **kwargs)
    return build_export(snap, match_of(snap, label), depth)


# --- the quoted-string oracle: Graphviz scan.l quoted-string rules, then the labels.c unescape -------------------

def lex_quoted(body: str) -> str:
    """scan.l `<qstring>`: `\\"` yields a quote, `\\\\` is kept as two characters, any other `\\X` is kept."""
    out, i = [], 0
    while i < len(body):
        if body[i] == '\\' and i + 1 < len(body):
            pair = body[i:i + 2]
            out.append('"' if pair == '\\"' else pair)
            i += 2
        else:
            assert body[i] != '"', 'an unescaped quote would end the string early'
            out.append(body[i])
            i += 1
    return ''.join(out)


def unescape_label(text: str) -> str:
    """labels.c: `\\\\` collapses to one backslash, `\\n` is a line break; any other escape would be a Graphviz
    escape string (`\\N`, `\\G`, ...) and must never be formable from label text."""
    out, i = [], 0
    while i < len(text):
        if text[i] == '\\':
            nxt = text[i + 1] if i + 1 < len(text) else ''
            assert nxt in {'\\', 'n'}, f'formed the escape \\{nxt}'
            out.append('\\' if nxt == '\\' else '\n')
            i += 2
        else:
            out.append(text[i])
            i += 1
    return ''.join(out)


def roundtrip(value: str) -> str:
    return unescape_label(lex_quoted(escape_label(value)))


def expected(value: str) -> str:
    return one_line(value.encode('utf-8', 'backslashreplace').decode('utf-8'))


@pytest.mark.parametrize('value', [
    'plain', 'say "hi"', 'back\\slash', 'trail\\', '\\N', '\\G\\E\\T\\H\\L', 'a\\nb', '\\"', '"\\', 'x\\\\y',
    '<b>x</b>', '{0} %s', 'file:///c:/x', 'a\u202eb', 'a\x00b', 'tab\there', 'line\nbreak', '\ud800lone', 'é' * 300],
    ids=['plain', 'quote', 'backslash', 'trailing', 'N', 'escapes', 'literal-n', 'bs-quote', 'quote-bs', 'double',
         'html', 'format', 'url', 'bidi', 'nul', 'tab', 'newline', 'surrogate', 'long'])
def test_escape_label_round_trips_through_the_lexer_oracle(value):
    assert roundtrip(value) == expected(value)


def test_every_unicode_category_round_trips():
    # No hypothesis in this environment: a deterministic sweep of all code points in 100-character labels.
    points = [chr(c) for c in range(0x110000) if not 0xD800 <= c <= 0xDFFF]
    for start in range(0, len(points), 100):
        label = ''.join(points[start:start + 100])
        assert roundtrip(label) == expected(label)


def test_escape_doubles_backslashes_before_quotes():
    assert escape_label('a\\"b') == 'a\\\\\\"b'


# --- document structure ------------------------------------------------------------------------------------------

def test_render_is_stable_lf_utf8_without_bom():
    export = export_of()
    first = render_dot(export)
    assert first == render_dot(export.model_copy())
    data = first.encode('utf-8')
    assert not data.startswith(b'\xef\xbb\xbf') and b'\r' not in data and data.endswith(b'}\n')
    assert f'digraph {GRAPH_ID} {{' in first


def test_attributes_are_whitelisted_and_no_html_or_urls():
    text = render_dot(export_of(label='FUN_140001d40'))
    for name in re.findall(r'([A-Za-z_]+)=', re.sub(r'"(?:[^"\\]|\\.)*"', '""', text)):
        assert name in ATTRIBUTES, name
    assert not any(word in text for word in FORBIDDEN)


def test_node_ids_are_positional_and_never_label_text():
    text = render_dot(export_of())
    ids = set(re.findall(r'^\s*(n\d+) \[', text, re.M))
    assert ids and ids == {f'n{k}' for k in range(1, len(ids) + 1)}
    edges = re.findall(r'^\s*(\S+) -> (\S+?)(?: \[.*)?;$', text, re.M)
    assert edges and all(a in ids and b in ids for a, b in edges)


def test_paired_export_has_clusters_and_dotted_correspondence():
    text = render_dot(export_of())
    assert 'subgraph cluster_older' in text and 'label="Older build"' in text
    assert 'subgraph cluster_newer' in text and 'label="Newer build"' in text
    assert 'style=dotted, constraint=false' in text


def test_one_sided_export_has_no_clusters():
    snap = snapshot('svc_pair')
    export = build_export(snap, match_of(snap, 'FUN_140001f00'))
    assert export.older is None and export.correspondence == ()
    assert 'cluster' not in render_dot(export)


def test_unresolved_nodes_are_dashed():
    assert 'style=dashed' in render_dot(export_of('ambiguous_pair', 'Dispatch'))


def test_header_comments_hold_only_validated_ids_and_hex():
    header = [line for line in render_dot(export_of()).splitlines() if line.startswith('//')]
    assert header[0].startswith('// patchtrace call graph export')
    assert all(re.fullmatch(r'// (match: [A-Za-z0-9_.:-]+|(older|newer) sha256: [0-9a-f]{64}|patchtrace.*)', h)
               for h in header)


def test_hostile_labels_stay_inside_their_quoted_strings():
    export = export_of('hostile_names', label=next_hostile_label())
    text = render_dot(export)
    bodies = re.findall(r'label="((?:[^"\\]|\\.)*)"', text)
    assert bodies
    labels = {n.label for view in (export.older, export.newer) if view for n in view.nodes}
    decoded = {unescape_label(lex_quoted(b)).split('\n')[0] for b in bodies}
    assert {one_line(label) for label in labels} <= decoded
    assert not any(word in text for word in ('<b>', 'URL', 'href'))


def next_hostile_label() -> str:
    snap = snapshot('hostile_names')
    return next(e.label for e in snap.data.entries if e.side == 'newer')


def hub_export() -> tuple[GraphExport, str]:
    """The newer callers of `TraceMessageHub`: 66 callers, so the 64-neighbour cap leaves `+2 more`."""
    snap = snapshot('cycle_hub')
    hub = find_node(snap, 'newer', 'TraceMessageHub')
    view = neighbourhood(snap, 'newer', [hub.id], direction='in', max_nodes=500, max_edges=500)
    data = snap.data
    export = GraphExport(project_id=data.project_id, run_id=data.run_id, match_id='m' * 64,
                         older_sha256=data.older_sha256, newer_sha256=data.newer_sha256, newer=view,
                         truncated=view.truncated, limitations=view.limitations)
    return export, hub.id


def node_lines(text: str) -> dict[str, str]:
    """Positional node id -> decoded label of every node statement."""
    found = re.findall(r'^\s*(n\d+) \[label="((?:[^"\\]|\\.)*)"', text, re.M)
    return {key: unescape_label(lex_quoted(body)) for key, body in found}


def test_capped_hub_gets_a_plus_n_more_placeholder_like_the_json_export():
    export, hub_id = hub_export()
    assert [(m.node, m.count) for m in export.newer.more] == [(hub_id, 2)]
    text = render_dot(export)
    nodes = node_lines(text)
    [hub_key] = [k for k, label in nodes.items() if label == 'TraceMessageHub']
    [(more_key, more_label)] = [(k, label) for k, label in nodes.items() if 'more' in label]
    assert more_label == '+2 more\nneighbours not shown'
    assert more_key == f'n{len(export.newer.nodes) + 1}'  # numbered after every function node
    assert re.search(rf'^\s*{more_key} \[label="[^\n]*style=dotted', text, re.M)
    assert re.search(rf'^\s*{hub_key} -> {more_key} \[style=dotted, arrowhead=none\];$', text, re.M)
    ids = set(re.findall(r'^\s*(n\d+) \[', text, re.M))
    assert ids == {f'n{k}' for k in range(1, len(ids) + 1)}
    edges = re.findall(r'^\s*(\S+) -> (\S+?)(?: \[.*)?;$', text, re.M)
    assert edges and all(a in ids and b in ids for a, b in edges)
    for name in re.findall(r'([A-Za-z_]+)=', re.sub(r'"(?:[^"\\]|\\.)*"', '""', text)):
        assert name in ATTRIBUTES, name


def test_uncapped_export_has_no_placeholder():
    export = export_of()
    assert not any(view.more for view in (export.older, export.newer) if view)
    assert not any('more' in label for label in node_lines(render_dot(export)).values())


def test_more_marker_node_ids_never_reach_the_text():
    snap = snapshot('hostile_names')
    focus = find_node(snap, 'newer', 'Dispatch')
    view = neighbourhood(snap, 'newer', [focus.id], direction='out', max_nodes=50, max_edges=100)
    hostile = next(n for n in view.nodes if n.label != 'Dispatch')
    dangling = 'INJECTED"]; x -> n1 [URL="file:///c:/x\\N\n\u202e'
    markers = (MoreMarker(node=hostile.id, count=3), MoreMarker(node=dangling, count=7))
    view = view.model_copy(update={'more': markers, 'nodes': (*view.nodes, hostile.model_copy(
        update={'id': 'IDTEXT"\\'}))})
    data = snap.data
    export = GraphExport(project_id=data.project_id, run_id=data.run_id, match_id='m' * 64,
                         older_sha256=data.older_sha256, newer_sha256=data.newer_sha256, newer=view)
    text = render_dot(export)
    assert 'INJECTED' not in text and 'IDTEXT' not in text and 'URL' not in text
    nodes = node_lines(text)
    placeholders = sorted(label for label in nodes.values() if label.startswith('+'))
    assert placeholders == ['+3 more\nneighbours not shown', '+7 more\nneighbours not shown']
    # the shown hub is joined to its placeholder; the marker of a node not in the view still states the cap alone
    assert len(re.findall(r' -> n\d+ \[style=dotted, arrowhead=none\];$', text, re.M)) == 1
    for body in re.findall(r'label="((?:[^"\\]|\\.)*)"', text):
        unescape_label(lex_quoted(body))  # the oracle asserts no early quote end and no Graphviz escape


def test_paired_export_keeps_each_placeholder_in_its_own_cluster():
    export, hub_id = hub_export()
    older = export.newer.model_copy(update={'side': 'older', 'more': ()})
    paired = export.model_copy(update={'older': older.model_copy(update={'nodes': (), 'edges': ()})})
    text = render_dot(paired)
    newer_block = text[text.index('subgraph cluster_newer'):]
    older_block = text[text.index('subgraph cluster_older'):text.index('subgraph cluster_newer')]
    assert '+2 more' in newer_block and 'more' not in older_block


def test_golden_matches_after_masking_the_random_match_id():
    text = re.sub(r'^// match: .*$', '// match: <id>', render_dot(export_of()), flags=re.M)
    assert text == GOLDEN.read_text(encoding='utf-8')


# --- JSON export and the writer ----------------------------------------------------------------------------------

def test_json_export_is_one_valid_document_with_correspondence():
    export = export_of()
    document = GraphExport.model_validate_json(to_json(export))
    assert document == export and document.correspondence
    assert all(isinstance(pair, tuple) and len(pair) == 2 for pair in document.correspondence)


def test_unknown_match_is_function_not_indexed():
    with pytest.raises(GraphError) as error:
        build_export(snapshot('svc_pair'), 'no-such-match')
    assert error.value.code == 'PT-GRAPH-INPUT' and 'function-not-indexed' in error.value.message


def test_writer_refuses_overwrite_and_names_by_content(tmp_path):
    text = render_dot(export_of())
    written = write_export(tmp_path, text, 'dot')
    assert written.name == default_name(text, 'dot') and re.fullmatch(r'callgraph-[0-9a-f]{12}\.dot', written.name)
    assert written.read_bytes() == text.encode('utf-8') and b'\r' not in written.read_bytes()
    with pytest.raises(GraphError) as error:
        write_export(written, text, 'dot')
    assert error.value.code == 'PT-GRAPH-INPUT'
    assert write_export(written, text + '// again\n', 'dot', overwrite=True) == written
    assert sorted(p.name for p in tmp_path.iterdir()) == [written.name]  # no stray temp file


def test_writer_failure_is_an_export_error(tmp_path):
    with pytest.raises(GraphError) as error:
        write_export(tmp_path / 'missing' / 'x.dot', 'x', 'dot')
    assert error.value.code == 'PT-GRAPH-EXPORT'


def test_oversized_export_is_refused():
    from patchtrace.callgraph.export_json import MAX_EXPORT_BYTES, check_size
    with pytest.raises(GraphError) as error:
        check_size('x' * (MAX_EXPORT_BYTES + 1))
    assert error.value.code == 'PT-GRAPH-EXPORT'
