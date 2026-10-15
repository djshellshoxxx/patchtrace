"""DOT text export (7.6): text only, no Graphviz dependency, no execution. Node ids are `n<k>`, labels are escaped
so no Graphviz escape (`\\N`, `\\G`, ...) can be formed from text, and the output is byte-stable."""
from __future__ import annotations

import re

from .contracts import GraphEdge, GraphNode, GraphView
from .export_json import GraphExport, check_size
from .text import one_line

GRAPH_ID = 'patchtrace_calls'
_SAFE_ID = re.compile(r'^[A-Za-z0-9_.:-]{1,128}$')
_HEX64 = re.compile(r'^[0-9a-f]{64}$')
# Fixed palette; the only colour values that ever reach the output.
_COLOURS = {'function': '#1f4e79', 'paired-unchanged': '#4d6b2f', 'external': '#6b4c9a',
            'label-only': '#6e6e6e', 'ambiguous': '#a15c00'}
_DASHED_KINDS = frozenset({'label-only', 'ambiguous'})
_KIND_LINE = {'function': None, 'paired-unchanged': 'paired, unchanged', 'external': 'import',
              'label-only': 'unresolved', 'ambiguous': 'ambiguous name'}
_SIDE_TITLE = {'older': 'Older build', 'newer': 'Newer build'}


def escape_label(value: object) -> str:
    """One display line (controls and bidi removed, 120 characters), then `\\` -> `\\\\` first and `"` -> `\\"`.
    A lone surrogate cannot be encoded, so it is written as a visible `\\uXXXX` (and then doubled like any `\\`)."""
    text = one_line(str(value).encode('utf-8', 'backslashreplace').decode('utf-8'))
    return text.replace('\\', '\\\\').replace('"', '\\"')


def _label(node: GraphNode) -> str:
    lines = [escape_label(node.label)]
    kind = _KIND_LINE[node.kind]
    if kind:
        lines.append(kind)
    return '\\n'.join(lines)  # the two characters backslash and n


def _header(export: GraphExport) -> list[str]:
    lines = ['// patchtrace call graph export (workbench-graph-export/1)']
    if _SAFE_ID.match(export.match_id):
        lines.append(f'// match: {export.match_id}')
    for side in ('older', 'newer'):
        digest = getattr(export, f'{side}_sha256')
        if _HEX64.match(digest):
            lines.append(f'// {side} sha256: {digest}')
    return lines


def _node_line(key: str, node: GraphNode, indent: str) -> str:
    style = ', style=dashed' if node.kind in _DASHED_KINDS else ''
    return f'{indent}{key} [label="{_label(node)}", color="{_COLOURS[node.kind]}"{style}];'


def _edge_line(ids: dict[str, str], edge: GraphEdge, indent: str) -> str:
    style = ' [style=dashed]' if 'inferred' in edge.flags else ''
    return f'{indent}{ids[edge.src]} -> {ids[edge.dst]}{style};'


def _sides(export: GraphExport) -> list[tuple[str, GraphView]]:
    return [(side, view) for side in ('older', 'newer') if (view := getattr(export, side)) is not None]


def render_dot(export: GraphExport) -> str:
    sides = _sides(export)
    paired = len(sides) == 2
    ordered = sorted(((side, node) for side, view in sides for node in view.nodes),
                     key=lambda item: (item[0] != 'older', item[1].label, item[1].id))
    ids = {node.id: f'n{k}' for k, (_, node) in enumerate(ordered, 1)}
    out = [*_header(export), f'digraph {GRAPH_ID} {{', '  rankdir=LR;', '  node [shape=box, fontname="Helvetica"];']
    for side, view in sides:
        indent = '    ' if paired else '  '
        if paired:
            out += [f'  subgraph cluster_{side} {{', f'    label="{_SIDE_TITLE[side]}";']
        shown = {n.id for n in view.nodes}
        out += [_node_line(ids[node.id], node, indent) for _, node in ordered if node.id in shown]
        out += [_edge_line(ids, edge, indent) for edge in view.edges]
        if paired:
            out.append('  }')
    order = {key: k for k, key in enumerate(ids.values())}
    links = sorted(((ids[a], ids[b]) for a, b in export.correspondence if a in ids and b in ids),
                   key=lambda link: (order[link[0]], order[link[1]]))
    out += [f'  {a} -> {b} [style=dotted, constraint=false, arrowhead=none];' for a, b in links]
    out.append('}')
    return check_size('\n'.join(out) + '\n')
