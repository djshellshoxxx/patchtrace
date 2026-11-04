"""Format-neutral document blocks for the Markdown and HTML renderers (SPEC-50 7.4).

Each block is a tuple whose first item names the escaping cell it needs: `h1`/`h2`/`note` carry static text written
here, `h3`/`para`/`bullets`/`code` carry untrusted data, `facts` pairs a static label with untrusted data, and `table`
has static headers over untrusted cells. Renderers escape by kind and never decide content.
"""
from __future__ import annotations

from .contracts import ATTENTION_LABEL

Block = tuple


def _unknown(state: str) -> str:
    return 'unknown' if state in ('absent', 'not_run') else state.replace('_', ' ')


def _names(match: dict) -> str:
    return ' / '.join(dict.fromkeys(f['name'] for f in match['older'] + match['newer']))


def _header(d: dict) -> list[Block]:
    cal, red, tool, ori, prov = d['calibration'], d['redaction'], d['tool'], d['orientation'], d['provenance']
    blocks: list[Block] = [
        ('h1', 'PatchTrace report'), ('para', d['name']),
        ('note', f'Report contract report/2; project revision {d["revision"]}.'),
        ('facts', [('Generated', d['generated_at']), ('Content digest', d['content_digest'] or 'not computed')]),
        ('note', cal['note'])]
    if d['stale_sections']:
        blocks.append(('para', 'STALE sections: ' + ', '.join(d['stale_sections'])))
    blocks += [('h2', 'Orientation and provenance'), ('table', ['Item', 'Value'], [
        ['Older SHA-256', ori['older_sha256'] or 'unknown'], ['Newer SHA-256', ori['newer_sha256'] or 'unknown'],
        ['Tool', f'{tool["name"]} {tool["version"]}'], ['Release tag', tool['release_tag'] or 'unknown'],
        ['Signed build', tool['signed']], ['Derived from', prov['derived_from']],
        ['Network used', str(prov['network_used']).lower()], ['Display level', cal['display_level']],
        ['Redaction profile', red['profile']], ['Code included', str(red['code']).lower()],
        ['Notes included', str(red['notes']).lower()], ['Web addresses', red['urls']],
        ['Redaction markers', ', '.join(f'{k}: {v}' for k, v in sorted(red['rules_applied'].items())) or 'none'],
        ['Text handling', d['normalization']]])]
    blocks.append(('h2', 'Not run or unknown'))
    blocks.append(('bullets', d['unknowns']) if d['unknowns'] else ('note', 'Nothing was recorded as unknown.'))
    return blocks


def _artifacts(d: dict) -> list[Block]:
    return [('h2', 'Artifacts'), ('table', ['Side', 'Name', 'SHA-256', 'Size'],
                                  [[a['side'], a['name'], a['sha256'], str(a['size'])] for a in d['artifacts']])]


def _ranking(d: dict) -> list[Block]:
    r = d['change_ranking']
    if r is None:
        return []
    label = f'Change ranking ({ATTENTION_LABEL}{", STALE" if r["stale"] else ""})'
    return [('h2', label), ('para', r['note']),
            ('table', ['Rank', 'Attention index', 'Evidence', 'Functions'],
             [[str(e['rank']), str(e['attention_index']), e['evidence'], ', '.join(e['functions'])]
              for e in r['entries']])]


def _evidence(d: dict) -> list[Block]:
    ev = d.get('engine_evidence')
    if ev is None:
        return []
    indexed = any(r['ordinal_index'] is not None for r in ev['rows'])
    head = ['Match', 'Verdict', 'Tier', 'Supporting', 'Contradicting', 'Unknown (not run or absent)', 'Channels',
            'Explanation'] + (['Index (ordinal)'] if indexed else [])
    rows = [[r['match_id'], r['verdict'], r['tier'], ', '.join(r['supporting_engines']) or '-',
             ', '.join(r['contradicting_engines']) or '-', ', '.join(r['missing_engines']) or '-',
             '; '.join(f'{c["engine"]}: {_unknown(c["state"])}' for c in r['channels']) or '-', r['explanation']]
            + ([str(r['ordinal_index'])] if indexed else []) for r in ev['rows']]
    return [('h2', 'Engine evidence' + (', STALE' if ev['stale'] else '')),
            ('note', 'Engines are listed separately and never merged. A missing engine is unknown, not a negative vote.'),
            ('table', ['Engine', 'Version'], [[e['name'], e['version']] for e in ev['engines']]),
            ('table', head, rows)]


def _matches(d: dict) -> list[Block]:
    blocks: list[Block] = [('h2', 'Matches')]
    for m in d['matches']:
        blocks += [('h3', _names(m)), ('facts', [
            ('Match', m['id']), ('Category', m['category']), ('Quality', m['quality']), ('Review', m['review']),
            ('Match types', ', '.join(m['match_types']) or '-'), ('Reason', m['reason'] or '-')])]
        for side in ('older', 'newer'):
            for f in m[side]:
                for field in ('code', 'assembly'):
                    if f.get(field):
                        blocks += [('para', f'{side} {f["name"]} ({field})'), ('code', f[field])]
    return blocks


def _findings(d: dict) -> list[Block]:
    blocks: list[Block] = [('h2', 'Findings')]
    for run in d['interpretations']:
        for f in run['findings']:
            blocks += [('h3', f['summary']), ('para', f['fix_purpose']),
                       ('facts', [('Review', f['review']), ('Stale', str(f['stale']).lower())])]
            if f.get('analyst_conclusion'):
                blocks.append(('para', 'Analyst conclusion: ' + f['analyst_conclusion']))
    return blocks if len(blocks) > 1 else []


def _facts(d: dict) -> list[Block]:
    blocks: list[Block] = []
    if d.get('build_facts') is not None:
        blocks += [('h2', 'Build facts'), ('table', ['Side', 'Fact', 'Value', 'Source', 'Claim level'],
                                          [[b['side'], b['fact'], b['value'], b['source'], b['claim_level']]
                                           for b in d['build_facts']])]
    s = d.get('symbols')
    if s is not None:
        blocks += [('h2', 'Symbols'), ('facts', [
            ('Mode', s['mode']), ('Servers contacted', ', '.join(s['servers']) or 'none'),
            ('Launcher version', s['launcher_version'] or 'unknown')]),
            ('table', ['PDB', 'GUID and age', 'SHA-256'], [[p['pdb_name'], p['guid_age'], p['sha256']]
                                                         for p in s['staged']])]
    return blocks


def _context(d: dict) -> list[Block]:
    blocks: list[Block] = []
    for a in d.get('advisories') or []:
        blocks += [('h3', f'{a["kind"].upper()} {a["id"]}'), ('facts', [
            ('Vendor', a['vendor'] or '-'), ('Address (inert text)', a['url_text'] or '-'),
            ('Fetched', a['fetched_at'] or '-'), ('Claim level', a['claim_level'])]), ('code', a['text'])]
    if d.get('advisories') is not None:
        blocks.insert(0, ('h2', 'Advisories'))
    if d.get('leads') is not None:
        blocks.append(('h2', 'Leads'))
        for lead in d['leads']:
            blocks += [('h3', lead['lead_id']), ('facts', [('Kind', lead['kind']),
                                                           ('Independent channels', ', '.join(lead['channels']))]),
                       ('para', lead['statement'])]
    s = d.get('series')
    if s is not None:
        blocks += [('h2', 'Series' + (', STALE' if s['stale'] else '')), ('table', ['Ordinal', 'Label', 'SHA-256'],
                                                                         [[str(b['ordinal']), b['label'], b['sha256']]
                                                                          for b in s['builds']])]
        blocks += [('table', ['Older', 'Newer', 'State'], [[str(p['older_ordinal']), str(p['newer_ordinal']),
                                                           _unknown(p['state'])] for p in s['pairs']])]
        blocks += [('bullets', [f'gap after {g["after_ordinal"]}: unknown ({g["reason"]})' for g in s['gaps']])]
    u = d.get('unified_result')
    if u is not None:
        blocks += [('h2', 'Unified result' + (', STALE' if u['stale'] else '')), ('facts', [
            ('Result id', u['result_id']), ('Manifest SHA-256', u['manifest_sha256']), ('Status', u['status']),
            ('Engines', ', '.join(u['engines']))])]
    return blocks


def build_blocks(d: dict, appendix: str) -> list[Block]:
    """`d` is the finalized report dict; `appendix` its pretty JSON, shown verbatim in a code block."""
    return [*_header(d), *_artifacts(d), *_ranking(d), *_evidence(d), *_matches(d), *_findings(d), *_facts(d),
            *_context(d), ('h2', 'Appendix: report JSON'), ('code', appendix)]

