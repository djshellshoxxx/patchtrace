"""Bounded, SYNTHETIC R2 ladder/graph experiments; never executes target binaries.

Reuses existing test generators, not a new corpus or evaluation framework.
Run each mode/size in a fresh process for meaningful Linux ru_maxrss.
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import platform
import resource
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT), str(ROOT / 'src'), str(ROOT / 'tests')]

from unified_ir_builder import generate_pair  # noqa: E402
from unified_residual_support import DenseMnemonics, GeneratedMnemonics, dense_world  # noqa: E402

from patchtrace.unified.ir.cfg import count_back_edges, dominators  # noqa: E402
from patchtrace.unified.ir.mdindex import flow_graph_md, md_key  # noqa: E402
from patchtrace.unified.ladder.assign import assign_with_rejection  # noqa: E402
from patchtrace.unified.ladder.blocking import block  # noqa: E402
from patchtrace.unified.ladder.engine import run_ladder_data  # noqa: E402
from patchtrace.unified.ladder.ports import FnRow, RowsIrSide  # noqa: E402
from patchtrace.unified.ladder.residual import pass_table, residual_passes  # noqa: E402
from patchtrace.unified.ladder.side import SideData  # noqa: E402
from patchtrace.unified.ladder.state import State  # noqa: E402
from patchtrace.unified.limits import DEFAULT_LIMITS, Budget  # noqa: E402
from tools.research.r2_paths import report_destination, write_report_json  # noqa: E402


def stamp():
    return time.perf_counter(), time.process_time()


def elapsed(start):
    return {'wall_s': time.perf_counter() - start[0], 'cpu_s': time.process_time() - start[1]}


def fn(fid, *, side=0, md=None):
    keys = tuple(1 + fid * 8 + k + side * 10**9 for k in range(6))
    return FnRow(fid, 0x1000 + fid * 128, 80, 'normal', None, 'DEFAULT', (), None, None,
                 6, 12, 20, *keys, *(md or (None, None)), True, False)


def run(args):
    out = {'mode': args.mode, 'n': args.n, 'seed': args.seed, 'omit': args.omit,
           'python': platform.python_version(), 'platform': platform.platform(),
           'hash_seed': os.environ.get('PYTHONHASHSEED', 'unset'),
           'limits': dataclasses.asdict(DEFAULT_LIMITS), 'synthetic_only': True}
    total = stamp()
    if args.mode == 'cfg':
        # A forward chain has no loops, but the current per-edge ancestor walk is quadratic.
        succ = [[i + 1] if i + 1 < args.n else [] for i in range(args.n)]
        start = stamp()
        ids = dominators(args.n, succ)
        out['dominators'] = elapsed(start)
        start = stamp()
        out['back_edges'] = count_back_edges(args.n, succ)
        out['count_back_edges'] = elapsed(start)
        out['ancestor_visits_derived'] = args.n * (args.n - 1) // 2
        out['last_idom'] = ids[-1]
    elif args.mode == 'assignment':
        # Deliberately only <=200 rows: never call dense assignment on the image scale.
        if args.n > 200:
            raise ValueError('assignment experiment is capped at production bucket cap 200')
        for shape in ('diagonal', 'equal'):
            matrix = [[1000 if shape == 'equal' or x == y else 700
                       for y in range(args.n)] for x in range(args.n)]
            count = [0]
            def tick(units, count=count):
                count[0] += units
            start = stamp()
            picked = assign_with_rejection(matrix, floor=600, tick=tick)
            out[shape] = {**elapsed(start), 'column_scans': count[0],
                          'identity': picked == list(range(args.n))}
    elif args.mode == 'collision':
        graphs = [[(i, (i + d) % 6) for i in range(6) for d in ds] for ds in ((1, -1), (1, 2))]
        keys = [tuple(md_key(v) for v in flow_graph_md(6, graph)) for graph in graphs]
        sides = [SideData.from_ir(RowsIrSide([fn(0, side=i, md=keys[i])])) for i in range(2)]
        corr = run_ladder_data(*sides)
        out.update(graphs=graphs, md_keys=keys,
                   pairs=[dataclasses.asdict(p) for p in corr.pairs],
                   note='First graph has reciprocal edges; second has none: non-isomorphic.')
    else:
        start = stamp()
        truth = None
        if args.mode == 'exact':
            rows = [fn(i) for i in range(args.n)]
            older, newer = RowsIrSide(rows), RowsIrSide(rows)
            table = pass_table()
        elif args.mode in ('residual', 'common', 'ambiguous'):
            world = dense_world(args.n, args.seed)
            if args.mode in ('common', 'ambiguous'):
                # Remove the generator's unique twin strings; every remaining token is common.
                world.older.strings = []
                world.newer.strings = []
                world.older.functions = [row._replace(n_insn=20, n_bb=6) for row in world.older.functions]
                world.newer.functions = [row._replace(n_insn=20, n_bb=6) for row in world.newer.functions]
                table = residual_passes()
            else:
                table = residual_passes(DenseMnemonics(world, 'older'), DenseMnemonics(world, 'newer'))
            older, newer = world.older, world.newer
            truth = {rva: identity for rva, identity in world.identity_older.items()}
        else:
            world = generate_pair(args.n, seed=args.seed, changed=0.5, shifted=0.2, duplicates=0.01)
            older, newer = world.older, world.newer
            truth = world.truth
            table = pass_table(older=GeneratedMnemonics(world, 'older'), newer=GeneratedMnemonics(world, 'newer'))
        out['generation'] = elapsed(start)
        start = stamp()
        a, b = SideData.from_ir(older), SideData.from_ir(newer)
        out['sides'] = elapsed(start)
        budget = Budget()
        if args.mode == 'common':
            start = stamp()
            blocked = block(State(a, b, DEFAULT_LIMITS, budget), None, None)
            out['blocking'] = {**elapsed(start), 'pairs': blocked.pairs,
                               'enumerated_members': blocked.work, 'abstained_buckets': blocked.caps}
        else:
            omitted = set(args.omit.split(','))
            if 'propagation' in omitted:
                import patchtrace.unified.ladder.engine as engine
                engine.propagate_to_fixpoint = lambda *_: None
            table = tuple(p for p in table if p.id not in omitted)
            log = {}
            def instrument(spec):
                if spec.run is None:
                    return spec
                def timed(st, rnd):
                    begin = stamp()
                    spec.run(st, rnd)
                    log[spec.id] = elapsed(begin)
                return dataclasses.replace(spec, run=timed)
            start = stamp()
            corr = run_ladder_data(a, b, passes=tuple(instrument(p) for p in table), budget=budget)
            out['ladder'] = elapsed(start)
            pairs = [(p.older_fid, p.newer_fid, p.pass_id, p.tier, p.chain) for p in corr.pairs]
            out.update(status=corr.status, pairs=len(pairs), stats=dict(corr.stats), limits_hit=dict(corr.limits_hit),
                       result_sha256=hashlib.sha256(json.dumps(pairs).encode()).hexdigest(), run_hooks=log)
            precision = Counter()
            for p in corr.pairs:
                old_rva, new_rva = corr.older_rva[p.older_fid], corr.newer_rva[p.newer_fid]
                if args.mode == 'exact':
                    right = p.older_fid == p.newer_fid
                elif args.mode in ('residual', 'ambiguous'):
                    right = truth[old_rva] == world.identity_newer[new_rva]
                else:
                    right = truth.get(old_rva) == new_rva
                precision[f'{p.pass_id}:{p.tier}:pairs'] += 1
                precision[f'{p.pass_id}:{p.tier}:right'] += int(right)
            out['truth_counts'] = dict(sorted(precision.items()))
            out['truth_total'] = args.n if args.mode == 'exact' else len(truth)
        out['ticks'] = budget.used
    out['total'] = elapsed(total)
    out['peak_rss_mib'] = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss / 1024
    out['rss_method'] = 'Linux resource.RUSAGE_SELF.ru_maxrss / 1024; process lifetime high water, includes generation'
    return out


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--mode', choices=('exact', 'residual', 'common', 'ambiguous', 'generated', 'cfg', 'assignment', 'collision'), required=True)
    parser.add_argument('--n', type=int, default=1000)
    parser.add_argument('--seed', type=int, default=1)
    parser.add_argument('--omit', default='')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.output:
        args.output = report_destination(args.output, checkout_root=ROOT)
    result = run(args)
    text = json.dumps(result, sort_keys=True, indent=2) + '\n'
    if args.output:
        write_report_json(args.output, result, checkout_root=ROOT)
    print(text)
