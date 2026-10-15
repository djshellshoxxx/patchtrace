"""Linear assignment with reject columns for the residual pass P19 (SPEC-31 04 s6.4).

A pure-Python shortest-augmenting-path solver of the Jonker-Volgenant family, written from the published description
of the algorithm (09-licensing s2: clean-room, no QBinDiff or BinSlayer code, no dependency). Integer costs only, so
the result is exact and identical on every platform and under any hash seed. Tie-break (documented, tested): rows are
added in input order and the lowest column index wins a tie, so equal costs give the identity assignment.
"""
from __future__ import annotations

from collections.abc import Callable, Sequence

_INF = 1 << 62


def solve(cost: Sequence[Sequence[int]], tick: Callable[[int], None] | None = None) -> list[int]:
    """The column of every row in a minimum-total-cost assignment of rows to distinct columns (rows <= columns).

    `tick(n)` is called once per Dijkstra expansion with the number of columns scanned, so a caller can meter work,
    enforce a deadline or abort by raising; nothing is returned in that case. O(rows^2 x columns) worst case.
    """
    rows = len(cost)
    if rows == 0:
        return []
    cols = len(cost[0])
    if cols < rows or any(len(row) != cols for row in cost):
        raise ValueError('an assignment needs a rectangular matrix with at least as many columns as rows')
    row_dual = [0] * rows                           # a new row's first expansion takes the minimum over all columns, which
    col_dual = [0] * cols                           # restores non-negative reduced costs (negative costs are fine)
    row_of_col = [-1] * cols
    col_of_row = [-1] * rows
    for start in range(rows):
        reach = [_INF] * cols                       # shortest reduced distance from `start`, per column
        via = [-1] * cols                           # the row that produced `reach`
        settled = [False] * cols
        inside: list[int] = []                      # settled columns that already have a row
        row, base = start, 0
        while True:
            costs, dual = cost[row], row_dual[row]
            best, best_col = _INF, -1
            for col in range(cols):
                if settled[col]:
                    continue
                candidate = base + costs[col] - dual - col_dual[col]
                if candidate < reach[col]:
                    reach[col] = candidate
                    via[col] = row
                if reach[col] < best:
                    best, best_col = reach[col], col
            if tick is not None:
                tick(cols)
            settled[best_col] = True
            base = best
            if row_of_col[best_col] < 0:
                end = best_col
                break
            inside.append(best_col)
            row = row_of_col[best_col]
        shortest = reach[end]
        for col in inside:                          # keep every reduced cost non-negative and the tree edges at zero
            delta = shortest - reach[col]
            col_dual[col] -= delta
            row_dual[row_of_col[col]] += delta
        row_dual[start] += shortest
        col = end
        while True:                                 # flip the alternating path back to `start`
            row = via[col]
            previous = col_of_row[row]
            row_of_col[col] = row
            col_of_row[row] = col
            if row == start:
                break
            col = previous
    return col_of_row


def assign_with_rejection(similarity: Sequence[Sequence[int]], *, floor: int, scale: int = 1000,
                          tick: Callable[[int], None] | None = None) -> list[int | None]:
    """Maximum-similarity assignment in which a row may stay unassigned (04 s6.4).

    `similarity` holds integers in `0..scale` (milli units at the call site); the cost of an assignment is
    `scale - similarity` and every row owns one dummy column of cost `scale - floor`, so a row takes a real column
    only when its similarity reaches `floor` (a tie at the floor is assigned). Returns the real column per row or
    None. Equivalent to maximising the sum of `similarity - floor` over the assigned pairs: symmetric in the sides.
    """
    rows = len(similarity)
    if rows == 0:
        return []
    cols = len(similarity[0])
    reject = scale - floor
    cost = [[scale - value for value in row] + [reject] * rows for row in similarity]
    return [col if col < cols else None for col in solve(cost, tick)]
