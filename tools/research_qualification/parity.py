"""AV-5: parity of two engines' ranked changed-function lists over one frozen case manifest.

Each engine is scored with scoring.score_case, so the expected-function rank rule and the no_change rule are
identical for both. A case is `blocked` when either engine returned null or did not list it; blocked cases are
never hits and are never compared. A disagreement is a compared case where exactly one engine hit.
Top-k overlap is the size of the intersection of the two top-k sets; Jaccard is that size over the union, and
two empty top-k sets count as identical (1.0).
"""

from __future__ import annotations

from typing import Any

from . import scoring as SC

OUTCOMES = ("both-hit", "a-only", "b-only", "both-miss", "blocked")
_DISAGREE = ("a-only", "b-only")


def _mean(xs: list[float]) -> float | None:
    return round(sum(xs) / len(xs), 3) if xs else None


def _side(row: dict[str, Any]) -> dict[str, Any]:
    return {"verdict": row["outcome"], "rank": row["rank"]}


def compare_runs(
    manifest: dict[str, Any], a: dict[str, Any], b: dict[str, Any], k: int = 5
) -> dict[str, Any]:
    if k < 1:
        raise ValueError("k must be >= 1")
    if not isinstance(a, dict) or not isinstance(b, dict):
        raise ValueError("each results file must be a JSON object of {case_id: [functions]|null}")
    ids = {c["id"] for c in manifest["cases"]}
    for name, run in (("a", a), ("b", b)):
        unknown = sorted(set(run) - ids)
        if unknown:
            raise ValueError(f"results {name} name cases not in the manifest: {unknown}")

    rows: list[dict[str, Any]] = []
    overlaps: list[float] = []
    jaccards: list[float] = []
    for case in sorted(manifest["cases"], key=lambda c: c["id"]):
        cid = case["id"]
        ca, cb = a.get(cid), b.get(cid)
        ra = SC.score_case(case, ca, k)
        rb = SC.score_case(case, cb, k)
        if ra["outcome"] == "BLOCKED" or rb["outcome"] == "BLOCKED":
            outcome = "blocked"
            overlap = jacc = None
        else:
            ha, hb = ra["outcome"] == "HIT", rb["outcome"] == "HIT"
            outcome = "both-hit" if ha and hb else "a-only" if ha else "b-only" if hb else "both-miss"
            top_a, top_b = set(ca[:k]), set(cb[:k])
            inter, union = top_a & top_b, top_a | top_b
            overlap = len(inter)
            jacc = len(inter) / len(union) if union else 1.0
            overlaps.append(overlap)
            jaccards.append(jacc)
        rows.append(
            {
                "id": cid,
                "outcome": outcome,
                "a": {**_side(ra), "top_k": None if ca is None else ca[:k]},
                "b": {**_side(rb), "top_k": None if cb is None else cb[:k]},
                "overlap_at_k": overlap,
                "jaccard_at_k": None if jacc is None else round(jacc, 3),
            }
        )

    counts = {o: sum(r["outcome"] == o for r in rows) for o in OUTCOMES}
    compared = len(rows) - counts["blocked"]
    disagreements = [r["id"] for r in rows if r["outcome"] in _DISAGREE]
    return {
        "k": k,
        "cases": len(rows),
        "compared": compared,
        "blocked": counts["blocked"],
        "outcomes": counts,
        "disagreements": disagreements,
        "identical": compared > 0 and not disagreements,
        "mean_overlap_at_k": _mean(overlaps),
        "mean_jaccard_at_k": _mean(jaccards),
        "rows": rows,
        "caveat": "blocked cases are excluded from comparison and never counted as hits; "
        "compared cases only show that the engines agree or differ, not which one is right",
    }
