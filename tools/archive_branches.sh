#!/usr/bin/env bash
# Archive, then delete, remote branches whose content is preserved elsewhere.
#
# Input: a disposition TSV (docs/qa/branch-disposition-YYYYMMDD.tsv) with columns
#   branch  tip_sha  pr  last_commit  category  delete_safe  note
# Only rows whose delete_safe column is exactly "yes" are touched. For each one the script:
#   1. checks that the remote branch still points at the recorded tip_sha (a branch that moved is skipped and reported,
#      so a worker's newer commits are never deleted);
#   2. pushes a lightweight tag archive/<date>/<branch> at that SHA, so every commit stays reachable and the branch can
#      be restored with: git push origin archive/<date>/<branch>:refs/heads/<branch>
#   3. deletes the remote branch.
# Default is a dry run that changes nothing. Pass --apply to act. Stops at the first failed git command.
#
# Usage: tools/archive_branches.sh docs/qa/branch-disposition-20261118.tsv [--apply] [--remote origin]
set -euo pipefail

tsv=""
apply=0
remote=origin
while [ $# -gt 0 ]; do
  case "$1" in
    --apply) apply=1 ;;
    --remote) shift; remote="${1:?--remote needs a name}" ;;
    -h|--help) sed -n '2,15p' "$0"; exit 0 ;;
    *) [ -z "$tsv" ] || { echo "unexpected argument: $1" >&2; exit 2; }; tsv="$1" ;;
  esac
  shift
done
[ -n "$tsv" ] && [ -f "$tsv" ] || { echo "usage: $0 DISPOSITION.tsv [--apply] [--remote NAME]" >&2; exit 2; }
git rev-parse --git-dir >/dev/null 2>&1 || { echo "run inside a clone of the repository" >&2; exit 2; }

stamp=$(basename "$tsv" .tsv | grep -oE '[0-9]{8}$' || true)
[ -n "$stamp" ] || { echo "the TSV file name must end in a YYYYMMDD date" >&2; exit 2; }
header=$(head -n1 "$tsv")
[ "$header" = "$(printf 'branch\ttip_sha\tpr\tlast_commit\tcategory\tdelete_safe\tnote')" ] \
  || { echo "unexpected TSV header" >&2; exit 2; }

# One ls-remote for all heads keeps the check consistent and cheap.
heads=$(git ls-remote --heads "$remote")
planned=0; moved=0; missing=0; done_count=0
while IFS=$'\t' read -r branch sha _pr _date category safe _note; do
  [ "$safe" = "yes" ] || continue
  case "$branch" in main|master|''|-*) echo "refusing protected or invalid name: '$branch'" >&2; exit 2 ;; esac
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "bad SHA for $branch" >&2; exit 2; }
  current=$(printf '%s\n' "$heads" | awk -v ref="refs/heads/$branch" '$2 == ref {print $1}')
  if [ -z "$current" ]; then missing=$((missing + 1)); echo "gone     $branch"; continue; fi
  if [ "$current" != "$sha" ]; then moved=$((moved + 1)); echo "MOVED    $branch (recorded ${sha:0:12}, now ${current:0:12}); skipped"; continue; fi
  tag="archive/$stamp/$branch"
  planned=$((planned + 1))
  if [ "$apply" -eq 0 ]; then
    echo "would    $branch -> $tag ($category)"
    continue
  fi
  git push --quiet "$remote" "$sha:refs/tags/$tag"
  git push --quiet "$remote" --delete "refs/heads/$branch"
  done_count=$((done_count + 1))
  echo "archived $branch -> $tag"
done < <(tail -n +2 "$tsv")

if [ "$apply" -eq 0 ]; then
  echo "dry run: $planned to archive, $moved moved (skipped), $missing already gone. Re-run with --apply to act."
else
  echo "done: $done_count archived and deleted, $moved moved (skipped), $missing already gone."
fi
