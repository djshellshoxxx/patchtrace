#!/usr/bin/env bash
# Prints the live state any contributor (human, ChatGPT/Codex, Claude) needs before acting.
# Needs: gh (authenticated) and jq. Read-only. Usage: tools/handoff_status.sh [owner/repo]
set -euo pipefail
repo="${1:-djshellshoxxx/patchtrace}"
command -v gh >/dev/null || { echo "gh CLI not found" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq not found" >&2; exit 2; }
echo "== default branch =="
gh api "repos/$repo" --jq '.default_branch' | while read -r b; do
  echo "$b $(gh api "repos/$repo/commits/$b" --jq '.sha[0:8]')"
done
echo "== open PRs (number | draft | base | head | mergeable_state | checks) =="
gh api "repos/$repo/pulls?state=open&per_page=100" --jq '.[].number' | sort -n | while read -r n; do
  pr=$(gh api "repos/$repo/pulls/$n")
  sha=$(jq -r .head.sha <<<"$pr")
  checks=$(gh api "repos/$repo/commits/$sha/check-runs?per_page=100" \
    --jq '[.check_runs[]|.conclusion//.status]|group_by(.)|map("\(.[0]):\(length)")|join(" ")')
  jq -r --arg c "$checks" '"#\(.number) | draft=\(.draft) | \(.base.ref) | \(.head.ref) | \(.mergeable_state) | \($c) | \(.title)"' <<<"$pr"
done
echo "== reminders =="
echo "Merge only when every test job is green and nothing blocking is open: gh api -X PUT repos/$repo/pulls/N/merge -f sha=HEAD_SHA -f merge_method=merge"
echo "Never force-push or rebase another worker's branch. REST only (GraphQL is blocked)."
