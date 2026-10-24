#!/usr/bin/env bash
# SPDX-License-Identifier: MIT
# Fail when the commits a PR introduces (BASE..HEAD_SHA), or its description
# (PR_BODY), carry an AI-attribution trailer, or a commit is authored or
# committed as an AI identity. Only this PR's own commits are checked: the rule
# is "introduce no new one", not "rewrite history".
#
#   BASE=<ref> HEAD_SHA=<sha> PR_BODY=<text> scan.sh
set -euo pipefail
# shellcheck source=patterns.sh
. "$(dirname "${BASH_SOURCE[0]}")/patterns.sh"

: "${BASE:?BASE (a ref or sha) is required}"
: "${HEAD_SHA:?HEAD_SHA is required}"
fail=0

commits=$(git rev-list "${BASE}..${HEAD_SHA}")

bad_messages=''
bad_identities=''
for c in $commits; do
    if git log -1 --format='%B' "$c" | grep -qiE "$ai_pattern"; then
        bad_messages+="$(git log -1 --format='    %h %s' "$c")"$'\n'
    fi
    if git log -1 --format='%an <%ae>%n%cn <%ce>' "$c" | grep -qiE "$ai_identity"; then
        bad_identities+="$(git log -1 --format='    %h author %an <%ae>, committer %cn <%ce>' "$c")"$'\n'
    fi
done

if [[ -n "$bad_messages" ]]; then
    fail=1
    printf 'BLOCKED: these commits carry an AI-attribution trailer:\n%s\n' "$bad_messages"
fi
if [[ -n "$bad_identities" ]]; then
    fail=1
    printf 'BLOCKED: these commits are authored or committed as an AI identity:\n%s' "$bad_identities"
    echo "  fix: git rebase ${BASE} --exec 'git commit --amend --no-edit --reset-author'"
    echo "       with your own user.name/user.email, then git push --force-with-lease"
    echo
fi

body="${PR_BODY:-}"
if grep -qiE "$ai_optout" <<<"$body"; then
    echo "note: the PR description carries an ai-attribution-ok: annotation; it was not scanned."
elif grep -qiE "$ai_pattern" <<<"$body"; then
    fail=1
    echo "BLOCKED: the PR description carries an AI-attribution line:"
    grep -inE "$ai_pattern" <<<"$body" | sed 's/^/    /'
fi

if [[ "$fail" -eq 0 ]]; then
    echo "OK: no AI attribution in this PR's commits or description."
    exit 0
fi
echo "Strip the lines (git rebase -i, or git commit --amend), edit the description, and push again."
echo "When squash-merging, write the squash message yourself: GitHub builds it from the branch commits."
exit 1
