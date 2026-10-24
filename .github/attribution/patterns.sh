# SPDX-License-Identifier: MIT
# shellcheck shell=bash disable=SC2034  # sourced: the variables are read by scan.sh and test.sh
# Patterns for the AI-attribution gate, sourced by scan.sh and test.sh so the
# gate and its fixtures cannot disagree. All are matched with grep -iE.

# A trailer or footer is always at the start of a line (after optional space,
# a markdown quote marker or emphasis); text ABOUT the rule quotes the same
# strings inline, mid-sentence, and must not fire. A session link fires anywhere.
ai_pattern='^[[:space:]]*>?[[:space:]]*[_*]*[[:space:]]*(Co-Authored-By:[[:space:]]*Claude|Claude-Session:|https://claude\.ai/code/session_|.?[[:space:]]*Generated (with|by) \[Claude Code\])|\]\(https://claude\.ai/code/session_'

# A commit authored or committed as the assistant, with a clean message.
ai_identity='noreply@anthropic\.com|^Claude[[:space:]]*<'

# A PR body that must quote a real trailer says so on its own line, with a reason.
ai_optout='^[[:space:]]*ai-attribution-ok:[[:space:]]*\S'
