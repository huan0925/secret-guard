#!/usr/bin/env python3
"""PreToolUse dispatcher for the secret-guard plugin.

Reads the hook JSON from stdin, evaluates the active rule set against the
current tool call, and prints a hook response JSON. Always exits 0 —
if the guard itself is broken, we fail open (allow) with a loud warning
rather than blocking every operation, since a security tool that locks
everything when it breaks just gets disabled by frustrated users.
"""

import json
import os
import sys

# Where this script itself lives — that's where lib/ lives too, regardless
# of what CLAUDE_PLUGIN_ROOT points at (tests point it at a bare fixture dir).
REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if REPO_ROOT not in sys.path:
    sys.path.insert(0, REPO_ROOT)

# Where the *bundled* rule pack lives — defaults to this same repo, but a
# real plugin install sets CLAUDE_PLUGIN_ROOT to the plugin's install dir.
PLUGIN_ROOT = os.environ.get('CLAUDE_PLUGIN_ROOT', REPO_ROOT)

GLOBAL_RULES_DIR = os.path.expanduser('~/.claude/secret-guard/rules')
PROJECT_ALLOWLIST_PATH = os.path.join('.claude', 'secret-guard-allow.local.md')


def main():
    try:
        from lib.engine import evaluate, load_allowlist, load_rules_dir

        input_data = json.load(sys.stdin)
        tool_name = input_data.get('tool_name', '')
        tool_input = input_data.get('tool_input', {})

        bundled_rules_dir = os.path.join(PLUGIN_ROOT, 'rules')
        rules = load_rules_dir(GLOBAL_RULES_DIR, bundled_rules_dir)
        allowlist = load_allowlist(PROJECT_ALLOWLIST_PATH)
        result = evaluate(tool_name, tool_input, rules, allowlist)

        if result['action'] == 'deny':
            message = '\n\n'.join(result['messages'])
            print(json.dumps({
                'hookSpecificOutput': {
                    'hookEventName': 'PreToolUse',
                    'permissionDecision': 'deny',
                    'permissionDecisionReason': message,
                },
                'systemMessage': f"secret-guard blocked this: {message}",
            }))
        elif result['action'] == 'warn':
            message = '\n\n'.join(result['messages'])
            print(json.dumps({'systemMessage': f"secret-guard warning: {message}"}))
        elif result['messages']:
            # 'allow' but with allowlist notices — surface that the rule fired
            # and was downgraded, without blocking or warning.
            message = '\n\n'.join(result['messages'])
            print(json.dumps({'systemMessage': f"secret-guard: {message}"}))
        # 'allow' with no messages at all: print nothing, allow silently.

    except Exception as e:
        print(json.dumps({
            'systemMessage': (
                f"secret-guard did not run correctly this call "
                f"({type(e).__name__}: {e}) — allowing the operation. "
                f"Check ~/.claude/secret-guard/rules/ and the plugin's rules/ "
                f"directory for malformed or unreadable files."
            ),
        }))

    finally:
        sys.exit(0)


if __name__ == '__main__':
    main()
