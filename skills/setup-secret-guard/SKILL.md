---
name: setup-secret-guard
description: Use when the user asks to "set up secret guard", "customize secret protection", "configure secret-guard rules", or wants to tune which secret-protection categories are active for their stack.
---

# Setting Up Secret Guard

## Overview

secret-guard ships a broad default rule pack covering cloud secret managers, database credentials, key files, Kubernetes secrets, and common API-token literal formats — active immediately after installing the plugin, read from `~/.claude/secret-guard/rules/` (falling back to the plugin's bundled defaults if that directory doesn't exist yet).

This skill personalizes that global rule set for the user's actual stack by writing a tuned copy of the category files to `~/.claude/secret-guard/rules/`.

## Workflow

1. Ask the user, one question at a time, which categories are relevant to them:
   - Which cloud provider(s) they use for secrets: GCP, AWS, Azure, more than one, or none.
   - Which databases they connect to directly from the terminal (Postgres/MySQL/MongoDB), if any.
   - Whether they use Kubernetes.
   - Whether they have any org-specific secret file naming conventions or paths not covered by the defaults (e.g. an internal `*.secret.json` convention) — if so, ask for the exact pattern.
   - How strict each kept category should be. Every rule has an `action`:
     - `deny`: always refused, no prompt. The bundled pack uses it for long-lived private keys: PEM blocks, SSH keys, `.pem/.pfx/.key` files, the AWS CLI credentials file, and creating GCP service-account keys.
     - `ask`: the user is asked before the call runs and can allow it once, allow that rule for the rest of the session, or refuse. The bundled default for everything else.
     - `warn`: the call runs and the user sees a notice.
     Offer the bundled defaults first and only change what the user asks to change.

2. Read the plugin's bundled rule files at `${CLAUDE_PLUGIN_ROOT}/rules/*.md` to see the full default set and each rule's `id`.

3. Create `~/.claude/secret-guard/rules/` if it doesn't exist, then write one `.md` file per category the user confirmed is relevant, copying the matching rules from the bundled set verbatim (same `id`, `match_against`, `pattern`, and message), with `action` as the user chose (the bundled one when they didn't say). Skip categories the user said don't apply to them (e.g. skip `kubernetes.md` entirely if they don't use Kubernetes).

4. For any org-specific pattern the user described, append a new rule block to the most relevant category file (or a new `custom.md` file if none fit), following the same format:
   ```markdown
   ---
   id: <kebab-case-id>
   match_against: [file_path]
   pattern: <the regex the user described>
   action: ask
   ---

   <a short message explaining what this rule caught>
   ```

5. Tell the user which files were written, and that the effect is immediate — no restart needed, since the guard reads the rules directory fresh on every tool call.

## Notes

- Never remove a category the user didn't explicitly say to drop, and never loosen a rule's `action` they didn't ask to loosen — when in doubt, keep the bundled default rather than silently narrowing coverage.
- Patterns are JavaScript regular expressions (no Python-only syntax such as `(?P<name>...)` or inline `(?i)`; matching is already case-insensitive). A pattern that doesn't compile never matches.
- `ask` needs someone to answer: in a non-interactive run (`claude -p`) it counts as a refusal.
- This skill only tunes the *global* rule set. It does not create or edit any project's `.claude/secret-guard-allow.local.md` allowlist — that's a manual, deliberate action the user takes per-project when a specific repo legitimately needs an exception.
