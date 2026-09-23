# secret-guard

A Claude Code plugin that globally, always-on blocks Claude from running commands or reading/writing files that touch secrets — cloud secret managers, database credentials, key files, Kubernetes secrets, and common API token formats. Protection is on for every project by default, not just ones you remembered to configure.

It's a self-contained Python dispatcher (standard library only, no `yq`/`pyyaml`/external dependencies) hooked into Claude Code's `PreToolUse` event for `Bash`, `Read`, `Edit`, `Write`, and `MultiEdit`.

## Why

Asking an AI assistant to "be careful with secrets" is a suggestion, not a guarantee — it can forget, get talked into it, or just make a mistake. This plugin is a deterministic, code-level guard: the same input always produces the same deny/allow decision, regardless of what the model decides in that moment. It doesn't replace good judgment, but it stops the accidental case — `cat`-ing a `.env` file, running `psql` with a password inline, reading an SSH private key — before it happens.

## How this compares to [hookify](https://github.com/anthropics/claude-code/tree/main/plugins/hookify)

hookify is Anthropic's official general-purpose `PreToolUse`/`PostToolUse`/`Stop`/`UserPromptSubmit` rule engine — a good tool, and secret-guard's rule-file format is deliberately modeled on it. But they solve different problems by design, not just by content:

| | hookify | secret-guard |
|---|---|---|
| Rule storage | `.claude/hookify.*.local.md`, relative to the **current working directory** — per-project | `~/.claude/secret-guard/rules/*.md`, a **global** path — active in every project immediately |
| Intent | General-purpose behavior reminders, often generated ad hoc from a conversation (`conversation-analyzer` agent) via `/hookify` | A secrets-protection baseline, shipped with 23 rules active out of the box — no conversation needed to get coverage |
| What a project can do | **Add** rules (opt in, per project) | Only **allowlist** (loosen) specific, already-existing global rules by id — never add restriction, never silently disable the whole guard |
| Event/operator surface | Broader: 5 event types (`bash/file/stop/prompt/all`), 6 match operators (`regex_match/contains/equals/...`) | Narrower on purpose: `PreToolUse` only, across `Bash/Read/Edit/Write/MultiEdit`, single regex `match_against` |
| Read coverage | Documented `file` event covers Edit/Write/MultiEdit only; Read needs a manual `tool_matcher` override | Read is covered out of the box |
| Fail-open behavior | Fails open (allows) with a warning if rules can't load | Same principle — plus explicitly treats a missing bundled-rules directory as a hard error, so that failure mode can't go silently unwarned (found during this project's own end-to-end verification) |
| Dependencies | Pure `python3` standard library | Same |

The short version: hookify is a generic, per-project, conversation-driven rule engine. secret-guard is the opposite shape on purpose — global by default, with project-level config allowed to move in only one direction (documented exceptions), because a secrets guard that's easy to quietly weaken isn't much of a guard.

### Using both together, for defense in depth

They're not competing for the same job, so installing both is the recommended setup, not a compromise:

- **secret-guard** is your always-on, global secrets floor — installed once, active in every project, not something you configure per repo.
- **hookify** is for project-specific behavioral guardrails that have nothing to do with secrets — e.g. its own bundled examples (`dangerous-rm.local.md`, `require-tests-stop.local.md`, `console-log-warning.local.md`) catch a destructive `rm -rf`, forgetting to run tests before stopping, or debug code left in. Those are exactly the kind of "this project, this habit" rules hookify's conversation-driven, per-project model is built for — and things secret-guard deliberately doesn't try to cover.

**Install both** the same way you'd install either alone — pass both directories to `--plugin-dir`, or copy both into `~/.claude/skills/`:

```bash
claude --plugin-dir /path/to/secret-guard --plugin-dir /path/to/hookify
```

**They can't fight each other.** Claude Code runs every matching `PreToolUse` hook and a `deny`/`block` from any one of them wins — and hookify's rules can only ever `warn` or `block`, never force an `allow`. So there's no scenario where a permissive hookify rule overrides a secret-guard deny, or vice versa. Verified directly: with both plugins loaded together, a command matching a secret-guard rule was still denied, with no interference from hookify being present.

**One thing to know about overlap:** hookify ships an example rule for `.env` files (`examples/sensitive-files-warning.local.md`) that a user could copy into their own project. If you do, and secret-guard is also installed, you'd get both hookify's warning *and* secret-guard's deny on the same `.env` access — which is redundant but harmless (belt-and-suspenders). If the double message bothers you, just don't enable hookify example rules that overlap with something secret-guard already covers by default; let secret-guard own the secrets baseline and use hookify for everything else.

## What it catches (default rule pack)

23 rules across 5 categories, all deny-by-default:

- **Cloud secrets** (`rules/cloud-secrets.md`): `gcloud secrets versions access/add`, `gcloud iam service-accounts keys create`, `aws secretsmanager get-secret-value/create-secret/put-secret-value`, `az keyvault secret show`, `gcloud run services describe`, `--data-file` (scoped to `gcloud` commands).
- **Database credentials** (`rules/db-credentials.md`): `psql`, `PGPASSWORD=`, inline `mysql -p...` passwords, MongoDB connection URIs with embedded credentials.
- **Key files** (`rules/key-files.md`): `.env*` files, `.pem`/`.pfx`/`.key` files (both as file paths and in Bash commands like `cat foo.pem`), SSH private key filenames (`id_rsa`, `id_ed25519`, `id_ecdsa`), `~/.aws/credentials`, `~/.kube/config`.
- **Kubernetes** (`rules/kubernetes.md`): `kubectl get/describe secret`, base64-decoding a Kubernetes secret value.
- **API token literals** (`rules/api-token-patterns.md`): AWS access keys (`AKIA...`), GitHub tokens (`ghp_`/`ghs_`), OpenAI/Stripe-style keys (`sk-...`), Slack tokens (`xox...`), Google API keys (`AIza...`), PEM private key blocks.

Every rule can independently be `deny` (blocks the tool call) or `warn` (allows it, but surfaces a warning) — the shipped defaults are all `deny`.

## Installation

### Try it first, without installing anything

```bash
claude --plugin-dir /path/to/secret-guard
```

This loads the plugin for that one session only. Ask Claude to do something like:

- `gcloud secrets versions access latest --secret=test`
- Read a `.env` file
- Write a file containing a string starting with `AKIA`

Each should be denied with a Chinese-language explanation of why.

### Install it so it's always on

Copy this repo into your Claude Code skills directory (or symlink it, if you're actively developing it and want edits to take effect immediately):

```bash
mkdir -p ~/.claude/skills
cp -r /path/to/secret-guard ~/.claude/skills/secret-guard
# or: ln -s /path/to/secret-guard ~/.claude/skills/secret-guard
```

It loads automatically on your next Claude Code session — no flags needed, and it applies in every project directory, not just ones you've configured.

## Customizing which rules are active

The bundled rule pack (this repo's own `rules/*.md`) is broad by design. If you want to tune it to your actual stack — e.g. you never use Kubernetes, or you have an org-specific secret file naming convention — ask Claude:

> "set up secret guard"

This runs the `setup-secret-guard` skill, which interviews you about your cloud provider(s), databases, and any custom patterns, then writes a tuned copy of the rule files to `~/.claude/secret-guard/rules/`. Once that directory has any `.md` files in it, `guard.py` reads rules from there instead of the plugin's bundled defaults — the effect is immediate, no restart needed.

## Allowing a specific project to bypass a rule

Global rules are always the strict default. If one specific project legitimately needs to run something a rule blocks (e.g. an infra repo whose actual job is rotating secrets), create `.claude/secret-guard-allow.local.md` in that project:

```markdown
---
allow: [gcloud-secret-access]
---

This repo's job is secret rotation — this command is expected here.
```

Only rules explicitly listed by their `id` (see the ids in `rules/*.md`) are loosened, and only in that project directory. Every other project, and every other rule, stays denied. This file should be commented in code review like any other — it's a visible, deliberate exception, not a silent opt-out.

## If something goes wrong

If the rule files are missing, unreadable, or malformed, the guard **fails open**: it allows the operation rather than blocking everything, but prints a loud warning saying it didn't run correctly and why. A security tool that locks up every operation when it's broken just gets disabled by frustrated users — failing open with a visible warning means you notice and fix it instead.

## Known limitations

This is a text-matching guard, not a sandbox — it stops accidents, not someone deliberately trying to defeat it. A rule that only checks `command` text never sees `Write` calls, so its trigger text can be routed around (e.g. writing sensitive text to a file, then using `git commit -F file` instead of `-m "..."`). Treat this as a floor for careless mistakes, not a substitute for real access controls like IAM or secret manager permissions.

## Running the test suite

```bash
python3 -m unittest discover -s tests -t .
```

62 tests covering the rule-file parser, the matching engine, the dispatcher's end-to-end behavior (via real subprocess calls to `hooks/guard.py`), and the bundled rule pack's actual coverage.

## Project layout

```
secret-guard/
├── .claude-plugin/plugin.json    # plugin manifest
├── hooks/
│   ├── hooks.json                # registers the PreToolUse hook
│   └── guard.py                  # the dispatcher
├── lib/
│   ├── frontmatter.py            # rule-file parser
│   └── engine.py                 # matching/evaluation engine
├── rules/                        # bundled default rule pack (5 files, 23 rules)
├── skills/setup-secret-guard/    # tuning wizard
└── tests/                        # 62 tests
```

## License

MIT — see [LICENSE](LICENSE).

## Status

This is v0.1.0, built and verified locally (including a real end-to-end test via `claude --plugin-dir`). It hasn't yet been published to a marketplace or submitted as a PR to `anthropics/claude-code`.
