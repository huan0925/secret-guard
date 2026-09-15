# Secret Guard Plugin — Design

## Background

The user has a personal Claude Code hook (`~/.claude/hooks/block-secret-reads.sh`), registered globally via `~/.claude/settings.json`, that intercepts `PreToolUse(Bash)` events and denies commands that look like they read or handle secret values (`gcloud secrets versions access`, `psql`, reading `.env`/`.key` files). It works today but has three limits: the rule set is a single hardcoded regex baked into the script, it only covers Bash commands (not Claude reading/writing files directly), and it only covers a handful of GCP/Postgres-specific patterns.

The goal of this project is to turn this into a shareable, broadly-useful secret-protection tool: rules externalized and configurable, broad default coverage (cloud secret managers, databases, key files, Kubernetes, common API token formats), and coverage of both Bash commands and direct file access (Read/Edit/Write/MultiEdit). The user's longer-term plan (recorded, not in scope for this spec) is three phases: (A) a Claude Code plugin — this spec, (B) a standalone script+config for other hook-capable tools, (C) a cross-AI-tool CLI with adapters, since users increasingly work across ChatGPT/Grok/other assistants too.

### Why not just build on the existing `hookify` plugin?

`hookify` (official plugin, `plugins/hookify` in `anthropics/claude-code`) already provides a generic PreToolUse/PostToolUse/Stop/UserPromptSubmit rule engine driven by markdown files with YAML frontmatter, matching against `command`/`file_path`/`content` fields with `regex_match`/`contains`/etc. operators and `warn`/`block` actions — dependency-free (pure `python3` stdlib, no `yq`/`pyyaml`). This looked like a natural engine to build on rather than reinvent.

However, its rule loader (`core/config_loader.py`, `load_rules()`) does:

```python
pattern = os.path.join('.claude', 'hookify.*.local.md')
files = glob.glob(pattern)
```

This is a path relative to the current working directory, with no global (`~/.claude/`) fallback. This matches hookify's actual design intent — the `.local.md` naming convention and its own guidance to `.gitignore` these files mirrors this machine's own `settings.local.json` convention: personal, per-project, ad-hoc overrides, generated on the fly from conversations via its `conversation-analyzer` agent. It is not designed as a static, cross-project security baseline.

Relying on hookify alone would mean secret protection only applies to projects someone remembered to configure — the opposite of the goal (protection present everywhere, especially brand-new/unconfigured projects, which is where risk is highest: an unfamiliar repo is exactly where someone is more likely to run an unfamiliar `gcloud`/`psql` command by accident).

**Decision**: build a small dedicated dispatcher rather than delegating execution to hookify, using a hookify-compatible rule file format (same frontmatter shape and field/operator vocabulary) for familiarity, but reading rules from a global path so protection is always on regardless of which project/directory Claude Code is running in.

### Global vs. per-project scope

The only legitimate case for project-level config found during design review is the opposite of "add more rules per project": some projects' actual job is to operate on secrets (an infra/secrets-rotation repo, a Terraform repo) and their engineers legitimately run commands like `gcloud secrets versions access` daily. A strict global deny would create constant friction there, and the realistic failure mode is the user disabling the whole guard out of frustration — net negative for security.

The resolution: global rules are always the strict default (deny-by-default) and are the *only* enforcement layer. Per-project configuration may **only loosen** a named, already-existing global rule for that project (an explicit, visible, PR-reviewable allowlist) — it can never silently add restriction, and critically, it can never silently weaken or disable the guard as a whole. This inverts hookify's own model (project *adds* rules) to fit a security-baseline tool (project may *allowlist* specific named exceptions, with a paper trail).

## Architecture

```
secret-guard/                          (plugin root)
├── .claude-plugin/
│   └── plugin.json                    # plugin metadata (name, version, description, author)
├── hooks/
│   ├── hooks.json                     # registers PreToolUse for Bash|Read|Edit|Write|MultiEdit
│   └── guard.py                       # the dispatcher (python3 stdlib only)
├── rules/                             # bundled default rule pack, shipped with the plugin
│   ├── cloud-secrets.md
│   ├── db-credentials.md
│   ├── key-files.md
│   ├── kubernetes.md
│   └── api-token-patterns.md
└── skills/
    └── setup-secret-guard/
        └── SKILL.md                   # interview flow; writes ~/.claude/secret-guard/rules/*.md
```

Installed/active rules live at `~/.claude/secret-guard/rules/*.md` (global, one file per category, same format as the bundled pack). If that directory doesn't exist yet (plugin freshly installed, wizard not yet run), `guard.py` falls back to the plugin's own bundled `rules/` directory, so protection is on by default immediately after installing — the wizard is for customization, not a required activation step.

### Rule file format

One rule per file is not required — each `.md` file may contain multiple rules, each its own frontmatter block, consistent with how the bundled category files group related rules (e.g. `cloud-secrets.md` holds the gcloud/AWS/Azure secret-manager rules together). Format:

```markdown
---
id: gcloud-secret-access
match_against: [command]
pattern: 'gcloud\s+secrets\s+versions\s+(access|add)'
action: deny
---

⚠️ 此指令會讀取/寫入 Secret Manager 機密值，依你的設定需自行在終端機執行。
```

Fields:
- `id` (required): unique identifier, used by allowlist files to reference this rule.
- `match_against` (required): list of one or more of `command` (Bash `tool_input.command`), `file_path` (Read/Edit/Write/MultiEdit `tool_input.file_path`), `content` (Write's `tool_input.content` / Edit's `tool_input.new_string` — never checked for Read, since there is no content yet).
- `pattern` (required): a regex (Python `re`, case-insensitive), matched with `search` against every field named in `match_against` that's present for the current tool call — any match triggers the rule.
- `action` (optional, default `deny`): `deny` blocks the tool call outright; `warn` allows it but surfaces the message.
- The markdown body after the frontmatter is the message shown to the user/Claude when the rule fires.

### Dispatcher behavior (`guard.py`)

1. Read the hook JSON from stdin; extract `tool_name` and `tool_input`.
2. Load rules: glob `~/.claude/secret-guard/rules/*.md`; if that directory is missing or empty, glob the plugin's own bundled `${CLAUDE_PLUGIN_ROOT}/rules/*.md` instead. Parse each file's one-or-more frontmatter blocks with a small hand-rolled parser (no `pyyaml`/`yq` dependency — same rationale hookify used).
3. For each rule, build the set of candidate strings from `tool_input` based on `match_against` and the current `tool_name`: `command` reads `tool_input.command` (Bash only); `file_path` reads `tool_input.file_path` (Read/Edit/Write) — `MultiEdit` also exposes `file_path` directly on `tool_input`, so this applies to it too; `content` reads `tool_input.content` (Write), `tool_input.new_string` (Edit), or the concatenation of every `new_string` across `tool_input.edits` (MultiEdit) — and is simply skipped for `Read`, since there's no content field to check. Run `pattern` against each candidate; the rule matches if any candidate matches.
4. If a rule matches, look for `<project>/.claude/secret-guard-allow.local.md` (relative to cwd). If present, parse its `allow:` list of rule ids; if this rule's `id` is listed, downgrade the action to allow-with-notice (print a short "allowlisted" notice, don't block) instead of enforcing `action`.
5. Among all matched, non-allowlisted rules: if any has `action: deny`, deny the tool call (`hookSpecificOutput.permissionDecision: "deny"`) with a combined message from all denying rules. Otherwise, if any matched rule is `warn`, allow the call but print the combined warning message. If nothing matched, allow silently.
6. **Fail-open on internal errors**: if rule files are missing, malformed, or `guard.py` hits an unexpected exception, always allow the operation (`exit 0`, no deny), but print a loud `systemMessage` warning that the guard did not run correctly this time and why. Rationale: a security tool that hard-locks every operation when it itself is broken gets disabled by frustrated users, which is a worse outcome than one bypassed operation with a clear warning. This mirrors the fail-open behavior already present in the user's existing `block-secret-reads.sh`.

### Default rule pack coverage

Bundled `rules/*.md`, grouped by category (all default to `action: deny` unless noted):

- **cloud-secrets.md**: `gcloud secrets versions access/add`, `aws secretsmanager get-secret-value/create-secret`, Azure `az keyvault secret show`, `gcloud iam service-accounts keys create`, `gcloud run services describe` (env var leakage), `--data-file` flag.
- **db-credentials.md**: `psql` invocation, `PGPASSWORD=`, `mysql -p`, MongoDB URIs with embedded credentials.
- **key-files.md**: reading/matching `.env*`, `.pem`, `.pfx`, `.key`, `id_rsa`, `id_ed25519`, `~/.aws/credentials`, `~/.kube/config` — as both `file_path` (Read/Edit/Write) and `command` (`cat`/`less`/`grep`/etc. piping these paths) rules.
- **kubernetes.md**: `kubectl get/describe secret`, base64-decoding a k8s secret value in a pipeline.
- **api-token-patterns.md**: literal secret-shaped strings appearing in a command or in content about to be written — `AKIA[0-9A-Z]{16}` (AWS), `ghp_`/`gho_` (GitHub), `sk-` (OpenAI/Stripe-style), `xox[baprs]-` (Slack), `AIza` (Google API key), generic PEM header `-----BEGIN (RSA |EC )?PRIVATE KEY-----`.

### Setup wizard (`skills/setup-secret-guard/SKILL.md`)

Interviews the user (cloud provider(s) in use, DB types, whether Kubernetes is relevant, any org-specific secret paths/naming conventions) and writes a tuned copy of the rule files to `~/.claude/secret-guard/rules/`, disabling categories that don't apply and letting the user append custom rules in the same format. This is optional — the bundled defaults are active from install regardless — the wizard only personalizes.

## Testing plan (this round, local only)

This round stays local: build the plugin, load it via a local marketplace/path install in this Claude Code environment, and verify:
- A `Bash` command matching a `cloud-secrets`/`db-credentials`/`key-files` rule is denied with the rule's message, from any working directory (proving global scope — no per-project setup needed).
- A `Read` on a path matching `key-files` (e.g. a scratch `.env`) is denied.
- A `Write`/`Edit` whose new content matches an `api-token-patterns` rule (e.g. writing a string starting `AKIA...`) is denied.
- A command with a rule id allowlisted via `.claude/secret-guard-allow.local.md` in a scratch project directory is allowed with a notice, while the same command is still denied in a directory without that allowlist file.
- Rules directory temporarily renamed/broken → operations are still allowed (fail-open), with a visible warning.

Publishing to GitHub, marketplace listing, README/LICENSE, and a PR to `anthropics/claude-code` (plugins directory, as a new plugin — the plugins/README.md contributing guidance covers *adding a new plugin*, not modifying `hookify` itself) are explicitly out of scope for this round; the user wants to confirm local behavior first.

## Out of scope for this spec

- Phase B (standalone script + config, tool-agnostic) and Phase C (cross-AI-tool CLI with adapters for ChatGPT/Grok/etc.) — recorded as future phases, not designed here.
- GitHub publishing / marketplace listing / PR to `anthropics/claude-code`.
- Any dependency on the `hookify` plugin being installed — secret-guard is fully self-contained.
