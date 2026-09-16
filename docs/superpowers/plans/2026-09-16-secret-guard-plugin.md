# Secret Guard Plugin Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a local, installable Claude Code plugin (`secret-guard`) that globally intercepts Bash/Read/Edit/Write/MultiEdit tool calls and denies (or warns on) ones that touch secrets — cloud secret managers, DB credentials, key files, Kubernetes secrets, common API-token literal formats — using a self-contained Python dispatcher (no `yq`/`pyyaml`), a hookify-compatible rule-file format, and an opt-in per-project allowlist for legitimate exceptions.

**Architecture:** `hooks/guard.py` is the `PreToolUse` entrypoint. It delegates to a small library (`lib/frontmatter.py` for parsing rule files, `lib/engine.py` for matching/evaluation) so the matching logic is unit-testable without spawning subprocesses. Rules live as markdown files with one-or-more YAML-frontmatter-delimited blocks; `guard.py` reads them from `~/.claude/secret-guard/rules/*.md` (global, falling back to the plugin's own bundled `rules/*.md` when that directory is empty/missing) plus an optional per-project `.claude/secret-guard-allow.local.md` allowlist.

**Tech Stack:** Python 3 standard library only (`re`, `glob`, `json`, `dataclasses`, `unittest`). No external dependencies.

Spec: `docs/superpowers/specs/2026-09-16-secret-guard-plugin-design.md`

---

## File Structure

```
secret-guard/
├── .claude-plugin/
│   └── plugin.json
├── hooks/
│   ├── hooks.json
│   └── guard.py
├── lib/
│   ├── __init__.py
│   ├── frontmatter.py     # parse_rule_file, parse_frontmatter_dict
│   └── engine.py          # Rule, load_rule_files, load_rules_dir, load_allowlist,
│                           # extract_candidates, rule_matches, evaluate
├── rules/                 # bundled default rule pack (5 category files)
│   ├── cloud-secrets.md
│   ├── db-credentials.md
│   ├── key-files.md
│   ├── kubernetes.md
│   └── api-token-patterns.md
├── skills/
│   └── setup-secret-guard/
│       └── SKILL.md
└── tests/
    ├── test_frontmatter.py
    ├── test_engine.py
    ├── test_guard_integration.py    # fixture-based dispatcher mechanics
    └── test_default_rules.py        # real bundled-pack coverage
```

---

### Task 1: Scaffold plugin skeleton

**Files:**
- Create: `.claude-plugin/plugin.json`
- Create: `lib/__init__.py`

- [ ] **Step 1: Create the directories and manifest**

```bash
mkdir -p .claude-plugin lib hooks rules skills/setup-secret-guard tests
touch lib/__init__.py
```

- [ ] **Step 2: Write the plugin manifest**

`.claude-plugin/plugin.json`:
```json
{
  "name": "secret-guard",
  "description": "Global, always-on protection against reading or running commands that touch secrets: cloud secret managers, database credentials, key files, Kubernetes secrets, and common API token formats.",
  "version": "0.1.0"
}
```

- [ ] **Step 3: Commit**

```bash
git add .claude-plugin lib/__init__.py
git commit -m "chore: scaffold secret-guard plugin skeleton"
```

---

### Task 2: Hook registration

**Files:**
- Create: `hooks/hooks.json`

- [ ] **Step 1: Write hooks.json**

`hooks/hooks.json`:
```json
{
  "hooks": {
    "PreToolUse": [
      {
        "matcher": "Bash|Read|Edit|Write|MultiEdit",
        "hooks": [
          {
            "type": "command",
            "command": "python3 \"${CLAUDE_PLUGIN_ROOT}/hooks/guard.py\"",
            "timeout": 10
          }
        ]
      }
    ]
  }
}
```

- [ ] **Step 2: Validate it's well-formed JSON**

Run: `python3 -c "import json; json.load(open('hooks/hooks.json'))" && echo OK`
Expected: `OK`

- [ ] **Step 3: Commit**

```bash
git add hooks/hooks.json
git commit -m "feat: register PreToolUse hook for Bash/Read/Edit/Write/MultiEdit"
```

---

### Task 3: Frontmatter dict parser

**Files:**
- Create: `lib/frontmatter.py`
- Test: `tests/test_frontmatter.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_frontmatter.py`:
```python
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.frontmatter import parse_frontmatter_dict, parse_rule_file


class TestParseFrontmatterDict(unittest.TestCase):
    def test_scalar_fields(self):
        lines = ['id: gcloud-secret-access', 'action: deny']
        result = parse_frontmatter_dict(lines)
        self.assertEqual(result, {'id': 'gcloud-secret-access', 'action': 'deny'})

    def test_inline_list_field(self):
        lines = ['match_against: [command, file_path]']
        result = parse_frontmatter_dict(lines)
        self.assertEqual(result, {'match_against': ['command', 'file_path']})

    def test_empty_inline_list_field(self):
        lines = ['allow: []']
        result = parse_frontmatter_dict(lines)
        self.assertEqual(result, {'allow': []})

    def test_pattern_with_colon_is_not_split_on_first_colon(self):
        lines = [r'pattern: mongodb://\S+:\S+@']
        result = parse_frontmatter_dict(lines)
        self.assertEqual(result['pattern'], r'mongodb://\S+:\S+@')

    def test_quoted_scalar_value_is_unquoted(self):
        lines = ["pattern: 'rm\\s+-rf'"]
        result = parse_frontmatter_dict(lines)
        self.assertEqual(result['pattern'], 'rm\\s+-rf')

    def test_blank_lines_and_comments_ignored(self):
        lines = ['', '# a comment', 'id: x']
        result = parse_frontmatter_dict(lines)
        self.assertEqual(result, {'id': 'x'})

    def test_bracket_shaped_pattern_stays_a_scalar(self):
        # 'pattern' is never treated as a list field, even if its value
        # happens to start with '[' and end with ']' (a regex char class).
        lines = ['pattern: [0-9]+']
        result = parse_frontmatter_dict(lines)
        self.assertEqual(result['pattern'], '[0-9]+')


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m unittest tests.test_frontmatter -v`
Expected: `ModuleNotFoundError: No module named 'lib.frontmatter'` (or import error)

- [ ] **Step 3: Implement `parse_frontmatter_dict`**

`lib/frontmatter.py`:
```python
"""Parser for secret-guard rule files."""

LIST_FIELDS = {'match_against', 'allow'}


def parse_frontmatter_dict(lines):
    """Parse a flat YAML-like frontmatter block into a dict.

    Supports scalar `key: value` lines and inline list syntax for the
    known list fields (`match_against`, `allow`), e.g. `key: [a, b]`.
    Every other field is always a scalar string, even if its value
    happens to look bracket-shaped (e.g. a regex character class).
    Comments (#) and blank lines are ignored.
    """
    result = {}
    for line in lines:
        stripped = line.strip()
        if not stripped or stripped.startswith('#'):
            continue
        if ':' not in stripped:
            continue
        key, value = stripped.split(':', 1)
        key = key.strip()
        value = value.strip()

        if key in LIST_FIELDS:
            inner = value.strip('[]').strip()
            if not inner:
                result[key] = []
            else:
                result[key] = [item.strip().strip('"').strip("'") for item in inner.split(',')]
        else:
            result[key] = value.strip('"').strip("'")

    return result
```

- [ ] **Step 4: Run to verify `TestParseFrontmatterDict` passes**

Run: `python3 -m unittest tests.test_frontmatter.TestParseFrontmatterDict -v`
Expected: `OK` (7 tests pass)

- [ ] **Step 5: Commit**

```bash
git add lib/frontmatter.py tests/test_frontmatter.py
git commit -m "feat: add frontmatter dict parser for rule files"
```

---

### Task 4: Multi-rule file parser

**Files:**
- Modify: `lib/frontmatter.py`
- Modify: `tests/test_frontmatter.py`

- [ ] **Step 1: Add the failing tests**

Append to `tests/test_frontmatter.py` (above the `if __name__` line):
```python
class TestParseRuleFile(unittest.TestCase):
    def test_single_rule(self):
        text = (
            "---\n"
            "id: a\n"
            "match_against: [command]\n"
            "pattern: rm\n"
            "action: deny\n"
            "---\n"
            "Warning message.\n"
        )
        rules = parse_rule_file(text)
        self.assertEqual(len(rules), 1)
        frontmatter, body = rules[0]
        self.assertEqual(frontmatter['id'], 'a')
        self.assertEqual(frontmatter['match_against'], ['command'])
        self.assertEqual(body, 'Warning message.')

    def test_multiple_rules_in_one_file(self):
        text = (
            "---\nid: a\nmatch_against: [command]\npattern: rm\n---\n"
            "Body A\n\n"
            "---\nid: b\nmatch_against: [file_path]\npattern: \\.env$\n---\n"
            "Body B\n"
        )
        rules = parse_rule_file(text)
        self.assertEqual(len(rules), 2)
        self.assertEqual(rules[0][0]['id'], 'a')
        self.assertEqual(rules[0][1], 'Body A')
        self.assertEqual(rules[1][0]['id'], 'b')
        self.assertEqual(rules[1][1], 'Body B')

    def test_empty_file_returns_no_rules(self):
        self.assertEqual(parse_rule_file(''), [])

    def test_file_not_starting_with_marker_returns_no_rules(self):
        self.assertEqual(parse_rule_file('id: a\npattern: x\n'), [])
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m unittest tests.test_frontmatter.TestParseRuleFile -v`
Expected: `AttributeError` or `NameError` — `parse_rule_file` doesn't exist yet

- [ ] **Step 3: Implement `parse_rule_file`**

Append to `lib/frontmatter.py`:
```python
def parse_rule_file(text):
    """Parse a rule file's text into a list of (frontmatter_dict, body) tuples.

    Each rule block looks like:
        ---
        key: value
        ---
        message body

    Multiple such blocks may appear back-to-back in the same file: the
    closing '---' of one rule's frontmatter also serves as the opening
    '---' of the next rule's frontmatter. A file with no '---' markers
    (or an odd, unpaired number of them) yields no rules.
    """
    lines = text.split('\n')
    marker_indices = [i for i, line in enumerate(lines) if line.strip() == '---']

    rules = []
    for k in range(0, len(marker_indices) - 1, 2):
        open_idx = marker_indices[k]
        close_idx = marker_indices[k + 1]
        frontmatter_lines = lines[open_idx + 1:close_idx]

        body_start = close_idx + 1
        body_end = marker_indices[k + 2] if k + 2 < len(marker_indices) else len(lines)
        body_lines = lines[body_start:body_end]

        frontmatter = parse_frontmatter_dict(frontmatter_lines)
        body = '\n'.join(body_lines).strip()
        rules.append((frontmatter, body))

    return rules
```

- [ ] **Step 4: Run the whole file to verify everything passes**

Run: `python3 -m unittest tests.test_frontmatter -v`
Expected: `OK` (11 tests pass)

- [ ] **Step 5: Commit**

```bash
git add lib/frontmatter.py tests/test_frontmatter.py
git commit -m "feat: support multiple rules per file in the frontmatter parser"
```

---

### Task 5: Rule data model and field extraction

**Files:**
- Create: `lib/engine.py`
- Create: `tests/test_engine.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_engine.py`:
```python
import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.engine import Rule, extract_candidates


def make_rule(match_against, pattern='irrelevant', action='deny', rule_id='r1'):
    return Rule(id=rule_id, match_against=match_against, pattern=pattern, action=action)


class TestExtractCandidates(unittest.TestCase):
    def test_bash_command_field(self):
        rule = make_rule(['command'])
        candidates = extract_candidates(rule, 'Bash', {'command': 'gcloud secrets versions access x'})
        self.assertEqual(candidates, ['gcloud secrets versions access x'])

    def test_command_field_ignored_for_non_bash_tools(self):
        rule = make_rule(['command'])
        candidates = extract_candidates(rule, 'Read', {'file_path': '/tmp/x', 'command': 'ignored'})
        self.assertEqual(candidates, [])

    def test_file_path_field_for_read_edit_write_multiedit(self):
        rule = make_rule(['file_path'])
        for tool_name in ('Read', 'Edit', 'Write', 'MultiEdit'):
            candidates = extract_candidates(rule, tool_name, {'file_path': '/tmp/.env'})
            self.assertEqual(candidates, ['/tmp/.env'], msg=tool_name)

    def test_content_field_for_write(self):
        rule = make_rule(['content'])
        candidates = extract_candidates(rule, 'Write', {'content': 'AKIA_SOMETHING'})
        self.assertEqual(candidates, ['AKIA_SOMETHING'])

    def test_content_field_for_edit_reads_new_string(self):
        rule = make_rule(['content'])
        candidates = extract_candidates(rule, 'Edit', {'new_string': 'AKIA_SOMETHING'})
        self.assertEqual(candidates, ['AKIA_SOMETHING'])

    def test_content_field_for_multiedit_concatenates_edits(self):
        rule = make_rule(['content'])
        tool_input = {'edits': [{'new_string': 'foo'}, {'new_string': 'bar'}]}
        candidates = extract_candidates(rule, 'MultiEdit', tool_input)
        self.assertEqual(candidates, ['foo bar'])

    def test_content_field_skipped_for_read(self):
        rule = make_rule(['content'])
        candidates = extract_candidates(rule, 'Read', {'file_path': '/tmp/.env'})
        self.assertEqual(candidates, [])

    def test_empty_field_values_are_dropped(self):
        rule = make_rule(['command'])
        candidates = extract_candidates(rule, 'Bash', {'command': ''})
        self.assertEqual(candidates, [])


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m unittest tests.test_engine -v`
Expected: `ModuleNotFoundError: No module named 'lib.engine'`

- [ ] **Step 3: Implement `Rule` and `extract_candidates`**

`lib/engine.py`:
```python
"""Rule matching engine for secret-guard."""

from dataclasses import dataclass, field
from typing import List


@dataclass
class Rule:
    id: str
    match_against: List[str]
    pattern: str
    action: str = 'deny'
    message: str = ''
    source_file: str = ''


def extract_candidates(rule, tool_name, tool_input):
    """Return the strings from tool_input this rule should check, per its match_against."""
    candidates = []
    for field_name in rule.match_against:
        if field_name == 'command' and tool_name == 'Bash':
            candidates.append(tool_input.get('command', ''))
        elif field_name == 'file_path' and tool_name in ('Read', 'Edit', 'Write', 'MultiEdit'):
            candidates.append(tool_input.get('file_path', ''))
        elif field_name == 'content':
            if tool_name == 'Write':
                candidates.append(tool_input.get('content', ''))
            elif tool_name == 'Edit':
                candidates.append(tool_input.get('new_string', ''))
            elif tool_name == 'MultiEdit':
                edits = tool_input.get('edits', [])
                candidates.append(' '.join(e.get('new_string', '') for e in edits))
            # Read has no content field yet — nothing to add.
    return [c for c in candidates if c]
```

- [ ] **Step 4: Run to verify it passes**

Run: `python3 -m unittest tests.test_engine -v`
Expected: `OK` (8 tests pass)

- [ ] **Step 5: Commit**

```bash
git add lib/engine.py tests/test_engine.py
git commit -m "feat: add Rule model and per-tool field extraction"
```

---

### Task 6: Rule matching

**Files:**
- Modify: `lib/engine.py`
- Modify: `tests/test_engine.py`

- [ ] **Step 1: Add the failing tests**

Append to `tests/test_engine.py` (above `if __name__`):
```python
from lib.engine import rule_matches


class TestRuleMatches(unittest.TestCase):
    def test_matches_when_pattern_found_in_a_candidate(self):
        rule = make_rule(['command'], pattern=r'gcloud\s+secrets\s+versions\s+access')
        self.assertTrue(rule_matches(rule, 'Bash', {'command': 'gcloud secrets versions access foo'}))

    def test_does_not_match_unrelated_command(self):
        rule = make_rule(['command'], pattern=r'gcloud\s+secrets\s+versions\s+access')
        self.assertFalse(rule_matches(rule, 'Bash', {'command': 'ls -la'}))

    def test_matching_is_case_insensitive(self):
        rule = make_rule(['command'], pattern='rm -rf')
        self.assertTrue(rule_matches(rule, 'Bash', {'command': 'RM -RF /tmp/x'}))

    def test_no_candidates_means_no_match(self):
        rule = make_rule(['content'])
        self.assertFalse(rule_matches(rule, 'Read', {'file_path': '/tmp/.env'}))

    def test_invalid_regex_is_treated_as_no_match(self):
        rule = make_rule(['command'], pattern='[unclosed')
        self.assertFalse(rule_matches(rule, 'Bash', {'command': 'anything'}))
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m unittest tests.test_engine.TestRuleMatches -v`
Expected: `ImportError: cannot import name 'rule_matches'`

- [ ] **Step 3: Implement `rule_matches`**

Append to `lib/engine.py` (add `import re` to the top imports):
```python
import re


def rule_matches(rule, tool_name, tool_input):
    candidates = extract_candidates(rule, tool_name, tool_input)
    if not candidates:
        return False
    try:
        regex = re.compile(rule.pattern, re.IGNORECASE)
    except re.error:
        return False
    return any(regex.search(candidate) for candidate in candidates)
```

- [ ] **Step 4: Run to verify it passes**

Run: `python3 -m unittest tests.test_engine -v`
Expected: `OK` (13 tests pass)

- [ ] **Step 5: Commit**

```bash
git add lib/engine.py tests/test_engine.py
git commit -m "feat: add rule_matches regex matching"
```

---

### Task 7: Loading rule files and directories

**Files:**
- Modify: `lib/engine.py`
- Modify: `tests/test_engine.py`

- [ ] **Step 1: Add the failing tests**

Append to `tests/test_engine.py`:
```python
import tempfile

from lib.engine import load_rule_files, load_rules_dir


class TestLoadRuleFiles(unittest.TestCase):
    def test_loads_rules_from_a_glob_pattern(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'a.md')
            with open(path, 'w') as f:
                f.write(
                    "---\nid: r1\nmatch_against: [command]\npattern: foo\naction: deny\n---\n"
                    "Message one.\n"
                )
            rules = load_rule_files([os.path.join(tmp, '*.md')])
            self.assertEqual(len(rules), 1)
            self.assertEqual(rules[0].id, 'r1')
            self.assertEqual(rules[0].match_against, ['command'])
            self.assertEqual(rules[0].pattern, 'foo')
            self.assertEqual(rules[0].action, 'deny')
            self.assertEqual(rules[0].message, 'Message one.')

    def test_skips_blocks_missing_id_or_pattern(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'a.md')
            with open(path, 'w') as f:
                f.write("---\naction: deny\n---\nno id or pattern here\n")
            rules = load_rule_files([os.path.join(tmp, '*.md')])
            self.assertEqual(rules, [])

    def test_defaults_action_to_deny_when_omitted(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'a.md')
            with open(path, 'w') as f:
                f.write("---\nid: r1\nmatch_against: [command]\npattern: foo\n---\nmsg\n")
            rules = load_rule_files([os.path.join(tmp, '*.md')])
            self.assertEqual(rules[0].action, 'deny')


class TestLoadRulesDir(unittest.TestCase):
    def test_uses_global_dir_when_it_has_rule_files(self):
        with tempfile.TemporaryDirectory() as global_dir, tempfile.TemporaryDirectory() as bundled_dir:
            with open(os.path.join(global_dir, 'a.md'), 'w') as f:
                f.write("---\nid: global-rule\nmatch_against: [command]\npattern: x\n---\nmsg\n")
            with open(os.path.join(bundled_dir, 'a.md'), 'w') as f:
                f.write("---\nid: bundled-rule\nmatch_against: [command]\npattern: x\n---\nmsg\n")

            rules = load_rules_dir(global_dir, bundled_dir)
            self.assertEqual([r.id for r in rules], ['global-rule'])

    def test_falls_back_to_bundled_dir_when_global_dir_is_missing(self):
        with tempfile.TemporaryDirectory() as bundled_dir:
            missing_global_dir = os.path.join(bundled_dir, 'does-not-exist')
            with open(os.path.join(bundled_dir, 'a.md'), 'w') as f:
                f.write("---\nid: bundled-rule\nmatch_against: [command]\npattern: x\n---\nmsg\n")

            rules = load_rules_dir(missing_global_dir, bundled_dir)
            self.assertEqual([r.id for r in rules], ['bundled-rule'])

    def test_falls_back_to_bundled_dir_when_global_dir_is_empty(self):
        with tempfile.TemporaryDirectory() as global_dir, tempfile.TemporaryDirectory() as bundled_dir:
            with open(os.path.join(bundled_dir, 'a.md'), 'w') as f:
                f.write("---\nid: bundled-rule\nmatch_against: [command]\npattern: x\n---\nmsg\n")

            rules = load_rules_dir(global_dir, bundled_dir)
            self.assertEqual([r.id for r in rules], ['bundled-rule'])
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m unittest tests.test_engine.TestLoadRuleFiles tests.test_engine.TestLoadRulesDir -v`
Expected: `ImportError: cannot import name 'load_rule_files'`

- [ ] **Step 3: Implement `load_rule_files` and `load_rules_dir`**

Append to `lib/engine.py` (add `import glob` and `import os` to the top imports, and `from lib.frontmatter import parse_rule_file`):
```python
import glob
import os

from lib.frontmatter import parse_rule_file


def load_rule_files(glob_patterns):
    """Load and parse every rule file matched by the given glob patterns.

    Args:
        glob_patterns: list of glob patterns, e.g. ['/some/dir/*.md'].

    Returns:
        List of Rule objects, in file-then-in-file order. Blocks missing
        `id` or `pattern` are skipped.
    """
    rules = []
    for pattern in glob_patterns:
        for file_path in sorted(glob.glob(pattern)):
            with open(file_path, 'r') as f:
                text = f.read()
            for frontmatter, body in parse_rule_file(text):
                if 'id' not in frontmatter or 'pattern' not in frontmatter:
                    continue
                rules.append(Rule(
                    id=frontmatter['id'],
                    match_against=frontmatter.get('match_against', []),
                    pattern=frontmatter['pattern'],
                    action=frontmatter.get('action', 'deny'),
                    message=body,
                    source_file=file_path,
                ))
    return rules


def load_rules_dir(global_dir, bundled_dir):
    """Load rules from global_dir if it has any *.md files, else from bundled_dir."""
    global_pattern = os.path.join(global_dir, '*.md')
    if glob.glob(global_pattern):
        return load_rule_files([global_pattern])
    return load_rule_files([os.path.join(bundled_dir, '*.md')])
```

- [ ] **Step 4: Run to verify it passes**

Run: `python3 -m unittest tests.test_engine -v`
Expected: `OK` (19 tests pass)

- [ ] **Step 5: Commit**

```bash
git add lib/engine.py tests/test_engine.py
git commit -m "feat: load rules from files and global-with-bundled-fallback directories"
```

---

### Task 8: Allowlist loading

**Files:**
- Modify: `lib/engine.py`
- Modify: `tests/test_engine.py`

- [ ] **Step 1: Add the failing tests**

Append to `tests/test_engine.py`:
```python
from lib.engine import load_allowlist


class TestLoadAllowlist(unittest.TestCase):
    def test_returns_empty_set_when_file_missing(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'does-not-exist.md')
            self.assertEqual(load_allowlist(path), set())

    def test_returns_allowed_ids_from_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = os.path.join(tmp, 'allow.md')
            with open(path, 'w') as f:
                f.write("---\nallow: [gcloud-secret-access, psql-invocation]\n---\nWhy this repo needs it.\n")
            self.assertEqual(load_allowlist(path), {'gcloud-secret-access', 'psql-invocation'})
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m unittest tests.test_engine.TestLoadAllowlist -v`
Expected: `ImportError: cannot import name 'load_allowlist'`

- [ ] **Step 3: Implement `load_allowlist`**

Append to `lib/engine.py`:
```python
def load_allowlist(allowlist_path):
    """Return the set of rule ids allowlisted by this project's allowlist file.

    Returns an empty set if the file doesn't exist.
    """
    if not os.path.isfile(allowlist_path):
        return set()
    with open(allowlist_path, 'r') as f:
        text = f.read()
    allowed = set()
    for frontmatter, _body in parse_rule_file(text):
        allowed.update(frontmatter.get('allow', []))
    return allowed
```

- [ ] **Step 4: Run to verify it passes**

Run: `python3 -m unittest tests.test_engine -v`
Expected: `OK` (21 tests pass)

- [ ] **Step 5: Commit**

```bash
git add lib/engine.py tests/test_engine.py
git commit -m "feat: load per-project rule allowlist"
```

---

### Task 9: Evaluation

**Files:**
- Modify: `lib/engine.py`
- Modify: `tests/test_engine.py`

- [ ] **Step 1: Add the failing tests**

Append to `tests/test_engine.py`:
```python
from lib.engine import evaluate


class TestEvaluate(unittest.TestCase):
    def test_no_rules_match_allows_silently(self):
        rules = [make_rule(['command'], pattern='gcloud secrets', rule_id='r1')]
        result = evaluate('Bash', {'command': 'ls -la'}, rules, allowlist=set())
        self.assertEqual(result, {'action': 'allow', 'messages': [], 'matched_ids': []})

    def test_matching_deny_rule_denies(self):
        rule = make_rule(['command'], pattern='gcloud secrets', action='deny', rule_id='gcloud-secret-access')
        rule.message = 'blocked message'
        result = evaluate('Bash', {'command': 'gcloud secrets versions access x'}, [rule], allowlist=set())
        self.assertEqual(result['action'], 'deny')
        self.assertEqual(result['matched_ids'], ['gcloud-secret-access'])
        self.assertEqual(result['messages'], ['blocked message'])

    def test_matching_warn_rule_warns_without_denying(self):
        rule = make_rule(['command'], pattern='sketchy', action='warn', rule_id='r1')
        rule.message = 'careful'
        result = evaluate('Bash', {'command': 'sketchy-thing'}, [rule], allowlist=set())
        self.assertEqual(result['action'], 'warn')
        self.assertEqual(result['matched_ids'], ['r1'])

    def test_deny_takes_priority_over_warn(self):
        deny_rule = make_rule(['command'], pattern='foo', action='deny', rule_id='deny-rule')
        warn_rule = make_rule(['command'], pattern='foo', action='warn', rule_id='warn-rule')
        result = evaluate('Bash', {'command': 'foo'}, [deny_rule, warn_rule], allowlist=set())
        self.assertEqual(result['action'], 'deny')
        self.assertEqual(result['matched_ids'], ['deny-rule'])

    def test_allowlisted_rule_is_not_denied(self):
        rule = make_rule(['command'], pattern='gcloud secrets', action='deny', rule_id='gcloud-secret-access')
        result = evaluate(
            'Bash', {'command': 'gcloud secrets versions access x'}, [rule],
            allowlist={'gcloud-secret-access'},
        )
        self.assertEqual(result['action'], 'allow')
        self.assertEqual(result['matched_ids'], ['gcloud-secret-access'])

    def test_allowlisting_one_rule_does_not_allowlist_another(self):
        allowed_rule = make_rule(['command'], pattern='foo', action='deny', rule_id='allowed-rule')
        other_rule = make_rule(['command'], pattern='foo', action='deny', rule_id='other-rule')
        result = evaluate(
            'Bash', {'command': 'foo'}, [allowed_rule, other_rule],
            allowlist={'allowed-rule'},
        )
        self.assertEqual(result['action'], 'deny')
        self.assertEqual(result['matched_ids'], ['other-rule'])
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m unittest tests.test_engine.TestEvaluate -v`
Expected: `ImportError: cannot import name 'evaluate'`

- [ ] **Step 3: Implement `evaluate`**

Append to `lib/engine.py`:
```python
def evaluate(tool_name, tool_input, rules, allowlist):
    """Evaluate every rule against this tool call.

    Returns {'action': 'deny'|'warn'|'allow', 'messages': [...], 'matched_ids': [...]}.
    A matched rule whose id is in `allowlist` never denies or warns, but its
    id is still surfaced in `matched_ids` (with a 'allow'-action, notice-style
    message) when nothing else matched, so the allowlisting is visible.
    """
    denies = []
    warns = []
    allowlisted = []

    for rule in rules:
        if not rule_matches(rule, tool_name, tool_input):
            continue
        if rule.id in allowlist:
            allowlisted.append(rule)
            continue
        if rule.action == 'warn':
            warns.append(rule)
        else:
            denies.append(rule)

    if denies:
        return {
            'action': 'deny',
            'messages': [r.message for r in denies],
            'matched_ids': [r.id for r in denies],
        }
    if warns:
        return {
            'action': 'warn',
            'messages': [r.message for r in warns],
            'matched_ids': [r.id for r in warns],
        }
    if allowlisted:
        return {
            'action': 'allow',
            'messages': [f'Allowlisted: {r.id}' for r in allowlisted],
            'matched_ids': [r.id for r in allowlisted],
        }
    return {'action': 'allow', 'messages': [], 'matched_ids': []}
```

- [ ] **Step 4: Run to verify it passes**

Run: `python3 -m unittest tests.test_engine -v`
Expected: `OK` (27 tests pass)

- [ ] **Step 5: Commit**

```bash
git add lib/engine.py tests/test_engine.py
git commit -m "feat: add evaluate() combining matching, allowlist, and action priority"
```

---

### Task 10: Dispatcher entrypoint and mechanics integration tests

**Files:**
- Create: `hooks/guard.py`
- Create: `tests/test_guard_integration.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_guard_integration.py`:
```python
import json
import os
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUARD_SCRIPT = os.path.join(REPO_ROOT, 'hooks', 'guard.py')

FIXTURE_RULES = (
    "---\n"
    "id: test-deny-rule\n"
    "match_against: [command]\n"
    "pattern: forbidden-command\n"
    "action: deny\n"
    "---\n"
    "Fixture deny message.\n"
    "\n"
    "---\n"
    "id: test-warn-rule\n"
    "match_against: [command]\n"
    "pattern: sketchy-thing\n"
    "action: warn\n"
    "---\n"
    "Fixture warn message.\n"
    "\n"
    "---\n"
    "id: test-file-path-rule\n"
    "match_against: [file_path]\n"
    "pattern: \\.env$\n"
    "action: deny\n"
    "---\n"
    "Fixture file_path deny message.\n"
    "\n"
    "---\n"
    "id: test-content-rule\n"
    "match_against: [content]\n"
    "pattern: SECRETVALUE\n"
    "action: deny\n"
    "---\n"
    "Fixture content deny message.\n"
)


def run_guard(tool_name, tool_input, plugin_root, home_dir, cwd):
    input_data = json.dumps({'tool_name': tool_name, 'tool_input': tool_input})
    env = dict(os.environ)
    env['HOME'] = home_dir
    env['CLAUDE_PLUGIN_ROOT'] = plugin_root
    return subprocess.run(
        [sys.executable, GUARD_SCRIPT],
        input=input_data,
        capture_output=True,
        text=True,
        cwd=cwd,
        env=env,
    )


class GuardIntegrationTestCase(unittest.TestCase):
    def setUp(self):
        self.plugin_root_dir = tempfile.TemporaryDirectory()
        self.home_dir = tempfile.TemporaryDirectory()
        self.project_dir = tempfile.TemporaryDirectory()

        rules_dir = os.path.join(self.plugin_root_dir.name, 'rules')
        os.makedirs(rules_dir)
        with open(os.path.join(rules_dir, 'fixture.md'), 'w') as f:
            f.write(FIXTURE_RULES)

    def tearDown(self):
        self.plugin_root_dir.cleanup()
        self.home_dir.cleanup()
        self.project_dir.cleanup()

    def run_guard(self, tool_name, tool_input, cwd=None):
        return run_guard(
            tool_name, tool_input,
            plugin_root=self.plugin_root_dir.name,
            home_dir=self.home_dir.name,
            cwd=cwd or self.project_dir.name,
        )


class TestGuardMechanics(GuardIntegrationTestCase):
    def test_matching_bash_command_is_denied_from_a_fresh_directory(self):
        fresh_dir = tempfile.TemporaryDirectory()
        try:
            result = self.run_guard('Bash', {'command': 'run forbidden-command now'}, cwd=fresh_dir.name)
        finally:
            fresh_dir.cleanup()
        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertEqual(output['hookSpecificOutput']['permissionDecision'], 'deny')
        self.assertIn('Fixture deny message.', output['hookSpecificOutput']['permissionDecisionReason'])

    def test_harmless_bash_command_is_allowed_silently(self):
        result = self.run_guard('Bash', {'command': 'ls -la'})
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), '')

    def test_warn_rule_allows_but_prints_a_warning(self):
        result = self.run_guard('Bash', {'command': 'sketchy-thing happened'})
        output = json.loads(result.stdout)
        self.assertNotIn('hookSpecificOutput', output)
        self.assertIn('Fixture warn message.', output['systemMessage'])

    def test_read_matching_file_path_is_denied(self):
        result = self.run_guard('Read', {'file_path': '/some/project/.env'})
        output = json.loads(result.stdout)
        self.assertEqual(output['hookSpecificOutput']['permissionDecision'], 'deny')

    def test_write_matching_content_is_denied(self):
        result = self.run_guard('Write', {'file_path': '/tmp/notes.txt', 'content': 'value=SECRETVALUE'})
        output = json.loads(result.stdout)
        self.assertEqual(output['hookSpecificOutput']['permissionDecision'], 'deny')

    def test_read_is_never_checked_against_content_rules(self):
        # test-content-rule matches 'SECRETVALUE' but only via match_against: [content],
        # and Read has no content field — so it must not be denied on that account.
        result = self.run_guard('Read', {'file_path': '/tmp/SECRETVALUE.txt'})
        self.assertEqual(result.stdout.strip(), '')


class TestGuardAllowlist(GuardIntegrationTestCase):
    def test_allowlisted_project_downgrades_the_rule_to_allow(self):
        claude_dir = os.path.join(self.project_dir.name, '.claude')
        os.makedirs(claude_dir, exist_ok=True)
        with open(os.path.join(claude_dir, 'secret-guard-allow.local.md'), 'w') as f:
            f.write('---\nallow: [test-deny-rule]\n---\nThis repo needs it.\n')

        result = self.run_guard('Bash', {'command': 'run forbidden-command now'})
        output = json.loads(result.stdout)
        self.assertNotIn('hookSpecificOutput', output)

    def test_a_different_project_without_the_allowlist_is_still_denied(self):
        other_project = tempfile.TemporaryDirectory()
        try:
            result = self.run_guard('Bash', {'command': 'run forbidden-command now'}, cwd=other_project.name)
        finally:
            other_project.cleanup()
        output = json.loads(result.stdout)
        self.assertEqual(output['hookSpecificOutput']['permissionDecision'], 'deny')


class TestGuardFailsOpen(GuardIntegrationTestCase):
    def test_unreadable_rule_file_fails_open_with_a_warning(self):
        rules_dir = os.path.join(self.plugin_root_dir.name, 'rules')
        broken_file = os.path.join(rules_dir, 'fixture.md')
        os.chmod(broken_file, 0o000)
        try:
            result = self.run_guard('Bash', {'command': 'run forbidden-command now'})
        finally:
            os.chmod(broken_file, 0o644)

        self.assertEqual(result.returncode, 0)
        output = json.loads(result.stdout)
        self.assertNotIn('hookSpecificOutput', output)
        self.assertIn('secret-guard did not run correctly', output['systemMessage'])


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m unittest tests.test_guard_integration -v`
Expected: fails — `hooks/guard.py` doesn't exist yet (non-zero exit / `FileNotFoundError` surfaced via subprocess, or similar)

- [ ] **Step 3: Implement `hooks/guard.py`**

```python
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

PLUGIN_ROOT = os.environ.get(
    'CLAUDE_PLUGIN_ROOT',
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
)
if PLUGIN_ROOT not in sys.path:
    sys.path.insert(0, PLUGIN_ROOT)

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
        # 'allow' with no messages: print nothing, allow silently.

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
```

- [ ] **Step 4: Run to verify it passes**

Run: `python3 -m unittest tests.test_guard_integration -v`
Expected: `OK` (8 tests pass)

- [ ] **Step 5: Commit**

```bash
git add hooks/guard.py tests/test_guard_integration.py
git commit -m "feat: add guard.py PreToolUse dispatcher with fail-open error handling"
```

---

### Task 11: Bundled default rule pack

**Files:**
- Create: `rules/cloud-secrets.md`
- Create: `rules/db-credentials.md`
- Create: `rules/key-files.md`
- Create: `rules/kubernetes.md`
- Create: `rules/api-token-patterns.md`
- Create: `tests/test_default_rules.py`

- [ ] **Step 1: Write the failing tests**

`tests/test_default_rules.py`:
```python
import json
import os
import re
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
GUARD_SCRIPT = os.path.join(REPO_ROOT, 'hooks', 'guard.py')

sys.path.insert(0, REPO_ROOT)
from lib.engine import load_rule_files

EXPECTED_RULE_IDS = {
    'gcloud-secret-access',
    'gcloud-iam-key-create',
    'aws-secretsmanager-access',
    'azure-keyvault-access',
    'psql-invocation',
    'pgpassword-env',
    'mysql-inline-password',
    'mongodb-uri-with-credentials',
    'dotenv-file',
    'private-key-file-extension',
    'ssh-private-key-filename',
    'aws-credentials-file',
    'kube-config-file',
    'kubectl-get-secret',
    'kubectl-secret-base64-decode',
    'aws-access-key-literal',
    'github-token-literal',
    'openai-stripe-style-key-literal',
    'slack-token-literal',
    'google-api-key-literal',
    'pem-private-key-block',
}


class TestBundledRulesLoadCleanly(unittest.TestCase):
    def test_every_expected_id_is_present_and_every_pattern_compiles(self):
        rules = load_rule_files([os.path.join(REPO_ROOT, 'rules', '*.md')])
        loaded_ids = {r.id for r in rules}
        self.assertEqual(loaded_ids, EXPECTED_RULE_IDS)
        for rule in rules:
            re.compile(rule.pattern)  # raises re.error if malformed


def run_guard_with_real_rules(tool_name, tool_input):
    home_dir = tempfile.TemporaryDirectory()
    try:
        env = dict(os.environ)
        env['HOME'] = home_dir.name
        env['CLAUDE_PLUGIN_ROOT'] = REPO_ROOT
        return subprocess.run(
            [sys.executable, GUARD_SCRIPT],
            input=json.dumps({'tool_name': tool_name, 'tool_input': tool_input}),
            capture_output=True,
            text=True,
            cwd=home_dir.name,
            env=env,
        )
    finally:
        home_dir.cleanup()


class TestBundledRulesCoverage(unittest.TestCase):
    def assert_denied(self, tool_name, tool_input):
        result = run_guard_with_real_rules(tool_name, tool_input)
        output = json.loads(result.stdout)
        self.assertEqual(
            output.get('hookSpecificOutput', {}).get('permissionDecision'), 'deny',
            msg=f"expected deny for {tool_name} {tool_input}, got: {result.stdout}",
        )

    def test_gcloud_secret_access_denied(self):
        self.assert_denied('Bash', {'command': 'gcloud secrets versions access latest --secret=foo'})

    def test_psql_denied(self):
        self.assert_denied('Bash', {'command': 'psql "postgres://user:pass@host/db"'})

    def test_kubectl_get_secret_denied(self):
        self.assert_denied('Bash', {'command': 'kubectl get secret my-secret -o yaml'})

    def test_read_dotenv_denied(self):
        self.assert_denied('Read', {'file_path': '/some/project/.env'})

    def test_read_ssh_key_denied(self):
        self.assert_denied('Read', {'file_path': os.path.expanduser('~/.ssh/id_rsa')})

    def test_write_aws_key_shaped_content_denied(self):
        self.assert_denied('Write', {
            'file_path': '/tmp/notes.txt',
            'content': 'key = AKIAABCDEFGHIJKLMNOP',
        })

    def test_harmless_bash_command_allowed(self):
        result = run_guard_with_real_rules('Bash', {'command': 'ls -la'})
        self.assertEqual(result.stdout.strip(), '')

    def test_harmless_read_allowed(self):
        result = run_guard_with_real_rules('Read', {'file_path': '/some/project/README.md'})
        self.assertEqual(result.stdout.strip(), '')


if __name__ == '__main__':
    unittest.main()
```

- [ ] **Step 2: Run to verify it fails**

Run: `python3 -m unittest tests.test_default_rules -v`
Expected: fails — `rules/*.md` files don't exist yet, `EXPECTED_RULE_IDS` won't match an empty set

- [ ] **Step 3: Write the bundled rule files**

`rules/cloud-secrets.md`:
```markdown
---
id: gcloud-secret-access
match_against: [command]
pattern: gcloud\s+secrets\s+versions\s+(access|add)
action: deny
---

⚠️ 此指令會讀取或寫入 Google Secret Manager 的機密值。若確定要執行，請自行在終端機執行。

---
id: gcloud-iam-key-create
match_against: [command]
pattern: gcloud\s+iam\s+service-accounts\s+keys\s+create
action: deny
---

⚠️ 此指令會建立一組新的 GCP 服務帳戶金鑰檔（長期憑證）。請自行在終端機執行。

---
id: aws-secretsmanager-access
match_against: [command]
pattern: aws\s+secretsmanager\s+(get-secret-value|create-secret|put-secret-value)
action: deny
---

⚠️ 此指令會讀取或寫入 AWS Secrets Manager 的機密值。請自行在終端機執行。

---
id: azure-keyvault-access
match_against: [command]
pattern: az\s+keyvault\s+secret\s+show
action: deny
---

⚠️ 此指令會讀取 Azure Key Vault 的機密值。請自行在終端機執行。
```

`rules/db-credentials.md`:
```markdown
---
id: psql-invocation
match_against: [command]
pattern: \bpsql\b
action: deny
---

⚠️ 這是直接連線資料庫的指令，可能暴露連線密碼。請自行在終端機執行。

---
id: pgpassword-env
match_against: [command]
pattern: PGPASSWORD=
action: deny
---

⚠️ 指令中直接帶有資料庫密碼環境變數（PGPASSWORD）。請自行在終端機執行。

---
id: mysql-inline-password
match_against: [command]
pattern: mysql\s+.*-p\S
action: deny
---

⚠️ 指令中直接帶有 MySQL 密碼參數。請自行在終端機執行。

---
id: mongodb-uri-with-credentials
match_against: [command, content]
pattern: mongodb(\+srv)?://[^:/\s]+:[^@/\s]+@
action: deny
---

⚠️ 偵測到 MongoDB 連線字串中直接帶有帳號密碼。
```

`rules/key-files.md`:
```markdown
---
id: dotenv-file
match_against: [command, file_path]
pattern: (^|[/\s"'])\.env(\.[a-zA-Z0-9_-]+)?($|[\s"'])
action: deny
---

⚠️ 這牽涉到 .env 環境變數檔案，可能包含機密值。

---
id: private-key-file-extension
match_against: [file_path]
pattern: \.(pem|pfx|key)$
action: deny
---

⚠️ 這是常見的私鑰/憑證檔案格式（.pem/.pfx/.key）。

---
id: ssh-private-key-filename
match_against: [file_path, command]
pattern: (id_rsa|id_ed25519|id_ecdsa)($|[\s"'])
action: deny
---

⚠️ 這看起來是 SSH 私鑰檔案。

---
id: aws-credentials-file
match_against: [file_path, command]
pattern: \.aws/credentials
action: deny
---

⚠️ 這是 AWS CLI 的機密憑證檔（~/.aws/credentials）。

---
id: kube-config-file
match_against: [file_path, command]
pattern: \.kube/config
action: deny
---

⚠️ 這是 Kubernetes 的 kubeconfig 檔案，通常內嵌叢集存取憑證。
```

`rules/kubernetes.md`:
```markdown
---
id: kubectl-get-secret
match_against: [command]
pattern: kubectl\s+(get|describe)\s+secret
action: deny
---

⚠️ 這會讀取 Kubernetes Secret 的內容。

---
id: kubectl-secret-base64-decode
match_against: [command]
pattern: kubectl\s+get\s+secret.*base64\s+(-d|--decode)
action: deny
---

⚠️ 這個指令會把 Kubernetes Secret 的值解碼成明文。
```

`rules/api-token-patterns.md`:
```markdown
---
id: aws-access-key-literal
match_against: [command, content]
pattern: AKIA[0-9A-Z]{16}
action: deny
---

⚠️ 偵測到文字中出現 AWS Access Key ID 格式的字串。

---
id: github-token-literal
match_against: [command, content]
pattern: gh[ps]_[0-9A-Za-z]{36}
action: deny
---

⚠️ 偵測到文字中出現 GitHub Token 格式的字串（ghp_/ghs_ 開頭）。

---
id: openai-stripe-style-key-literal
match_against: [command, content]
pattern: sk-[A-Za-z0-9]{20,}
action: deny
---

⚠️ 偵測到文字中出現 sk- 開頭的 API Key 格式字串（常見於 OpenAI/Stripe）。

---
id: slack-token-literal
match_against: [command, content]
pattern: xox[baprs]-[0-9A-Za-z-]+
action: deny
---

⚠️ 偵測到文字中出現 Slack Token 格式的字串。

---
id: google-api-key-literal
match_against: [command, content]
pattern: AIza[0-9A-Za-z_-]{35}
action: deny
---

⚠️ 偵測到文字中出現 Google API Key 格式的字串。

---
id: pem-private-key-block
match_against: [command, content]
pattern: -----BEGIN\s?(RSA |EC |OPENSSH )?PRIVATE KEY-----
action: deny
---

⚠️ 偵測到文字中包含 PEM 格式私鑰區塊。
```

- [ ] **Step 4: Run to verify it passes**

Run: `python3 -m unittest tests.test_default_rules -v`
Expected: `OK` (10 tests pass)

- [ ] **Step 5: Run the entire test suite to confirm nothing regressed**

Run: `python3 -m unittest discover -s tests -t . -v`
Expected: `OK` (all tests across all files pass)

- [ ] **Step 6: Commit**

```bash
git add rules tests/test_default_rules.py
git commit -m "feat: add bundled default secret-protection rule pack"
```

---

### Task 12: Setup wizard skill

**Files:**
- Create: `skills/setup-secret-guard/SKILL.md`

- [ ] **Step 1: Write the skill**

`skills/setup-secret-guard/SKILL.md`:
```markdown
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

2. Read the plugin's bundled rule files at `${CLAUDE_PLUGIN_ROOT}/rules/*.md` to see the full default set and each rule's `id`.

3. Create `~/.claude/secret-guard/rules/` if it doesn't exist, then write one `.md` file per category the user confirmed is relevant, copying the matching rules from the bundled set verbatim (same `id`, `match_against`, `pattern`, `action`, and message). Skip categories the user said don't apply to them (e.g. skip `kubernetes.md` entirely if they don't use Kubernetes).

4. For any org-specific pattern the user described, append a new rule block to the most relevant category file (or a new `custom.md` file if none fit), following the same format:
   ```markdown
   ---
   id: <kebab-case-id>
   match_against: [file_path]
   pattern: <the regex the user described>
   action: deny
   ---

   <a short message explaining what this rule caught>
   ```

5. Tell the user which files were written, and that the effect is immediate — no restart needed, since `guard.py` reads the rules directory fresh on every tool call.

## Notes

- Never remove a category the user didn't explicitly say to drop — when in doubt, keep the default (deny-by-default) rather than silently narrowing coverage.
- This skill only tunes the *global* rule set. It does not create or edit any project's `.claude/secret-guard-allow.local.md` allowlist — that's a manual, deliberate action the user takes per-project when a specific repo legitimately needs an exception.
```

- [ ] **Step 2: Commit**

```bash
git add skills/setup-secret-guard/SKILL.md
git commit -m "feat: add setup-secret-guard wizard skill"
```

---

### Task 13: Local install verification and final commit

**Files:** none (manual verification only)

- [ ] **Step 1: Run the full automated test suite one more time**

Run: `python3 -m unittest discover -s tests -t . -v`
Expected: `OK`, all tests pass

- [ ] **Step 2: Load the plugin locally**

Run (from anywhere, e.g. `~/Desktop`):
```bash
claude --plugin-dir /Users/linzhihuan/Desktop/secret-guard
```

- [ ] **Step 3: Verify global scope — a brand-new, never-configured directory is still protected**

Inside that Claude Code session, in a scratch directory you've never used before, ask Claude to run:
```
gcloud secrets versions access latest --secret=test
```
Expected: Claude Code reports the tool call was denied, with the `gcloud-secret-access` rule's message shown.

- [ ] **Step 4: Verify Read coverage**

Create a scratch file named `.env` with any content, then ask Claude to read it.
Expected: denied by the `dotenv-file` rule.

- [ ] **Step 5: Verify Write/content coverage**

Ask Claude to write a new file containing the text `AKIAABCDEFGHIJKLMNOP`.
Expected: denied by the `aws-access-key-literal` rule.

- [ ] **Step 6: Verify the per-project allowlist**

In that scratch project directory, create `.claude/secret-guard-allow.local.md`:
```markdown
---
allow: [gcloud-secret-access]
---
Testing the allowlist mechanism.
```
Ask Claude to run `gcloud secrets versions access latest --secret=test` again in the same directory.
Expected: now allowed (with a systemMessage noting it's allowlisted). Then `cd` to a different, unrelated directory and repeat the same command — expect it denied there, confirming the allowlist is project-scoped and the deny is global by default.

- [ ] **Step 7: Verify fail-open behavior**

Temporarily rename `~/.claude/secret-guard/rules` (if it exists from a previous manual test) or the plugin's own `rules/` directory to break the load path, e.g.:
```bash
mv /Users/linzhihuan/Desktop/secret-guard/rules /Users/linzhihuan/Desktop/secret-guard/rules.bak
```
Ask Claude to run a harmless command. Expected: it's allowed, but with a visible warning that secret-guard didn't run correctly. Then restore:
```bash
mv /Users/linzhihuan/Desktop/secret-guard/rules.bak /Users/linzhihuan/Desktop/secret-guard/rules
```

- [ ] **Step 8: Final commit**

```bash
git add -A
git status
git commit -m "chore: mark secret-guard plugin v0.1.0 locally verified" --allow-empty
```

---

## Explicitly out of scope for this plan

Per the spec: GitHub publishing, marketplace listing, README/LICENSE for distribution, and a PR to `anthropics/claude-code`. Phases B (standalone script) and C (cross-AI-tool CLI) are future work, not part of this plan.
