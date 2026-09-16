"""Rule matching engine for secret-guard."""

import glob
import os
import re
from dataclasses import dataclass, field
from typing import List

from lib.frontmatter import parse_rule_file


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


def rule_matches(rule, tool_name, tool_input):
    """Check if a rule's pattern matches any candidate from tool_input."""
    candidates = extract_candidates(rule, tool_name, tool_input)
    if not candidates:
        return False
    try:
        # Case-insensitive matching errs toward over-matching; safer for deny-by-default guards.
        regex = re.compile(rule.pattern, re.IGNORECASE)
    except re.error:
        return False
    return any(regex.search(candidate) for candidate in candidates)


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
