"""Rule matching engine for secret-guard."""

import re
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


def rule_matches(rule, tool_name, tool_input):
    """Check if a rule's pattern matches any candidate from tool_input."""
    candidates = extract_candidates(rule, tool_name, tool_input)
    if not candidates:
        return False
    try:
        regex = re.compile(rule.pattern, re.IGNORECASE)
    except re.error:
        return False
    return any(regex.search(candidate) for candidate in candidates)
