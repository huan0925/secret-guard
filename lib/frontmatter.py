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
