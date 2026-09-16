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
