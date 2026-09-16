import os
import sys
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from lib.frontmatter import parse_frontmatter_dict


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
