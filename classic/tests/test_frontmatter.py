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


if __name__ == '__main__':
    unittest.main()
