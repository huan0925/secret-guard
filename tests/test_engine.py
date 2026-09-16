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
