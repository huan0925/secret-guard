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


if __name__ == '__main__':
    unittest.main()
