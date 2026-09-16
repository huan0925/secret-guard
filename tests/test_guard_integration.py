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
