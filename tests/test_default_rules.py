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
    'gcloud-run-describe',
    'data-file-flag',
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

    def test_bash_cat_of_pem_file_denied(self):
        self.assert_denied('Bash', {'command': 'cat ~/.ssh/server.pem'})

    def test_gcloud_run_describe_denied(self):
        self.assert_denied('Bash', {'command': 'gcloud run services describe my-service'})

    def test_data_file_flag_denied(self):
        self.assert_denied('Bash', {'command': 'gcloud secrets create foo --data-file=secret.txt'})

    def test_data_file_flag_without_gcloud_is_not_denied(self):
        result = run_guard_with_real_rules('Bash', {'command': 'python3 train_model.py --data-file=dataset.csv'})
        self.assertEqual(result.stdout.strip(), '')

    def test_harmless_bash_command_allowed(self):
        result = run_guard_with_real_rules('Bash', {'command': 'ls -la'})
        self.assertEqual(result.stdout.strip(), '')

    def test_harmless_read_allowed(self):
        result = run_guard_with_real_rules('Read', {'file_path': '/some/project/README.md'})
        self.assertEqual(result.stdout.strip(), '')


if __name__ == '__main__':
    unittest.main()
