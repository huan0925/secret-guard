"""The mod (hooks/engine.ts) and this Python engine must judge the same calls
the same way, since they share rules/. Runs the TypeScript engine through Node's
type stripping; skipped when that Node isn't available.

Every case is a made-up string: nothing here reads a real file's contents.
Token-shaped values are assembled at run time so this file itself never holds
one (the guard checks written content for them).
"""

import json
import os
import shutil
import subprocess
import sys
import tempfile
import unittest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RULES_DIR = os.path.join(REPO_ROOT, 'rules')
JUDGE = os.path.join(REPO_ROOT, 'tests', 'parity_judge.ts')

sys.path.insert(0, REPO_ROOT)
from lib.engine import evaluate, load_rule_files

AWS = 'AKIA' + 'ABCDEFGHIJKLMNOP'
GITHUB = 'ghp' + '_' + 'a' * 36
SK = 'sk' + '-' + 'a' * 24
GOOGLE = 'AIza' + 'b' * 35
SLACK = 'xox' + 'b-123-abc'
MONGO = 'mongodb+srv' + '://u:p' + '@h/db'
PEM = '-----BEGIN RSA ' + 'PRIVATE KEY-----'

COMMANDS = [
    'ls -la', 'npm run envtest', 'cat environment.ts', 'git log --keyring',
    'cat .env', 'cat .env.local', 'grep KEY .env', 'echo psql',
    'PGPASSWORD=x pg_dump', 'mysql -u root -psecret', f'mongosh {MONGO}',
    'gcloud secrets versions access latest --secret=x',
    'gcloud secrets create a --data-file=f', 'python3 x.py --data-file=d',
    'gcloud iam service-accounts keys create k.json',
    'aws secretsmanager get-secret-value --secret-id x',
    'az keyvault secret show -n x', 'gcloud run services describe s',
    'kubectl get secret s -o yaml',
    'kubectl get secret s -o jsonpath={.data.x} | base64 -d',
    'cat ~/.ssh/id_rsa', 'cat server.pem', 'cat ~/.aws/credentials',
    'cat ~/.kube/config', f'echo {AWS}', f'echo {GITHUB}', f'echo {SK}',
    f'echo {SLACK}', f'echo {GOOGLE}', 'PSQL -h db',
]
READ_PATHS = [
    '/p/.env', '/p/.env.production', '/p/.envrc', '/p/README.md',
    '/home/u/.ssh/id_ed25519', '/p/cert.pfx', '/p/key.pem.bak',
]
WRITE_CONTENTS = [f'k={AWS}', PEM, f'url={MONGO}', 'hello']

CASES = (
    [['Bash', {'command': c}] for c in COMMANDS]
    + [['Read', {'file_path': p}] for p in READ_PATHS]
    + [['Write', {'file_path': '/tmp/a.txt', 'content': c}] for c in WRITE_CONTENTS]
    + [
        ['Edit', {'file_path': '/tmp/a', 'old_string': 'x', 'new_string': f'tok {GITHUB}'}],
        ['MultiEdit', {'file_path': '/p/.env', 'edits': [{'old_string': 'a', 'new_string': 'b'}]}],
    ]
)


def node_can_strip_types():
    node = shutil.which('node')
    if not node:
        return False
    probe = subprocess.run(
        [node, '--experimental-strip-types', '--no-warnings', '-e', '0'],
        capture_output=True,
    )
    return probe.returncode == 0


@unittest.skipUnless(node_can_strip_types(), 'needs Node with --experimental-strip-types (22.6+)')
class TestParityWithMod(unittest.TestCase):
    def test_both_engines_agree_on_every_case(self):
        rules = load_rule_files([os.path.join(RULES_DIR, '*.md')])
        expected = []
        for tool, args in CASES:
            result = evaluate(tool, args, rules, set())
            expected.append([result['action'], result['matched_ids']])

        with tempfile.NamedTemporaryFile('w', suffix='.json', delete=False) as f:
            json.dump(CASES, f)
            cases_file = f.name
        try:
            run = subprocess.run(
                ['node', '--experimental-strip-types', '--no-warnings', JUDGE, RULES_DIR, cases_file],
                capture_output=True, text=True, check=True,
            )
        finally:
            os.unlink(cases_file)

        actual = json.loads(run.stdout)
        for (tool, args), py, ts in zip(CASES, expected, actual):
            with self.subTest(tool=tool, args=args):
                self.assertEqual(ts, py)
        self.assertEqual(len(actual), len(CASES))

    def test_the_cases_exercise_every_action(self):
        rules = load_rule_files([os.path.join(RULES_DIR, '*.md')])
        actions = {evaluate(tool, args, rules, set())['action'] for tool, args in CASES}
        self.assertEqual(actions, {'allow', 'ask', 'deny'})


if __name__ == '__main__':
    unittest.main()
