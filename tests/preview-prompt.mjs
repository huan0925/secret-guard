// Prints the reasons block the ask / deny prompt would show for a few realistic calls.
//   node --experimental-strip-types tests/preview-prompt.mjs
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const { rulesFromText, evaluate, hitOf } = await import(`${root}/hooks/engine.ts`)

const rules = fs
  .readdirSync(`${root}/rules`)
  .filter(name => name.endsWith('.md'))
  .flatMap(name => rulesFromText(fs.readFileSync(`${root}/rules/${name}`, 'utf8'), name))

const samples = [
  ['Bash', { command: 'P=my-project\na=$(gcloud secrets versions access 2 --secret=DB_PASSWORD --project $P | shasum -a 256 | cut -c1-12)\necho "$a"' }],
  ['Bash', { command: 'gcloud secrets versions access latest --secret=DB_PASSWORD --project my-project' }],
  ['Bash', { command: 'ls database/migrations && ls app/Models && grep -E "^DB_" .env' }],
  ['Bash', { command: 'S=/private/tmp/claude-501/some/very/long/scratchpad/path/that/pushes/the/real/command/far/to/the/right/of/the/line/and/used/to/hide/it/completely/in/the/old/preview; mkdir -p $S; cd ~/code/app; set -a && source .env && set +a && php artisan migrate --pretend' }],
  ['Bash', { command: "bash -c 'T=$(gcloud auth print-access-token); curl -s -H \"Authorization: Bearer $T\" https://asia-east1-docker.pkg.dev/v2/x/manifests/latest | jq .config'" }],
  ['Read', { file_path: '/Users/x/proj/storage/oauth-private.key' }],
  ['mcp__claude_ai_Neon__get_connection_string', { project_id: 'my-project-id' }],
]

for (const [tool, args] of samples) {
  const verdict = evaluate(tool, args, rules, new Set())
  console.log(`\n── ${tool}（${verdict.action}）`)
  for (const rule of verdict.rules) {
    const hit = hitOf(rule, tool, args)
    console.log(`• ${rule.message || rule.id}（規則：${rule.id}）`)
    if (hit) console.log(`  碰到的部分：${hit.line}`)
  }
}
