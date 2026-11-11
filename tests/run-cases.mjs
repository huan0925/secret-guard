// Runs tests/rule-cases.json against the bundled rules.
//   node --experimental-strip-types tests/run-cases.mjs
// Each case: [expect, description, tool, args]
//   block — must hit a rule (deny / ask / warn)
//   allow — must not hit any rule
//   limit — a known gap text matching cannot close; reported, never fails the run
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..')
const { rulesFromText, evaluate } = await import(`${root}/hooks/engine.ts`)

const rules = fs
  .readdirSync(`${root}/rules`)
  .filter(name => name.endsWith('.md'))
  .flatMap(name => rulesFromText(fs.readFileSync(`${root}/rules/${name}`, 'utf8'), name))

const cases = JSON.parse(fs.readFileSync(`${root}/tests/rule-cases.json`, 'utf8'))
const count = { ok: 0, missed: 0, falsePositive: 0, limit: 0 }

for (const [expect, description, tool, args] of cases) {
  const verdict = evaluate(tool, args, rules, new Set())
  const got = verdict.action === 'allow' ? 'allow' : 'block'
  const hit = verdict.rules.map(rule => rule.id).join(',')

  let tag = '  ok '
  if (expect === 'limit') {
    count.limit++
    tag = got === 'block' ? 'FIXED' : 'limit'
  } else if (got === expect) count.ok++
  else if (expect === 'block') {
    count.missed++
    tag = 'MISS '
  } else {
    count.falsePositive++
    tag = 'FALSE'
  }
  console.log(tag, `[${verdict.action}${hit ? `:${hit}` : ''}]`.padEnd(38), description)
}

console.log({ rules: rules.length, ...count, total: cases.length })
process.exit(count.missed + count.falsePositive > 0 ? 1 : 0)
