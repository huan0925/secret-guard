// Helper for test_parity_with_mod.py: runs the mod's engine (hooks/engine.ts)
// over the same rules and cases, printing [action, matched ids] per case.
// Run with: node --experimental-strip-types parity_judge.ts <rules dir> <cases.json>
import { readFileSync, readdirSync } from 'node:fs'

import { evaluate, rulesFromText } from '../../hooks/engine.ts'

const [rulesDir, casesFile] = process.argv.slice(2) as [string, string]
const rules = readdirSync(rulesDir)
  .filter(name => name.endsWith('.md'))
  .sort()
  .flatMap(name => rulesFromText(readFileSync(`${rulesDir}/${name}`, 'utf8'), name))
const cases: Array<[string, Record<string, unknown>]> = JSON.parse(readFileSync(casesFile, 'utf8'))

console.log(JSON.stringify(cases.map(([tool, args]) => {
  const verdict = evaluate(tool, args, rules, new Set())
  return [verdict.action, verdict.rules.map(r => r.id)]
})))
