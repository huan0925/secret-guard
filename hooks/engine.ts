// Rule-file parser and matching engine, ported from v0.1's Python hook so
// rules/*.md keep their meaning. Pure functions only; register.ts does the I/O.

export type Action = 'deny' | 'ask' | 'warn'

export type Rule = {
  id: string
  matchAgainst: string[]
  pattern: string
  action: string
  message: string
  source: string
}

export type Verdict = {
  action: Action | 'allow'
  // The rules behind `action` (empty for a plain allow).
  rules: Rule[]
  // Rules that matched but the project allowlist or a session approval let through.
  allowed: Rule[]
}

const LIST_FIELDS = new Set(['match_against', 'allow'])

const unquote = (s: string) => s.replace(/^["']+|["']+$/g, '')

// Flat `key: value` lines; `match_against` and `allow` take `[a, b]` lists.
export const parseFrontmatter = (lines: string[]): Record<string, string | string[]> => {
  const out: Record<string, string | string[]> = {}
  for (const line of lines) {
    const stripped = line.trim()
    if (!stripped || stripped.startsWith('#')) continue
    const colon = stripped.indexOf(':')
    if (colon < 0) continue
    const key = stripped.slice(0, colon).trim()
    const value = stripped.slice(colon + 1).trim()

    if (LIST_FIELDS.has(key)) {
      const inner = value.replace(/^\[+|\]+$/g, '').trim()
      out[key] = inner ? inner.split(',').map(item => unquote(item.trim())) : []
    } else {
      out[key] = unquote(value)
    }
  }
  return out
}

// Back-to-back `---` blocks: one rule's closing marker opens the next one.
export const parseRuleFile = (text: string): Array<[Record<string, string | string[]>, string]> => {
  const lines = text.split('\n')
  const markers = lines.flatMap((line, i) => (line.trim() === '---' ? [i] : []))

  const blocks: Array<[Record<string, string | string[]>, string]> = []
  for (let k = 0; k + 1 < markers.length; k += 2) {
    const open = markers[k]!
    const close = markers[k + 1]!
    const bodyEnd = k + 2 < markers.length ? markers[k + 2]! : lines.length
    blocks.push([parseFrontmatter(lines.slice(open + 1, close)), lines.slice(close + 1, bodyEnd).join('\n').trim()])
  }
  return blocks
}

const asList = (v: string | string[] | undefined) => (Array.isArray(v) ? v : [])
const asText = (v: string | string[] | undefined) => (typeof v === 'string' ? v : undefined)

export const rulesFromText = (text: string, source: string): Rule[] =>
  parseRuleFile(text).flatMap(([fm, body]) => {
    const id = asText(fm.id)
    const pattern = asText(fm.pattern)
    if (!id || !pattern) return []
    return [{ id, matchAgainst: asList(fm.match_against), pattern, action: asText(fm.action) ?? 'deny', message: body, source }]
  })

export const allowlistFromText = (text: string): Set<string> =>
  new Set(parseRuleFile(text).flatMap(([fm]) => asList(fm.allow)))

type Args = Record<string, unknown>

const str = (v: unknown) => (typeof v === 'string' ? v : '')

// The strings a rule checks, per its match_against. Beyond v0.1: NotebookEdit
// counts as a file write and Grep's `path` and `glob` as a file read.
export const candidates = (rule: Rule, tool: string, args: Args): string[] => {
  const out: string[] = []
  for (const field of rule.matchAgainst) {
    if (field === 'command' && tool === 'Bash') out.push(str(args.command))
    // `tool` checks the tool's own name, for tools (MCP ones) that hand back secrets.
    else if (field === 'tool') out.push(tool)
    else if (field === 'file_path') {
      if (['Read', 'Edit', 'Write', 'MultiEdit'].includes(tool)) out.push(str(args.file_path))
      else if (tool === 'NotebookEdit') out.push(str(args.notebook_path))
      else if (tool === 'Grep') out.push(str(args.path), str(args.glob))
    } else if (field === 'content') {
      if (tool === 'Write') out.push(str(args.content))
      else if (tool === 'Edit') out.push(str(args.new_string))
      else if (tool === 'MultiEdit') {
        const edits = Array.isArray(args.edits) ? args.edits : []
        out.push(edits.map(one => str((one as Args | null)?.new_string)).join(' '))
      } else if (tool === 'NotebookEdit') out.push(str(args.new_source))
    }
  }
  return out.filter(Boolean)
}

const compiled = new Map<string, RegExp | null>()

// Case-insensitive, as in v0.1. A pattern JS cannot compile (Python-only
// syntax such as `(?P<name>...)`) never matches.
const regexOf = (pattern: string): RegExp | null => {
  if (!compiled.has(pattern)) {
    let re: RegExp | null = null
    try {
      re = new RegExp(pattern, 'i')
    } catch {
      re = null
    }
    compiled.set(pattern, re)
  }
  return compiled.get(pattern)!
}

export const ruleMatches = (rule: Rule, tool: string, args: Args): boolean => {
  const found = candidates(rule, tool, args)
  const re = found.length > 0 ? regexOf(rule.pattern) : null
  return re !== null && found.some(c => re.test(c))
}

export type Hit = {
  // The text the pattern matched.
  matched: string
  // The whole line around it, with the match wrapped in 【】.
  line: string
}

const LINE_LIMIT = 240

const squash = (s: string) => s.replace(/\s+/g, ' ')

// What a rule matched and the line around it, so whoever is asked can see what
// the call would touch and, from the rest of the line, where the output goes.
export const hitOf = (rule: Rule, tool: string, args: Args): Hit | undefined => {
  const re = regexOf(rule.pattern)
  if (!re) return undefined

  for (const text of candidates(rule, tool, args)) {
    const m = re.exec(text)
    if (!m) continue

    const matchEnd = m.index + m[0].length
    const lineStart = text.lastIndexOf('\n', m.index - 1) + 1
    const nextBreak = text.indexOf('\n', matchEnd)
    const lineEnd = nextBreak < 0 ? text.length : nextBreak

    // A long line keeps the match and what follows it, which says where the output goes.
    const from = Math.max(lineStart, Math.min(m.index - 60, lineEnd - LINE_LIMIT))
    const to = Math.min(lineEnd, Math.max(from + LINE_LIMIT, matchEnd))
    const before = squash(text.slice(from, m.index))
    const matched = squash(m[0])
    const after = squash(text.slice(matchEnd, to))
    const marked = matched.trim() ? `${before}【${matched}】${after}` : `${before}${after}`

    return {
      matched: matched.trim(),
      line: `${from > lineStart ? '…' : ''}${marked.trim()}${to < lineEnd ? '…' : ''}`,
    }
  }
  return undefined
}

// deny > ask > warn > allow. The project allowlist lets any rule through;
// a session approval only lets an `ask` rule through, since that is all it answered.
export const evaluate = (
  tool: string,
  args: Args,
  rules: Rule[],
  allowlist: ReadonlySet<string>,
  sessionAllowed: ReadonlySet<string> = new Set(),
): Verdict => {
  const hit: Record<Action, Rule[]> = { deny: [], ask: [], warn: [] }
  const allowed: Rule[] = []

  for (const rule of rules) {
    if (!ruleMatches(rule, tool, args)) continue
    const action: Action = rule.action === 'warn' || rule.action === 'ask' ? rule.action : 'deny'
    if (allowlist.has(rule.id) || (action === 'ask' && sessionAllowed.has(rule.id))) allowed.push(rule)
    else hit[action].push(rule)
  }

  for (const action of ['deny', 'ask', 'warn'] as const) {
    if (hit[action].length > 0) return { action, rules: hit[action], allowed }
  }
  return { action: 'allow', rules: [], allowed }
}
