import { atom, read, update } from 'claude-code'
import type { EngineInterface, Register, ToolCallInput } from 'claude-code'

import { allowlistFromText, evaluate, hitOf, rulesFromText } from './engine'
import type { Rule } from './engine'

const ALLOWLIST_FILE = '.claude/secret-guard-allow.local.md'

const ALLOW_ONCE = '允許這一次'
const ALLOW_SESSION = '這個 session 都允許'
const DENY = '拒絕'

// `ask` rules the user approved for the rest of this session.
const sessionAllowed = atom({ plugin: 'secret-guard', key: 'sessionAllowed' } as const, [])

const mdFiles = async ($: EngineInterface, dir: string): Promise<string[]> => {
  const entries = await $.fs.list(dir).catch(() => [])
  return entries
    .filter(one => one.name.endsWith('.md') && (one.kind === 'file' || one.isLink))
    .map(one => `${dir}/${one.name}`)
    .sort()
}

// ~/.claude/secret-guard/rules/ wins when it has any .md file,
// else the plugin's own rules/. Read fresh on every call, so edits apply at once.
const loadRules = async ($: EngineInterface): Promise<Rule[]> => {
  const home = await $.env.get('HOME')
  const globalFiles = home ? await mdFiles($, `${home}/.claude/secret-guard/rules`) : []
  const files = globalFiles.length > 0 ? globalFiles : await mdFiles($, `${$.plugin.root}/rules`)
  if (files.length === 0) throw new Error(`no rule files in ${$.plugin.root}/rules`)

  const texts = await Promise.all(files.map(file => $.fs.read(file)))
  return texts.flatMap((text, i) => rulesFromText(text, files[i]!))
}

const loadAllowlist = async ($: EngineInterface): Promise<Set<string>> => {
  const isThere = await $.fs.exists(ALLOWLIST_FILE)
  return isThere ? allowlistFromText(await $.fs.read(ALLOWLIST_FILE)) : new Set()
}

const messages = (rules: Rule[]) => rules.map(r => r.message || r.id).join('\n')

// Per rule: why it fired and the exact part of the call that set it off.
const reasons = (e: ToolCallInput, rules: Rule[]) =>
  rules
    .map(rule => {
      const hit = hitOf(rule, e.tool, e as unknown as Record<string, unknown>)
      const why = `• ${rule.message || rule.id}（規則：${rule.id}）`
      return hit ? `${why}\n  碰到的部分：${hit.line}` : why
    })
    .join('\n')

const LEGEND = '【】標出觸發規則的文字；同一行後面接的指令就是結果的去向。'

// Returns a deny reason, or undefined to let the call run.
const decide = async ($: EngineInterface, e: ToolCallInput): Promise<string | undefined> => {
  let rules: Rule[]
  try {
    rules = await loadRules($)
  } catch (err) {
    // Fail open with a loud warning: a guard that blocks
    // everything when its rule files break just gets uninstalled.
    $.ui.toast(`secret-guard 規則載入失敗，這次先放行：${String(err)}`)
    return undefined
  }

  const approved = new Set(await read($, sessionAllowed))
  const verdict = evaluate(e.tool, e as unknown as Record<string, unknown>, rules, await loadAllowlist($), approved)
  const ids = verdict.rules.map(r => r.id)

  if (verdict.action === 'allow') return undefined

  if (verdict.action === 'warn') {
    $.ui.toast(`secret-guard 提醒：${messages(verdict.rules)}`)
    return undefined
  }

  if (verdict.action === 'deny') {
    return `🛑 secret-guard 擋下這個 ${e.tool} 呼叫：\n${reasons(e, verdict.rules)}\n${LEGEND}\n這條規則設定為一律拒絕，不要換個方式繞過；需要的話請使用者自己在終端機執行。`
  }

  const question = `secret-guard 攔下一個 ${e.tool} 呼叫，放行前請確認。\n\n為什麼攔：\n${reasons(e, verdict.rules)}\n\n${LEGEND}\n要放行嗎？`
  // Dismissed, or nobody to ask (`claude -p`): counts as a no.
  const answer = await $.ui
    .ask(question, { header: '機密保護', options: [ALLOW_ONCE, ALLOW_SESSION, DENY] })
    .catch(() => DENY)

  if (answer === ALLOW_SESSION) {
    await update($, sessionAllowed, list => [...new Set([...list, ...ids])])
    return undefined
  }
  if (answer === ALLOW_ONCE) return undefined

  return `🛑 secret-guard：使用者沒有放行這個操作（${ids.join(', ')}）。不要換個方式繞過；需要的話請使用者自己在終端機執行。`
}

export const register: Register = on => {
  on('session.start', async ($, e, next) => {
    await $.command.register({
      name: 'secret-guard',
      description: '列出這個 session 放行的機密規則；加 reset 清除',
    })
    return next(e)
  })

  on('command.run', { command: 'secret-guard' }, async ($, e) => {
    if (e.args.trim() === 'reset') {
      await update($, sessionAllowed, () => [])
      return { text: '已清除這個 session 放行的機密規則。' }
    }
    const list = await read($, sessionAllowed)
    return {
      text: list.length === 0 ? '這個 session 沒有放行任何機密規則。' : `這個 session 已放行：${list.join(', ')}`,
    }
  })

  // Anything unexpected while deciding denies: a gating hook that throws is
  // skipped by the engine, which would let the call through unchecked.
  on('tool.call', ($, e, next) =>
    decide($, e)
      .then(deny => (deny === undefined ? next(e) : { deny }))
      .catch(err => ({ deny: `🛑 secret-guard 檢查出錯，先擋下：${String(err)}` })),
  )
}
