import { expect, test } from 'claude-code/testing'
import type { Engine } from 'claude-code/testing'
import type { On } from 'claude-code'

const HOME = '/home/tester'
const GLOBAL_DIR = `${HOME}/.claude/secret-guard/rules`
const ALLOWLIST = '.claude/secret-guard-allow.local.md'

const BUNDLED = `---
id: psql-invocation
match_against: [command]
pattern: \\bpsql\\b
action: ask
---

直接連線資料庫。

---
id: ssh-private-key-filename
match_against: [file_path, command]
pattern: (id_rsa|id_ed25519)($|[\\s"'])
action: deny
---

SSH 私鑰檔。

---
id: sketchy
match_against: [command]
pattern: sketchy-thing
action: warn
---

小心一點。

---
id: token-literal
match_against: [command, content]
pattern: tok_[0-9a-z]{8}
action: ask
---

出現 token。
`

type World = {
  bundled?: string
  global?: string
  allowlist?: string
  answers?: string[]
}

// The engine beneath the plugin: a virtual file system, HOME, the ask dialog,
// toasts, and tools that just record that they ran.
const engine = (on: On, world: World) => {
  const asked: string[] = []
  const ran: string[] = []
  const toasts: string[] = []
  const answers = [...(world.answers ?? [])]

  const dirOf = (path: string) => {
    if (path === GLOBAL_DIR) return world.global === undefined ? undefined : { 'custom.md': world.global }
    if (path.endsWith('/rules')) return world.bundled === undefined ? undefined : { 'default.md': world.bundled }
    return undefined
  }
  const fileOf = (path: string) => {
    // the engine hands hooks the path made absolute under the working directory
    if (path === ALLOWLIST || path.endsWith(`/${ALLOWLIST}`)) return world.allowlist
    const cut = path.lastIndexOf('/')
    return dirOf(path.slice(0, cut))?.[path.slice(cut + 1) as 'custom.md']
  }

  on('env.get', (_$, e) => ({ value: e.name === 'HOME' ? HOME : undefined }))
  on('fs.list', (_$, e) => {
    const dir = dirOf(e.path)
    if (!dir) return { deny: `ENOENT ${e.path}` }
    return { value: Object.keys(dir).map(name => ({ name, kind: 'file' as const, size: 1, mtimeMs: 0, isLink: false })) }
  })
  on('fs.exists', (_$, e) => ({ value: fileOf(e.path) !== undefined }))
  on('fs.read', (_$, e) => {
    const text = fileOf(e.path)
    return text === undefined ? { deny: `ENOENT ${e.path}` } : { value: text }
  })
  on('ui.toast', (_$, e) => {
    toasts.push(e.text)
    return { value: undefined }
  })
  on('tool.call', { tool: 'AskUserQuestion' }, (_$, e) => {
    const q = e.questions[0]!.question
    asked.push(q)
    return { result: { questions: e.questions, answers: { [q]: answers.shift() ?? '拒絕' } } }
  })
  on('tool.call', { tool: 'Bash' }, (_$, e) => {
    ran.push(e.command)
    return { result: { stdout: 'ok', stderr: '', interrupted: false } }
  })
  on('tool.call', { tool: 'Read' }, (_$, e) => {
    ran.push(`Read ${e.file_path}`)
    return { result: { type: 'text', file: { filePath: e.file_path, content: '', numLines: 0, startLine: 1, totalLines: 0 } } }
  })
  return { asked, ran, toasts }
}

const bash = ($: Engine, command: string) => $.tool.call({ tool: 'Bash', command })

test('harmless commands run without asking', async ($, on) => {
  const t = engine(on, { bundled: BUNDLED })
  await bash($, 'ls -la')
  expect(t.asked).toEqual([])
  expect(t.ran).toEqual(['ls -la'])
})

test('an ask rule asks, and 拒絕 stops the call', async ($, on) => {
  const t = engine(on, { bundled: BUNDLED, answers: ['拒絕'] })
  const r = await bash($, 'psql -h db')
  expect(t.asked.length).toBe(1)
  expect(t.asked[0]).toContain('psql-invocation')
  expect(t.asked[0]).toContain('直接連線資料庫。')
  expect(t.ran).toEqual([])
  expect(r.deny).toContain('psql-invocation')
})

test('允許這一次 runs it once and asks again next time', async ($, on) => {
  const t = engine(on, { bundled: BUNDLED, answers: ['允許這一次', '拒絕'] })
  await bash($, 'psql -h db')
  await bash($, 'psql -h db')
  expect(t.asked.length).toBe(2)
  expect(t.ran).toEqual(['psql -h db'])
})

test('這個 session 都允許 stops asking for that rule, and /secret-guard reset undoes it', async ($, on) => {
  const t = engine(on, { bundled: BUNDLED, answers: ['這個 session 都允許', '拒絕'] })
  await bash($, 'psql -h a')
  await bash($, 'psql -h b')
  expect(t.asked.length).toBe(1)
  expect(t.ran).toEqual(['psql -h a', 'psql -h b'])

  await $.command.run({
    command: 'secret-guard',
    args: 'reset',
    origin: { kind: 'composer' },
    presentation: { isFullscreen: false, columns: 80 },
  })
  await bash($, 'psql -h c')
  expect(t.asked.length).toBe(2)
  expect(t.ran).toEqual(['psql -h a', 'psql -h b'])
})

test('a session approval of one rule does not cover another', async ($, on) => {
  const t = engine(on, { bundled: BUNDLED, answers: ['這個 session 都允許', '拒絕'] })
  await bash($, 'psql -h a')
  await bash($, 'echo tok_abcd1234')
  expect(t.asked.length).toBe(2)
  expect(t.ran).toEqual(['psql -h a'])
})

test('free text under Other counts as a no', async ($, on) => {
  const t = engine(on, { bundled: BUNDLED, answers: ['let me think'] })
  await bash($, 'psql -h db')
  expect(t.ran).toEqual([])
})

test('a deny rule denies without asking', async ($, on) => {
  const t = engine(on, { bundled: BUNDLED })
  const r = await $.tool.call({ tool: 'Read', file_path: '/Users/me/.ssh/id_rsa' })
  expect(t.asked).toEqual([])
  expect(t.ran).toEqual([])
  expect(r.deny).toContain('ssh-private-key-filename')
})

test('deny wins over ask when both match', async ($, on) => {
  const t = engine(on, { bundled: BUNDLED })
  const r = await bash($, 'psql -f ~/.ssh/id_rsa')
  expect(t.asked).toEqual([])
  expect(r.deny).toContain('ssh-private-key-filename')
})

test('a warn rule runs the call and shows a toast', async ($, on) => {
  const t = engine(on, { bundled: BUNDLED })
  await bash($, 'sketchy-thing now')
  expect(t.ran).toEqual(['sketchy-thing now'])
  expect(t.toasts.join('\n')).toContain('小心一點。')
})

test('the project allowlist lets even a deny rule through', async ($, on) => {
  const t = engine(on, { bundled: BUNDLED, allowlist: '---\nallow: [ssh-private-key-filename, psql-invocation]\n---\n' })
  await $.tool.call({ tool: 'Read', file_path: '/Users/me/.ssh/id_rsa' })
  await bash($, 'psql -h db')
  expect(t.asked).toEqual([])
  expect(t.ran).toEqual(['Read /Users/me/.ssh/id_rsa', 'psql -h db'])
})

test('~/.claude/secret-guard/rules replaces the bundled rules', async ($, on) => {
  const custom = '---\nid: only-rule\nmatch_against: [command]\npattern: deploy-prod\naction: deny\n---\n\n不准部署。\n'
  const t = engine(on, { bundled: BUNDLED, global: custom })
  await bash($, 'psql -h db')
  const r = await bash($, 'deploy-prod')
  expect(t.asked).toEqual([])
  expect(t.ran).toEqual(['psql -h db'])
  expect(r.deny).toContain('不准部署。')
})

test('missing rule files fail open with a toast', async ($, on) => {
  const t = engine(on, {})
  await bash($, 'psql -h db')
  expect(t.ran).toEqual(['psql -h db'])
  expect(t.toasts.join('\n')).toContain('規則載入失敗')
})
