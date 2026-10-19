import { describe, expect, test } from 'claude-code/testing'

import { allowlistFromText, candidates, evaluate, parseRuleFile, rulesFromText } from './engine'
import type { Rule } from './engine'

// Carried over from v0.1's Python tests, so the port keeps the rules' meaning.

const rule = (matchAgainst: string[], pattern = 'x', action = 'deny', id = 'r1'): Rule => ({
  id, matchAgainst, pattern, action, message: '', source: 't',
})

describe('parseRuleFile', () => {
  test('back-to-back blocks share their marker', () => {
    const blocks = parseRuleFile('---\nid: a\npattern: p\n---\nbody a\n\n---\nid: b\npattern: q\n---\nbody b\n')
    expect(blocks.map(([fm, body]) => [fm.id, body])).toEqual([['a', 'body a'], ['b', 'body b']])
  })

  test('list fields parse as lists, everything else stays a string', () => {
    const [[fm]] = parseRuleFile('---\nmatch_against: [command, "file_path"]\npattern: [a-z]+\n---\n') as [[Record<string, unknown>, string]]
    expect(fm.match_against).toEqual(['command', 'file_path'])
    expect(fm.pattern).toBe('[a-z]+')
  })

  test('comments and lines without a colon are ignored', () => {
    const [[fm]] = parseRuleFile('---\n# note\nnonsense\nid: a\n---\n') as [[Record<string, unknown>, string]]
    expect(fm).toEqual({ id: 'a' })
  })

  test('an unpaired marker yields no rule', () => {
    expect(parseRuleFile('---\nid: a\n')).toEqual([])
  })

  test('blocks missing id or pattern are skipped, action defaults to deny', () => {
    const rules = rulesFromText('---\nid: a\n---\n\n---\nid: b\npattern: p\n---\nmsg\n', 'f.md')
    expect(rules.map(r => [r.id, r.action, r.message])).toEqual([['b', 'deny', 'msg']])
  })

  test('allowlist collects every allow list', () => {
    expect([...allowlistFromText('---\nallow: [a, b]\n---\nwhy\n')]).toEqual(['a', 'b'])
  })
})

describe('candidates', () => {
  test('command only for Bash', () => {
    expect(candidates(rule(['command']), 'Bash', { command: 'ls' })).toEqual(['ls'])
    expect(candidates(rule(['command']), 'Read', { command: 'ls' })).toEqual([])
  })

  test('content for Write, Edit, MultiEdit and NotebookEdit, never Read', () => {
    const r = rule(['content'])
    expect(candidates(r, 'Write', { content: 'a' })).toEqual(['a'])
    expect(candidates(r, 'Edit', { new_string: 'b' })).toEqual(['b'])
    expect(candidates(r, 'MultiEdit', { edits: [{ new_string: 'c' }, { new_string: 'd' }] })).toEqual(['c d'])
    expect(candidates(r, 'NotebookEdit', { new_source: 'e' })).toEqual(['e'])
    expect(candidates(r, 'Read', { file_path: 'f' })).toEqual([])
  })

  test('file_path covers NotebookEdit and Grep too', () => {
    const r = rule(['file_path'])
    expect(candidates(r, 'NotebookEdit', { notebook_path: 'n.ipynb' })).toEqual(['n.ipynb'])
    expect(candidates(r, 'Grep', { path: '.env', pattern: 'KEY' })).toEqual(['.env'])
  })
})

describe('evaluate', () => {
  test('matching is case-insensitive', () => {
    expect(evaluate('Bash', { command: 'PSQL' }, [rule(['command'], 'psql')], new Set()).action).toBe('deny')
  })

  test('a pattern JS cannot compile never matches', () => {
    expect(evaluate('Bash', { command: 'x' }, [rule(['command'], '(?P<n>x)')], new Set()).action).toBe('allow')
  })

  test('deny > ask > warn', () => {
    const d = rule(['command'], 'foo', 'deny', 'd')
    const a = rule(['command'], 'foo', 'ask', 'a')
    const w = rule(['command'], 'foo', 'warn', 'w')
    expect(evaluate('Bash', { command: 'foo' }, [w, a, d], new Set()).action).toBe('deny')
    expect(evaluate('Bash', { command: 'foo' }, [w, a], new Set()).rules.map(r => r.id)).toEqual(['a'])
  })

  test('an unknown action is treated as deny', () => {
    expect(evaluate('Bash', { command: 'foo' }, [rule(['command'], 'foo', 'block')], new Set()).action).toBe('deny')
  })

  test('the allowlist lets any rule through, a session approval only an ask rule', () => {
    const d = rule(['command'], 'foo', 'deny', 'd')
    const a = rule(['command'], 'foo', 'ask', 'a')
    expect(evaluate('Bash', { command: 'foo' }, [d], new Set(['d'])).action).toBe('allow')
    expect(evaluate('Bash', { command: 'foo' }, [d], new Set(), new Set(['d'])).action).toBe('deny')
    expect(evaluate('Bash', { command: 'foo' }, [a], new Set(), new Set(['a'])).action).toBe('allow')
  })
})
