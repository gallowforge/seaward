import { describe, expect, it } from 'vitest'
import index from '../../samples/index.json'
import { readIndex } from './samples'

describe('the list of samples', () => {
  it('reads the list in the repository whole, with the default sample first', () => {
    const list = readIndex(index)
    expect(list.length).toBe((index as unknown[]).length)
    expect(list[0]).toMatchObject({ id: 'shop-1', file: 'shop-1.snapshot' })
    for (const s of list) {
      expect(s.title).not.toBe('')
      expect(s.description).not.toBe('')
    }
  })

  it('keeps only entries it can fetch from beside the page', () => {
    const ok = { id: 'a-1', file: 'a-1.snapshot', title: 'A', description: 'One.' }
    expect(readIndex([ok])).toEqual([ok])
    expect(readIndex({ samples: [ok] })).toEqual([ok])
    // a file name is a name: no folders, no other host
    for (const file of ['../a.snapshot', 'x/a.snapshot', 'https://example.com/a.snapshot', '//example.com/a', '.hidden', '', 'a b.snapshot', 'a?x=1']) {
      expect(readIndex([{ ...ok, file }])).toEqual([])
    }
    for (const id of ['', 'A-1', 'a 1', '-a', 'a"><i>']) expect(readIndex([{ ...ok, id }])).toEqual([])
    expect(readIndex([ok, { ...ok, title: 'again' }])).toEqual([ok])
    expect(readIndex([{ id: 'b', file: 'b.snapshot' }])).toEqual([{ id: 'b', file: 'b.snapshot', title: 'b', description: '' }])
    for (const junk of [null, undefined, 'x', 7, {}, [null, 3, 'x']]) expect(readIndex(junk)).toEqual([])
  })
})
