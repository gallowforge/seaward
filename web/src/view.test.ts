import { describe, expect, it } from 'vitest'
import { noInterface } from './testdata/cases'
import shop from './testdata/shop-1.report.json'
import type { Cell, Report } from './types'
import { classWords, contradicts, endOf, lanes, packetGroups, passage, portId, readAnswer, sentences, stepRows } from './view'

// The report the engine writes for samples/shop-1.snapshot, unchanged.
const report = shop as unknown as Report
const INTERNET = 0
const LAN = 1
const by = (id: string, vantage = INTERNET) => {
  const l = lanes(report, vantage).find((x) => x.id === id)
  if (!l) throw new Error(`no lane ${id}`)
  return l
}

describe('the chart of shop-1', () => {
  it('has one lane for every port, in the order of the report', () => {
    const rows = lanes(report, INTERNET)
    expect(rows.map((l) => l.id)).toEqual(report.ports.map(portId))
    expect(rows.map((l) => l.id)).toEqual(['tcp-5432', 'tcp-6379', 'tcp-8081', 'tcp-22', 'tcp-80', 'tcp-443', 'tcp-9100', 'tcp-8443', 'tcp-111', 'udp-111', 'tcp-53', 'udp-53', 'tcp-8125'])
    expect(new Set(rows.map((l) => l.id)).size).toBe(rows.length)
  })

  it('makes the exposed ports loud and no others', () => {
    const loud = lanes(report, INTERNET).filter((l) => l.loud)
    expect(loud.map((l) => l.id)).toEqual(['tcp-5432', 'tcp-6379', 'tcp-8081'])
    expect(loud.length).toBe(report.counts.exposed)
    for (const l of loud) {
      // through the shoreline where ufw's own list has a wall
      expect([l.sea, l.shore, l.land, l.berth, l.breach], l.id).toEqual(['through', 'wall', 'through', 'answers', true])
      expect(l.remark).toBe(true)
    }
  })

  it('draws each kind of lane as the report has it', () => {
    // allowed and reachable: a gate in the shoreline, through to the service
    expect(by('tcp-22')).toMatchObject({ sea: 'through', shore: 'gate', land: 'through', berth: 'answers', loud: false, breach: false, remark: false })
    // let through, nothing listening: an empty berth, and the title is worth showing
    expect(by('tcp-8443')).toMatchObject({ sea: 'through', shore: 'gate', land: 'through', berth: 'empty', remark: true })
    // stopped: the lane ends at the shoreline
    expect(by('tcp-111')).toMatchObject({ sea: 'stopped', shore: 'wall', land: 'none', berth: 'answers' })
    // bound to the machine itself: never touches the water
    expect(by('tcp-53')).toMatchObject({ sea: 'none', land: 'stub', berth: 'answers' })
  })

  it('draws a lane as it is seen from the chosen place', () => {
    // node_exporter is open to one network on the internet side, and stopped from the LAN
    expect(by('tcp-9100', INTERNET)).toMatchObject({ sea: 'some', shore: 'part', land: 'through' })
    expect(by('tcp-9100', INTERNET).view?.note).toBe('198.51.100.0/24 only')
    expect(by('tcp-9100', LAN)).toMatchObject({ sea: 'stopped', shore: 'wall', land: 'none' })
    // a place the report does not have draws nothing in the water
    expect(by('tcp-22', 7)).toMatchObject({ sea: 'none', land: 'none' })
  })
})

describe('the passage to tcp 5432', () => {
  const port = report.ports[0]!
  const cell = port.cells[0]!

  it('numbers the steps and marks the rewrite, the deciding rule and the last word', () => {
    const rows = stepRows(cell)
    expect(rows.map((r) => r.n)).toEqual([1, 2, 3, 4, 5, 6, 7, 8])
    expect(rows.filter((r) => r.rewrite).map((r) => r.n)).toEqual([2])
    expect(rows.filter((r) => r.deciding).map((r) => r.n)).toEqual([7])
    expect(rows.filter((r) => r.decisive).map((r) => r.n)).toEqual([8])
    // jumps from chain to chain carry no mark and stay quiet
    expect(rows.filter((r) => r.quiet).map((r) => r.n)).toEqual([1, 4, 5, 6])
    expect(rows[1]!.step.effect).toBe(cell.rewrite?.effect)
    expect(rows[6]!.step.rule).toBe(cell.deciding?.rule)
  })

  it('groups the steps by hook, in the order the packet met them', () => {
    const groups = passage(cell)
    expect(groups.map((g) => g.hook)).toEqual(['prerouting', 'route', 'forward', 'deliver'])
    expect(groups.map((g) => g.rows.length)).toEqual([2, 1, 4, 1])
    expect(groups.flatMap((g) => g.rows.map((r) => r.step))).toEqual(cell.steps)
  })

  it('knows the packet that contradicts ufw from the one that does not', () => {
    expect(cell.class).toBe('open')
    expect(contradicts(cell)).toBe(true)
    expect(endOf(cell)).toBe('berth')
    const v6 = port.cells.find((c) => c.ipv6)!
    expect(contradicts(v6)).toBe(false)
    expect(endOf(v6)).toBe('stopped')
    expect(classWords(v6.class)).toBe('dropped without a word')
  })

  it('puts the packets sent from the chosen place first and loses none', () => {
    const fromLan = packetGroups(report, port, LAN)
    expect(fromLan.map((g) => g.id)).toEqual(['lan:eth0', 'internet'])
    expect(fromLan[0]!.vantage?.short).toBe('LAN eth0')
    expect(fromLan.flatMap((g) => g.cells).length).toBe(port.cells.length)
    expect(packetGroups(report, port, INTERNET).map((g) => g.id)).toEqual(['internet', 'lan:eth0'])
  })

  it('claims no settling step for a packet that was not decided', () => {
    const open: Cell = { ...cell, steps: cell.steps.map((s) => ({ ...s })) }
    const hanging: Cell = { ...open, class: 'undecided', possible: ['open', 'filtered'], unknowns: ['a rule source could not be read'] }
    expect(stepRows(open).some((r) => r.decisive)).toBe(true)
    expect(stepRows(hanging).some((r) => r.decisive)).toBe(false)
    expect(endOf(hanging)).toBe('undecided')
  })
})

describe('the headline', () => {
  it('is set one sentence to a line, with nothing lost', () => {
    expect(sentences(report.headline)).toEqual(['7 ports can be reached from outside.', 'ufw allows only 4 of them.'])
    expect(sentences('4 ports can be reached from outside, all allowed by ufw.')).toEqual(['4 ports can be reached from outside, all allowed by ufw.'])
    expect(sentences('Nothing listens')).toEqual(['Nothing listens'])
    expect(sentences('')).toEqual([])
  })

  it('does not break an address or a version at its dots', () => {
    const said = 'Port 22 is open to 198.51.100.0/24 only. nftables 1.1.3 decides it.'
    expect(sentences(said)).toEqual(['Port 22 is open to 198.51.100.0/24 only.', 'nftables 1.1.3 decides it.'])
    expect(sentences(said).join(' ')).toBe(said)
  })
})

describe('what the engine answers', () => {
  it('is a report when it says so', () => {
    const got = readAnswer(JSON.stringify({ ok: true, version: '1.2.3', report }))
    expect(got.ok).toBe(true)
    expect(got.version).toBe('1.2.3')
    if (got.ok) expect(got.report.headline).toBe(report.headline)
  })

  it("is the engine's own words when it refuses", () => {
    const got = readAnswer(JSON.stringify({ ok: false, version: 'dev', error: 'snapshot: this is not a Seaward snapshot' }))
    expect(got).toEqual({ ok: false, version: 'dev', error: 'snapshot: this is not a Seaward snapshot' })
  })

  it('is an error in plain words when it is anything else', () => {
    expect(readAnswer('not json')).toMatchObject({ ok: false, error: 'The engine answered with something that is not a report.' })
    expect(readAnswer('null')).toMatchObject({ ok: false, error: 'The engine gave no report and no reason.' })
    expect(readAnswer(JSON.stringify({ ok: true, version: 'dev' }))).toMatchObject({ ok: false })
    expect(readAnswer(JSON.stringify({ ok: true, version: 'dev', report: { host: 'x' } }))).toMatchObject({ ok: false })
    expect(readAnswer(JSON.stringify({ ok: false, error: '   ' }))).toMatchObject({ ok: false, error: 'The engine gave no report and no reason.', version: '' })
  })

  it('refuses a report with a part missing, which the page could not draw', () => {
    const NOT = { ok: false, error: 'The engine answered with something that is not a report.', version: 'dev' }
    const without = (change: (r: Record<string, unknown>) => void) => {
      const copy = JSON.parse(JSON.stringify(report)) as Record<string, unknown>
      change(copy)
      return readAnswer(JSON.stringify({ ok: true, version: 'dev', report: copy }))
    }
    const port = (r: Record<string, unknown>) => (r.ports as Record<string, unknown>[])[0]!
    expect(without((r) => delete r.headline)).toEqual(NOT)
    expect(without((r) => delete r.caveat)).toEqual(NOT)
    expect(without((r) => delete r.counts)).toEqual(NOT)
    expect(without((r) => (r.vantages = 'internet'))).toEqual(NOT)
    expect(without((r) => (r.frontend = { tool: 'ufw' }))).toEqual(NOT)
    expect(without((r) => (r.unread = 'the nftables rules'))).toEqual(NOT)
    expect(without((r) => (r.ports = [null]))).toEqual(NOT)
    expect(without((r) => delete port(r).cells)).toEqual(NOT)
    expect(without((r) => delete port(r).views)).toEqual(NOT)
    expect(without((r) => delete (port(r).cells as Record<string, unknown>[])[0]!.steps)).toEqual(NOT)
    // and nothing else about a whole report is asked for
    expect(without(() => undefined).ok).toBe(true)
    expect(without((r) => delete r.frontend).ok).toBe(true)
    expect(without((r) => delete r.detail).ok).toBe(true)
  })

  it('reads a list the engine left empty, written as null, as an empty list', () => {
    const copy = JSON.parse(JSON.stringify(report)) as Report
    const cell = copy.ports[0]!.cells[0]! as unknown as Record<string, unknown>
    cell.steps = null
    ;(copy as unknown as Record<string, unknown>).notes = null
    const got = readAnswer(JSON.stringify({ ok: true, version: 'dev', report: copy }))
    expect(got.ok).toBe(true)
    if (!got.ok) return
    expect(got.report.ports[0]!.cells[0]!.steps).toEqual([])
    expect(got.report.notes).toEqual([])
    expect(readAnswer(JSON.stringify({ ok: true, version: 'dev', report: { ...noInterface, vantages: null, ports: null } }))).toMatchObject({ ok: true, report: { vantages: [], ports: [] } })
  })
})
