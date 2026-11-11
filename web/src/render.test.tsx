import { render } from 'preact'
import type { ComponentChild } from 'preact'
import { afterEach, describe, expect, it } from 'vitest'
import { Chart } from './chart'
import { FinePrint, Own, Verdict } from './parts'
import { noInterface, noTool, nothingListens, notRead } from './testdata/cases'
import shop from './testdata/shop-1.report.json'
import type { Report } from './types'
import { readAnswer } from './view'

const shop1 = shop as unknown as Report
const nothing = () => undefined

let host: HTMLElement | undefined
function page(ui: ComponentChild): HTMLElement {
  host = document.createElement('div')
  document.body.append(host)
  render(ui, host)
  return host
}
afterEach(() => {
  if (host) render(null, host)
  host?.remove()
  host = undefined
})

/** The verdict, the chart and its fine print for one report, as the page sets them. */
function whole(report: Report, open: string | null = null, vantage = 0): HTMLElement {
  return page(
    <>
      <Verdict report={report} source={null} samples={[]} busy={false} failed={null} headRef={{ current: null }} onSample={nothing} />
      <Chart report={report} vantage={vantage} onVantage={nothing} open={open} onToggle={nothing} onClose={nothing} />
      <FinePrint report={report} vantage={vantage} />
    </>,
  )
}
const text = (el: Element | null | undefined): string => (el?.textContent ?? '').replace(/\s+/g, ' ').trim()
const all = (root: Element, sel: string): Element[] => [...root.querySelectorAll(sel)]
/** A list of terms and what is said of each. */
const pairs = (dl: Element): string[][] => all(dl, 'dt').map((dt) => [text(dt), text(dt.nextElementSibling)])

describe('shop-1 on the page', () => {
  it('says the verdict in the report’s words and overprints the contradiction', () => {
    const p = whole(shop1)
    expect(all(p, 'h1 .said').map(text)).toEqual(['7 ports can be reached from outside.', 'ufw allows only 4 of them.'])
    expect(all(p, 'h1 .said.over').map(text)).toEqual(['ufw allows only 4 of them.'])
    expect(text(p.querySelector('.detail'))).toBe(shop1.detail)
    // the caveat stands in the title block and under the chart, every time
    expect(text(p.querySelector('.cart-caveat'))).toBe(shop1.caveat)
    expect(text(p.querySelector('.fine .caution'))).toBe(shop1.caveat)
  })

  it('draws one lane a port, each a link to its own address', () => {
    const p = whole(shop1)
    const rows = all(p, '.lanes > li')
    expect(rows.map((r) => r.id)).toEqual(shop1.ports.map((x) => `${x.proto}-${x.port}`))
    for (const r of rows) expect(r.querySelector('a.lane')?.getAttribute('href')).toBe(`#${r.id}`)
    // what the tool says and what is true, side by side
    const pg = p.querySelector('#tcp-5432')!
    expect(text(pg.querySelector('.says .v'))).toBe('not allowed')
    expect(text(pg.querySelector('.fact .v'))).toBe('the internet (IPv4 only)')
  })

  it('marks an exposed port in words, not in colour alone', () => {
    const p = whole(shop1)
    const loud = all(p, '.lanes > li.loud')
    expect(loud.map((r) => r.id)).toEqual(['tcp-5432', 'tcp-6379', 'tcp-8081'])
    for (const r of loud) expect(text(r.querySelector('.fact .title'))).toMatch(/^Exposed\s*Reachable from the internet\. ufw does not allow it\.$/)
    expect(all(p, '.lanes > li:not(.loud) .over')).toEqual([])
    expect(text(p.querySelector('.fine .symbols li'))).toBe('Reachable, and ufw does not allow it')
  })

  it('opens a lane into its passage: every packet, every step, the rule as written', () => {
    const p = whole(shop1, 'tcp-5432')
    const pass = p.querySelector('#tcp-5432-passage')!
    expect(pass.getAttribute('aria-label')).toBe('The passage to tcp port 5432')
    expect(p.querySelector('#tcp-5432 a.lane')?.getAttribute('aria-expanded')).toBe('true')
    const port = shop1.ports[0]!
    expect(all(pass, '.packet').length).toBe(port.cells.length)
    const first = pass.querySelector('.packet')!
    const cell = port.cells[0]!
    expect(text(first.querySelector('.packet-h'))).toContain(`From ${cell.from} (${cell.src}) to ${cell.dst}`)
    expect(text(first.querySelector('.why'))).toBe(cell.why)
    expect(all(first, '.step').length).toBe(cell.steps.length)
    expect(all(first, '.rule').map((r) => r.textContent)).toEqual(cell.steps.filter((s) => s.rule).map((s) => s.rule))
    expect(all(first, '.hook-h b').map(text)).toEqual(['prerouting', 'routing decision', 'forward', 'delivery'])
    expect(all(first, '.step .tag').map(text)).toEqual(['Rewrites the destination', 'The deciding rule', 'Settles it'])
    // the packets sent from the other place are there, folded
    expect(all(pass, 'details.from summary').map(text)).toEqual([expect.stringContaining('the local network on eth0')])
  })
})

describe('reports the samples do not show', () => {
  it('a machine with no ports: says so, and draws no lane and no symbol', () => {
    const p = whole(nothingListens)
    expect(text(p.querySelector('h1'))).toBe('Nothing listens on this machine.')
    expect(text(p.querySelector('.none-said'))).toBe('The report lists no ports.')
    expect(p.querySelector('.lanes')).toBeNull()
    expect(p.querySelector('.symbols')).toBeNull()
    expect(pairs(p.querySelector('.cart-figures')!)[0]).toEqual(['ports', '0'])
    expect(text(p.querySelector('.fine .caution'))).toBe(nothingListens.caveat)
  })

  it('a machine with nowhere to ask from: no vantage switch, and the notes in full', () => {
    const p = whole(noInterface)
    expect(text(p.querySelector('h1'))).toBe(noInterface.headline)
    expect(p.querySelector('.seen')).toBeNull()
    expect(p.querySelector('.lanes')).toBeNull()
    expect(pairs(p.querySelector('.cart-facts')!)[0]).toEqual(['Seen from', 'no outside network interface'])
    expect(all(p, '.notes li').map(text)).toEqual(noInterface.notes)
    expect(text(p.querySelector('.fine .caution'))).toBe(noInterface.caveat)
  })

  it('rule sources that could not be read: said loudly, entry by entry', () => {
    const p = whole(notRead)
    const box = p.querySelector('.unread')!
    expect(box.getAttribute('role')).toBe('note')
    expect(text(box.querySelector('h3'))).toBe('Could not be read')
    expect(all(box, 'li').map(text)).toEqual(notRead.unread)
    expect(all(p, '.notes li').map(text)).toEqual(notRead.notes)
    // one unread source is spoken of as one
    const one = whole({ ...notRead, unread: notRead.unread!.slice(0, 1) })
    expect(text(one.querySelector('.unread p'))).toMatch(/^This rule source exists/)
  })

  it('an undecided port: a lane that claims nothing, and a passage that says what it hangs on', () => {
    const p = whole(notRead, 'tcp-22')
    const row = p.querySelector('#tcp-22')!
    expect(row.className).toContain('sea-undecided')
    expect(row.className).not.toContain('loud')
    expect(text(row.querySelector('.fact .v'))).toBe('not known')
    expect(text(row.querySelector('.svc .v'))).toBe('none named')
    expect(text(p.querySelector('.fine .symbols'))).toBe('Not decided')
    const pass = p.querySelector('#tcp-22-passage')!
    expect(pairs(pass.querySelector('.ends')!)).toEqual([
      ['It ends', 'undecided: hangs on something the snapshot does not hold'],
      ['It could end', 'open, or filtered'],
      ['It hangs on', 'The nftables packet rules could not be read: nft needs root.'],
    ])
    expect(all(pass, '.tag')).toEqual([])
    expect(p.querySelector('h1 .over')).toBeNull()
  })

  it('no firewall tool: no "says" column, and the page does not invent a list', () => {
    const p = whole(noTool)
    expect(p.querySelector('.strip')?.className).toContain('no-tool')
    expect(p.querySelector('.says')).toBeNull()
    expect(p.querySelector('.h-says')).toBeNull()
    expect(pairs(p.querySelector('.cart-facts')!)).toContainEqual(['Firewall tool', 'none reported'])
    expect(text(p.querySelector('.fine'))).toContain('The report names none, so there is no list to compare the rules with.')
    expect(text(p.querySelector('.fine .symbols'))).toBe('Reachable')
    // the same port from the other place is drawn as stopped
    const lan = whole(noTool, null, 1)
    expect(lan.querySelector('#udp-51820')?.className).toContain('sea-stopped')
    expect(all(lan, '.seen button').map((b) => [text(b), b.getAttribute('aria-pressed')])).toEqual([
      ['internet', 'false'],
      ['LAN lan0', 'true'],
    ])
  })

  it('an engine error: shown in the engine’s own words, with the way to try again', () => {
    const got = readAnswer(JSON.stringify({ ok: false, version: 'dev', error: 'snapshot: this is not a Seaward snapshot (the first line should be "# seaward snapshot 1")' }))
    expect(got.ok).toBe(false)
    if (got.ok) return
    const p = page(<Own state={{ at: 'refused', name: 'notes.txt', error: got.error }} dragging={false} onFile={nothing} />)
    const alert = p.querySelector('[role=alert]')!
    expect(text(alert)).toContain('notes.txt was not read. The engine says:')
    expect(text(alert.querySelector('pre'))).toBe(got.error)
    expect(text(p.querySelector('.drop-how'))).toBe('Run sudo seaward snapshot -o server.snapshot on the server, then drop the file here. It is read in this page and never leaves your browser.')
    expect(all(p, '.cmds code').map(text)).toEqual(['sudo seaward scan', 'sudo seaward why 5432', 'sudo seaward scan --check'])
    // and with no sample at all, the verdict says what failed and how to do without the page
    const v = page(<Verdict report={null} source={null} samples={[]} busy={false} failed={got.error} headRef={{ current: null }} onSample={nothing} />)
    expect(text(v.querySelector('h1'))).toBe('The sample could not be read.')
    expect(text(v.querySelector('[role=alert]'))).toBe(got.error)
  })
})
