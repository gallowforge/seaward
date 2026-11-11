import { render } from 'preact'
import type { ComponentChild } from 'preact'
import { afterEach, describe, expect, it, vi } from 'vitest'
import { Chart } from './chart'
import { FinePrint, Own, Verdict } from './parts'
import passageCss from './styles/passage.css?raw'
import { atIngress, BRIDGE, INGRESS, LONG_JUMP, LONG_NFT, LONG_WORD, longRules, noInterface, noTool, nothingListens, notFollowed, notRead, ownReason, pastCeiling, SENDERS_CUT } from './testdata/cases'
import shop from './testdata/shop-1.report.json'
import type { Report } from './types'
import { readAnswer } from './view'

const shop1 = shop as unknown as Report
const nothing = () => undefined

// every page a test sets up, so that none is left standing for the next test; `host` is the last one
const hosts: HTMLElement[] = []
let host: HTMLElement | undefined
function page(ui: ComponentChild): HTMLElement {
  host = document.createElement('div')
  hosts.push(host)
  document.body.append(host)
  render(ui, host)
  return host
}
afterEach(() => {
  for (const h of hosts.splice(0)) {
    render(null, h)
    h.remove()
  }
  host = undefined
  vi.unstubAllGlobals()
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

  it('labels each packet in the words the command uses, on its lane and under it', () => {
    const p = whole(shop1, 'tcp-5432')
    const [v4, v6] = all(p, '#tcp-5432-passage .from:not(details) .packet') as [Element, Element]
    // over IPv4 it is handed to the container, against ufw's list
    expect(text(v4.querySelector('.t-word'))).toBe('gets through')
    expect(pairs(v4.querySelector('.ends')!)).toEqual([
      ['It ends', 'gets through: a program received it'],
      ['ufw says', 'not allowed'],
    ])
    expect(v4.className).toContain('end-berth')
    expect(v4.className).toContain('bad')
    // over IPv6 no rule lets it in
    expect(text(v6.querySelector('.t-word'))).toBe('dropped')
    expect(pairs(v6.querySelector('.ends')!)).toEqual([
      ['It ends', 'dropped without a word'],
      ['ufw says', 'not allowed'],
    ])
    expect(v6.className).toContain('end-stopped')
    // one that gets through and finds nobody there
    const dead = whole(shop1, 'tcp-8443').querySelector('#tcp-8443-passage .packet')!
    expect(text(dead.querySelector('.t-word'))).toBe('no listener')
    expect(pairs(dead.querySelector('.ends')!)[0]).toEqual(['It ends', 'no listener: it got through and nothing was listening'])
    // and no packet anywhere on the page is labelled with the report's own word for its end
    for (const port of shop1.ports) {
      const words = all(whole(shop1, `${port.proto}-${port.port}`), '.t-word, .ends div:first-child dd b').map(text)
      expect(words.length, `${port.proto} ${port.port}`).toBe(port.cells.length * 2)
      for (const w of words) expect(['gets through', 'passed on', 'no listener', 'refused', 'dropped', 'not decided']).toContain(w)
    }
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
    expect(text(pass.querySelector('.why'))).toBe('The nftables packet rules could not be read: nft needs root.')
    expect(text(pass.querySelector('.either'))).toBe('It could end either way: gets through, or dropped.')
    // the one thing it hangs on is the reason just given, so it is not said twice
    expect(text(pass.querySelector('.t-word'))).toBe('not decided')
    expect(pairs(pass.querySelector('.ends')!)).toEqual([['It ends', 'not decided: hangs on something Seaward cannot see']])
    expect(all(pass, '.tag')).toEqual([])
    expect(p.querySelector('h1 .over')).toBeNull()
    // the fine print gives the reason once for every port, so the lane does not repeat it
    expect(row.querySelector('.fact .title')).toBeNull()
  })

  it('a scan that stopped at a ceiling: said first and loudly, and the chart rules nothing out', () => {
    const p = whole(pastCeiling)
    expect(text(p.querySelector('h1'))).toBe('At least 1 port can be reached from outside.')
    expect(text(p.querySelector('.detail'))).toBe('Not every sender was asked. 1 more port could not be decided.')
    const box = p.querySelector('.partial')!
    expect(box.getAttribute('role')).toBe('note')
    expect(text(box.querySelector('h3'))).toBe('Not asked')
    expect(text(box.querySelector('p'))).toBe('The scan stopped at a ceiling. What lies beyond it is not on the chart, so the chart rules nothing out.')
    expect(all(box, 'li').map(text)).toEqual([SENDERS_CUT])
    // the port nobody that was asked reaches is drawn as not decided, and says who was asked
    const ssh = p.querySelector('#tcp-22')!
    expect(ssh.className).toContain('sea-undecided')
    expect(text(ssh.querySelector('.fact .v'))).toBe('nobody that was asked')
    // the reason stands in the fine print once, so the lane does not repeat it
    expect(ssh.querySelector('.fact .title')).toBeNull()
    // the port that is reached says "at least", and its lane how many senders were found
    const web = p.querySelector('#tcp-8080')!
    expect(text(web.querySelector('.fact .v'))).toBe('at least 10.0.0.1, 10.0.0.17, 10.0.0.33 and 1020 more')
    expect(text(web.querySelector('.remark'))).toBe('at least 2 named senders')
    // with rule sources that were not read as well, what was not asked comes first
    const both = whole({ ...pastCeiling, unread: notRead.unread, unfollowed: [BRIDGE] })
    expect(all(both, '.fine [role=note]').map((b) => text(b.querySelector('h3')))).toEqual(['Not asked', 'Could not be read', 'Not followed'])
    // and there is no such box on a report that asked everything
    expect(whole(shop1).querySelector('.partial')).toBeNull()
    expect(whole({ ...pastCeiling, partial: [] }).querySelector('.partial')).toBeNull()
  })

  it('chains that were not followed: listed like what was not read, entry by entry', () => {
    const p = whole(notFollowed)
    expect(p.querySelector('.unread')).toBeNull()
    const box = p.querySelector('.unfollowed')!
    expect(box.getAttribute('role')).toBe('note')
    expect(text(box.querySelector('h3'))).toBe('Not followed')
    expect(text(box.querySelector('p'))).toBe('This chain acts on packets outside the path Seaward follows. What it does to them is not on the chart.')
    expect(all(box, 'li').map((li) => li.textContent)).toEqual([INGRESS])
    // more than one is spoken of as several, each as the report wrote it
    const two = whole({ ...notFollowed, unfollowed: [INGRESS, BRIDGE] })
    expect(text(two.querySelector('.unfollowed p'))).toBe('These chains act on packets outside the path Seaward follows. What they do to them is not on the chart.')
    expect(all(two, '.unfollowed li').map((li) => li.textContent)).toEqual([INGRESS, BRIDGE])
    // with rule sources that were not read as well: two boxes, what was not read first
    const both = whole({ ...notRead, unfollowed: [BRIDGE] })
    expect(all(both, '.fine [role=note]').map((b) => text(b.querySelector('h3')))).toEqual(['Could not be read', 'Not followed'])
    expect(both.querySelector('.unread')?.nextElementSibling?.className).toBe('unfollowed')
    // and no box at all where the report lists none
    expect(whole(shop1).querySelector('.unfollowed')).toBeNull()
    expect(whole({ ...notFollowed, unfollowed: [] }).querySelector('.unfollowed')).toBeNull()
  })

  it('an undecided port the fine print explains stays a plain lane; one it does not says why', () => {
    const quiet = whole(notFollowed)
    const row = quiet.querySelector('#tcp-22')!
    expect(row.className).toContain('sea-undecided')
    expect(row.className).not.toContain('loud')
    expect(text(row.querySelector('.fact .v'))).toBe('not known')
    expect(row.querySelector('.fact .title')).toBeNull()
    // refused either way: the report counts it as stopped, and so does its lane
    expect(quiet.querySelector('#tcp-113')?.className).toContain('sea-stopped')
    expect(quiet.querySelector('#tcp-113 .fact .title')).toBeNull()
    const own = whole(ownReason)
    const said = own.querySelector('#tcp-22')!
    expect(text(said.querySelector('.fact .v'))).toBe('not known')
    expect(text(said.querySelector('.fact .title'))).toBe('The meta hour match depends on the time of day or the date, which seaward does not model.')
    expect(said.className).not.toContain('loud')
    expect(said.querySelector('.over')).toBeNull()
    expect(own.querySelector('.unfollowed, .unread')).toBeNull()
  })

  it('a packet past a chain that was not followed: named by how it ends, with both ends said', () => {
    const p = whole(notFollowed, 'tcp-22')
    const [v4, v6] = all(p, '#tcp-22-passage .packet') as [Element, Element]
    // over IPv4 it gets in unless that chain drops it: not decided
    expect(v4.className).toContain('end-undecided')
    expect(text(v4.querySelector('.t-word'))).toBe('not decided')
    expect(text(v4.querySelector('.why'))).toBe('Accepted by a rule in chain input of table inet filter. A chain that was not followed may drop it instead.')
    expect(text(v4.querySelector('.either'))).toBe('It could end either way: gets through, or dropped.')
    expect(v4.querySelector('.why')?.nextElementSibling).toBe(v4.querySelector('.either'))
    expect(pairs(v4.querySelector('.ends')!)).toEqual([
      ['It ends', 'not decided: hangs on something Seaward cannot see'],
      ['It hangs on', notFollowed.ports[0]!.cells[0]!.unknowns![0]!],
    ])
    expect(all(v4, '.tag').map(text)).toEqual(['The deciding rule'])
    // over IPv6 nothing listens, so it gets nowhere either way: named by that, and drawn as that
    expect(v6.className).toContain('end-empty')
    expect(v6.className).not.toContain('end-undecided')
    expect(text(v6.querySelector('.t-word'))).toBe('no listener')
    expect(text(v6.querySelector('.either'))).toBe('It does not get through either way: no listener, or dropped.')
    expect(pairs(v6.querySelector('.ends')!)).toEqual([
      ['It ends', 'no listener'],
      ['It hangs on', notFollowed.ports[0]!.cells[1]!.unknowns![0]!],
    ])
    // the port's own reason is the first packet's, so it is not set above them as well
    expect(p.querySelector('.pass-why')).toBeNull()
    // refused either way
    const refused = whole(notFollowed, 'tcp-113').querySelector('#tcp-113-passage .packet')!
    expect(refused.className).toContain('end-stopped')
    expect(text(refused.querySelector('.t-word'))).toBe('refused')
    expect(text(refused.querySelector('.either'))).toBe('It does not get through either way: refused, or dropped.')
    expect(pairs(refused.querySelector('.ends')!)[0]).toEqual(['It ends', 'refused'])
    expect(all(refused, '.tag').map(text)).toEqual(['The deciding rule'])
  })

  it('a packet with one end says no "either way", and one with a reason of its own does not repeat it', () => {
    expect(all(whole(shop1, 'tcp-5432'), '.either')).toEqual([])
    expect(all(whole(atIngress, 'tcp-80'), '.either')).toEqual([])
    const pass = whole(ownReason, 'tcp-22').querySelector('#tcp-22-passage')!
    expect(text(pass.querySelector('.either'))).toBe('It could end either way: gets through, or dropped.')
    expect(pairs(pass.querySelector('.ends')!)).toEqual([['It ends', 'not decided: hangs on something Seaward cannot see']])
    // a second thing it hangs on is still listed, as the report wrote it
    const port = ownReason.ports[0]!
    const more: Report = { ...ownReason, ports: [{ ...port, cells: [{ ...port.cells[0]!, unknowns: [...port.cells[0]!.unknowns!, 'the set allowed was not captured'] }] }] }
    expect(pairs(whole(more, 'tcp-22').querySelector('.ends')!)[1]).toEqual(['It hangs on', 'the set allowed was not captured'])
  })

  it('a rule at the ingress hook: named, placed and explained like any other step', () => {
    const p = whole(atIngress, 'tcp-80')
    expect(p.querySelector('#tcp-80')?.className).toContain('sea-stopped')
    const packet = p.querySelector('#tcp-80-passage .packet')!
    expect(text(packet.querySelector('.hook-h'))).toBe('ingressas it arrives on the interface')
    expect(all(packet, '.hook-h b').map(text)).toEqual(['ingress'])
    expect(all(packet, '.t-name').map(text)).toEqual(['ingress'])
    expect(text(packet.querySelector('.step .place'))).toBe('netdev early / ingress')
    expect(all(packet, '.rule').map((r) => r.textContent)).toEqual(['tcp dport 80 drop'])
    expect(all(packet, '.tag').map(text)).toEqual(['Settles it'])
    expect(text(packet.querySelector('.t-word'))).toBe('dropped')
    expect(pairs(packet.querySelector('.ends')!)).toEqual([['It ends', 'dropped without a word']])
  })

  it('notes: set exactly as the report wrote them, with nothing added or changed', () => {
    const notes = [
      'The chain ingress of table netdev early drops by default every frame that arrives on eth0: seaward follows the IP packet through it and takes it that the address lookups before it (ARP) get through.',
      'Docker publishes 2 ports (203.0.113.10:8080, 203.0.113.10:8443).',
      'a note the engine left without a capital or a full stop',
      'Is the bridge filtered?',
    ]
    const p = whole({ ...notFollowed, notes })
    expect(all(p, '.notes li').map((li) => li.textContent)).toEqual(notes)
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

  it('a packet says who sent it as the command does: senders that are one address are named once', () => {
    const port = noTool.ports[0]!
    const cell = port.cells[0]!
    const head = (from: string): Element => whole({ ...noTool, ports: [{ ...port, cells: [{ ...cell, from }] }] }, 'udp-51820').querySelector('#udp-51820-passage .packet-h')!
    // a group of senders, and the address that stood for them
    expect(text(head('anyone'))).toBe('From anyone (198.51.100.7) to 203.0.113.20 IPv4')
    expect(text(head('anyone').querySelector('i'))).toBe('anyone')
    // the mark of the family is tied to the address by a space that does not break, so it never stands alone on a line
    expect(head('anyone').textContent).toContain('203.0.113.20\u00a0IPv4')
    expect(text(head('198.51.100.0/24'))).toBe('From 198.51.100.0/24 (198.51.100.7) to 203.0.113.20 IPv4')
    // one address, or no name at all: the address alone
    for (const from of [cell.src, '']) {
      expect(text(head(from))).toBe('From 198.51.100.7 to 203.0.113.20 IPv4')
      expect(head(from).querySelector('i')).toBeNull()
      expect(all(head(from), '.addr').map(text)).toEqual(['198.51.100.7', '203.0.113.20'])
    }
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

describe('a long rule', () => {
  /** What is set whole in one rule: its groups, as the page marks them. */
  const kept = (rule: Element): string[] => all(rule, '.opt').map((o) => o.textContent ?? '')

  it('is on the page character for character, cut only where the command would break it', () => {
    const p = whole(longRules, 'tcp-587')
    const [jump, word] = all(p, '#tcp-587-passage .rule') as [Element, Element]
    expect(jump.textContent).toBe(LONG_JUMP)
    expect(word.textContent).toBe(LONG_WORD)
    // an option is kept with what belongs to it, however long that is
    expect(kept(jump)).toEqual([
      '-A INPUT',
      '-d 203.0.113.10/32',
      '-i eth0',
      '-p tcp',
      '-m multiport',
      '--dports 25,465,587,993,995,4190',
      '-m conntrack',
      '--ctstate NEW',
      '-m comment',
      '--comment "mail for the office and both relays, added for the migration and never taken out again"',
      '-j MAIL-IN',
    ])
    expect(kept(word)).toEqual(['-A MAIL-IN', '-s 198.51.100.0/24', '-m comment', '--comment "https://tickets.example/ops/firewall/2026/allow-the-office-network-through-to-every-mail-port"', '-j ACCEPT'])
    // between two groups there is the space the rule has there, and nothing else
    for (const rule of [jump, word]) {
      const code = rule.querySelector('code')!
      expect([...code.childNodes].filter((n) => n.nodeType === Node.TEXT_NODE).map((n) => n.textContent)).toEqual(kept(rule).slice(1).map(() => ' '))
      expect(code.children.length).toBe(kept(rule).length)
    }
    // the rule is still one block of text for a reader, with its step's number
    expect(jump.tagName).toBe('PRE')
    expect(jump.getAttribute('data-n')).toBe('2')
  })

  it('written without options, as nft writes them, is plain text that breaks between its words', () => {
    const p = whole(longRules, 'tcp-993')
    const rule = p.querySelector('#tcp-993-passage .rule')!
    expect(rule.textContent).toBe(LONG_NFT)
    expect(kept(rule)).toEqual([])
    expect(rule.querySelector('code')?.childNodes.length).toBe(1)
    // a short rule of the same kind is plain text as well
    expect(kept(whole(atIngress, 'tcp-80').querySelector('#tcp-80-passage .rule')!)).toEqual([])
  })

  it('is set to break over lines, its further lines two columns in, and never to be cut at the edge of its box', () => {
    // The breaking itself is the browser's work, and this test's page lays nothing out: what can
    // be held to here is that the page asks for it. (The built page is looked at in a browser.)
    const block = (selector: string): string => {
      const at = passageCss.indexOf(`\n${selector} {`)
      expect(at, selector).toBeGreaterThan(-1)
      return passageCss.slice(at, passageCss.indexOf('}', at))
    }
    const rule = block('.rule')
    expect(rule).toMatch(/white-space:\s*pre-wrap;/)
    expect(rule).toMatch(/overflow-wrap:\s*anywhere;/)
    expect(rule).toMatch(/--in:\s*2ch;/)
    expect(rule).toMatch(/text-indent:\s*calc\(var\(--in\) \* -1\);/)
    expect(rule).toMatch(/padding:[^;]*calc\(0\.75rem \+ var\(--in\)\);/)
    expect(rule).not.toMatch(/white-space:\s*(pre|nowrap);/)
    const opt = block('.rule .opt')
    expect(opt).toMatch(/display:\s*inline-block;/)
    expect(opt).toMatch(/max-width:\s*100%;/)
    expect(opt).toMatch(/text-indent:\s*0;/)
  })
})

// The stylesheet breaks a long rule over lines, so in a browser that does as it is asked no rule
// is wider than its box. Should one be all the same, it scrolls sideways, and then the keys have to
// reach it: that is measured, and measured again whenever a size changes, not once on opening.
describe('a rule wider than its box all the same', () => {
  /** Stands in for the browser's own watcher of sizes, which the tests' page does not have. */
  class Watch {
    static made: Watch[] = []
    tell: () => void
    seen: Element[] = []
    off = false
    constructor(tell: () => void) {
      this.tell = tell
      Watch.made.push(this)
    }
    observe(el: Element) {
      this.seen.push(el)
    }
    unobserve() {}
    disconnect() {
      this.off = true
    }
  }
  const sized = (el: Element, scroll: number, client: number) => {
    Object.defineProperty(el, 'scrollWidth', { configurable: true, value: scroll })
    Object.defineProperty(el, 'clientWidth', { configurable: true, value: client })
  }

  it('is measured again whenever its box changes size, and no longer once the passage is closed', () => {
    Watch.made = []
    vi.stubGlobal('ResizeObserver', Watch)
    const p = whole(shop1, 'tcp-5432')
    const pass = p.querySelector('#tcp-5432-passage')!
    const rules = all(pass, '.rule') as HTMLElement[]
    const rule = rules[0]!
    expect(Watch.made.length).toBe(1)
    const watch = Watch.made[0]!
    // the passage and every rule in it are watched, the folded ones too
    expect(watch.seen).toContain(pass)
    for (const r of rules) expect(watch.seen).toContain(r)
    // as first measured, the rule fits: nothing to scroll, so no stop for the keys
    expect(rule.hasAttribute('tabindex')).toBe(false)
    // the box gets narrower than the rule
    sized(rule, 808, 288)
    watch.tell()
    expect(rule.tabIndex).toBe(0)
    expect(rule.getAttribute('role')).toBe('group')
    expect(rule.getAttribute('aria-label')).toBe(`The rule at step ${rule.dataset.n}, which scrolls sideways`)
    expect(rules[1]!.hasAttribute('tabindex')).toBe(false)
    // and wide enough again
    sized(rule, 808, 900)
    watch.tell()
    expect(rule.hasAttribute('tabindex')).toBe(false)
    expect(rule.hasAttribute('role')).toBe(false)
    expect(rule.hasAttribute('aria-label')).toBe(false)
    // closing the passage stops the watching
    expect(watch.off).toBe(false)
    render(null, host!)
    expect(watch.off).toBe(true)
    // a size reported late, after that, does no harm
    expect(() => watch.tell()).not.toThrow()
  })

  it('starts a fresh watch when the passage is seen from another place, and drops the old one', () => {
    Watch.made = []
    vi.stubGlobal('ResizeObserver', Watch)
    const chart = (vantage: number) => <Chart report={shop1} vantage={vantage} onVantage={nothing} open="tcp-5432" onToggle={nothing} onClose={nothing} />
    const p = page(chart(0))
    const pass = p.querySelector('#tcp-5432-passage')!
    expect(Watch.made.length).toBe(1)
    // the same passage, seen from the other place: other packets come first, with other rules
    render(chart(1), p)
    expect(p.querySelector('#tcp-5432-passage')).toBe(pass)
    expect(Watch.made.length).toBe(2)
    expect(Watch.made[0]!.off).toBe(true)
    expect(Watch.made[1]!.off).toBe(false)
    for (const r of all(pass, '.rule')) expect(Watch.made[1]!.seen).toContain(r)
  })

  it('is still drawn where the browser cannot watch a size', () => {
    expect(typeof ResizeObserver).toBe('undefined')
    const p = whole(shop1, 'tcp-5432')
    expect(all(p, '#tcp-5432-passage .rule').length).toBeGreaterThan(0)
    expect(p.querySelector('#tcp-5432-passage .rule')?.hasAttribute('tabindex')).toBe(false)
  })
})
