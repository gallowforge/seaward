import { describe, expect, it } from 'vitest'
import { atIngress, BRIDGE, INGRESS, noInterface, notFollowed, notRead, ownReason, pastCeiling, SENDERS_CUT } from './testdata/cases'
import shop from './testdata/shop-1.report.json'
import type { Cell, Port, Report } from './types'
import { asSentence, classWords, contradicts, eitherWay, endOf, endWords, explained, hangsOn, hookName, labelOf, laneNote, lanes, outcomeWords, packetGroups, passage, portId, readAnswer, ruleGroups, sentences, stepRows, toldBy } from './view'

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

  it('sets a short note on the lane when the report names many senders', () => {
    // one network: the lane carries the report's own words
    const one = by('tcp-9100', INTERNET)
    expect(laneNote(one.port, one.view)).toBe('198.51.100.0/24 only')
    expect(laneNote(one.port, undefined)).toBe('')
    // sixteen addresses let in one by one: the report says three of them and how many more, which
    // is more than a lane has room for, so the lane says how many there are
    const from = (i: number) => `198.51.100.${8 * (i + 1)}`
    const cells = Array.from({ length: 16 }, (_, i) => ({ ...one.port.cells[0]!, vantage: 'internet', from: from(i), src: from(i), class: 'open' as const }))
    const dropped = { ...one.port.cells[0]!, vantage: 'internet', from: 'anyone', class: 'filtered' as const }
    const elsewhere = { ...cells[0]!, vantage: 'lan:eth0', from: '203.0.113.50' }
    const many = { ...one.port, cells: [dropped, ...cells, elsewhere] }
    const note = '198.51.100.8, 198.51.100.16, 198.51.100.24 and 13 more only'
    expect(laneNote(many, { vantage: 'internet', state: 'some', note })).toBe('16 named senders only')
    // two short names fit, and one long name is still one name
    expect(laneNote(many, { vantage: 'internet', state: 'some', note: '198.51.100.8 and 198.51.100.16 only' })).toBe('198.51.100.8 and 198.51.100.16 only')
    const long = '2001:db8:1234:5678:9abc:def0:1234:5678 only'
    expect(laneNote({ ...many, cells: [dropped, { ...cells[0]!, from: long.slice(0, -5) }] }, { vantage: 'internet', state: 'some', note: long })).toBe(long)
    // a note about the address family is never a list of senders
    expect(laneNote(many, { vantage: 'internet', state: 'open', note: 'IPv4 only' })).toBe('IPv4 only')
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

describe('a port that could not be decided', () => {
  const port = notFollowed.ports[0]!
  /** The port with every undecided packet hanging on these reasons. */
  const hangingOn = (unknowns: string[] | undefined, why = 'Accepted by a rule in chain input of table inet filter.'): Port => ({
    ...port,
    why,
    cells: port.cells.map((c) => {
      const { unknowns: _, ...rest } = c
      return unknowns ? { ...rest, unknowns } : rest
    }),
  })

  it('sets a reason as a sentence the way the command does', () => {
    expect(asSentence('the chain pre of table bridge b acts on frames')).toBe('The chain pre of table bridge b acts on frames.')
    expect(asSentence('Already a sentence.')).toBe('Already a sentence.')
    expect(asSentence('nft needs root: run it again')).toBe('Nft needs root: run it again.')
    expect(asSentence('')).toBe('')
  })

  it('is explained when the fine print lists its own reason', () => {
    // the port's reason is one of the chains not followed, or one of the sources not read
    expect(explained({ ...notFollowed, unfollowed: [BRIDGE] }, hangingOn(undefined, BRIDGE))).toBe(true)
    expect(explained(notRead, notRead.ports[0]!)).toBe(true)
  })

  it('is explained when everything its packets hang on is listed, whichever list it is in', () => {
    expect(explained(notFollowed, port)).toBe(true)
    // the packets carry the reason without its capital and full stop, or with them
    expect(explained(notFollowed, hangingOn(['the chain ingress of table netdev early acts on packets as they pass eth0, underneath the bridge, bond or VLAN interface they arrive on, where seaward does not follow them']))).toBe(true)
    expect(explained(notFollowed, hangingOn([INGRESS]))).toBe(true)
    const both: Report = { ...notFollowed, unread: [BRIDGE] }
    expect(explained(both, hangingOn([INGRESS, BRIDGE]))).toBe(true)
  })

  it('is explained when the scan stopped at a ceiling and the fine print says so', () => {
    // nobody that was asked gets through, and the reason nothing is ruled out is given once for all
    const ssh = pastCeiling.ports[0]!
    expect(explained(pastCeiling, ssh)).toBe(true)
    expect(explained({ ...pastCeiling, partial: undefined }, ssh)).toBe(false)
    const rows = lanes(pastCeiling, 0)
    expect(rows[0]).toMatchObject({ id: 'tcp-22', sea: 'undecided', land: 'none', reason: undefined, loud: false })
    // seen from the local network, where everyone was asked, the same port is simply stopped
    expect(lanes(pastCeiling, 1)[0]).toMatchObject({ sea: 'stopped', land: 'none' })
    // a port that is reached says "at least", and its lane says how many senders were found
    expect(rows[1]).toMatchObject({ id: 'tcp-8080', sea: 'some', land: 'through' })
    expect(laneNote(rows[1]!.port, rows[1]!.view)).toBe('at least 2 named senders')
    expect(SENDERS_CUT).toMatch(/were not asked\.$/)
  })

  it('is not explained when one thing it hangs on is listed nowhere, or when it names nothing', () => {
    expect(explained(notFollowed, hangingOn([INGRESS, 'the set allowed was not captured']))).toBe(false)
    expect(explained(notFollowed, hangingOn([]))).toBe(false)
    expect(explained(notFollowed, hangingOn(undefined))).toBe(false)
    expect(explained(ownReason, ownReason.ports[0]!)).toBe(false)
    // what a decided packet carries does not count for or against
    const decided: Port = { ...port, why: 'x', cells: port.cells.map((c) => ({ ...c, class: 'filtered' as const })) }
    expect(explained(notFollowed, decided)).toBe(false)
  })

  it('says its reason on its lane only where the fine print does not', () => {
    expect(lanes(notFollowed, INTERNET).map((l) => l.reason)).toEqual([undefined, undefined])
    expect(lanes(notRead, INTERNET).map((l) => l.reason)).toEqual([undefined])
    expect(lanes(ownReason, INTERNET).map((l) => l.reason)).toEqual([ownReason.ports[0]!.why])
    // a decided port never does
    expect(lanes(report, INTERNET).every((l) => l.reason === undefined)).toBe(true)
    expect(lanes(atIngress, INTERNET)[0]).toMatchObject({ sea: 'stopped', reason: undefined })
  })

  it('names a packet that gets nowhere either way by how the followed rules end it', () => {
    const [v4, v6] = port.cells as [Cell, Cell]
    const refused = notFollowed.ports[1]!.cells[0]!
    // it gets in unless the chain drops it: that is not decided
    expect([toldBy(v4), labelOf(v4), endOf(v4)]).toEqual(['undecided', 'not decided', 'undecided'])
    expect([toldBy(v6), labelOf(v6), endOf(v6)]).toEqual(['closed', 'no listener', 'empty'])
    expect([toldBy(refused), labelOf(refused), endOf(refused)]).toEqual(['rejected', 'refused', 'stopped'])
    // only the two ends that reach nothing are told that way
    expect([toldBy({ ...v4, otherwise: 'forwarded' }), labelOf({ ...v4, otherwise: 'forwarded' })]).toEqual(['undecided', 'not decided'])
    expect(toldBy({ ...v4, otherwise: 'filtered' })).toBe('undecided')
    // and none of them has a step that settles it: the chain not followed may still drop it
    for (const c of [v4, v6, refused]) expect(stepRows(c).some((r) => r.decisive)).toBe(false)
  })

  it('labels every packet in the words the command sets at the head of it', () => {
    const cell = report.ports[0]!.cells[0]!
    const ended = (c: Cell['class']): Cell => ({ ...cell, class: c })
    expect((['open', 'forwarded', 'closed', 'rejected', 'filtered', 'undecided'] as const).map((c) => labelOf(ended(c)))).toEqual(['gets through', 'passed on', 'no listener', 'refused', 'dropped', 'not decided'])
    // an end the page has never heard of is still said, as the report wrote it
    expect(labelOf({ ...cell, class: 'held' as Cell['class'] })).toBe('held')
  })

  it('says how a packet ends: its label, then what the engine means by that end', () => {
    const cell = report.ports[0]!.cells[0]!
    const said = (c: Cell): string => `${endWords(c).label}${endWords(c).more}`
    const ended = (c: Cell['class']): Cell => ({ ...cell, class: c })
    expect(said(ended('open'))).toBe('gets through: a program received it')
    expect(said(ended('forwarded'))).toBe('passed on: let through to another machine')
    expect(said(ended('closed'))).toBe('no listener: it got through and nothing was listening')
    expect(said(ended('rejected'))).toBe('refused: a rule refused it and told the sender')
    expect(said(ended('undecided'))).toBe('not decided: hangs on something Seaward cannot see')
    // the definition opens with the label, so the label is said once
    expect(endWords(ended('filtered'))).toEqual({ label: 'dropped', more: ' without a word' })
    expect(said(ended('filtered'))).toBe(classWords('filtered'))
    // told by how the followed rules end it: the label alone, since a chain not followed may still drop it
    const [v4, v6] = port.cells as [Cell, Cell]
    expect(endWords(v6)).toEqual({ label: 'no listener', more: '' })
    expect(endWords(notFollowed.ports[1]!.cells[0]!)).toEqual({ label: 'refused', more: '' })
    expect(said(v4)).toBe('not decided: hangs on something Seaward cannot see')
    expect(endWords({ ...cell, class: 'held' as Cell['class'] })).toEqual({ label: 'held', more: '' })
  })

  it('says how a packet with more than one end could end, in the command\'s words', () => {
    const [v4, v6] = port.cells as [Cell, Cell]
    expect(eitherWay(v4)).toBe('It could end either way: gets through, or dropped.')
    expect(eitherWay(v6)).toBe('It does not get through either way: no listener, or dropped.')
    expect(eitherWay(notFollowed.ports[1]!.cells[0]!)).toBe('It does not get through either way: refused, or dropped.')
    expect(eitherWay({ ...v4, possible: ['forwarded', 'rejected', 'undecided'] })).toBe('It could end either way: passed on, or refused, or not decided.')
    // one end, or none, is no choice
    expect(eitherWay({ ...v4, possible: ['open'] })).toBe('')
    expect(eitherWay(atIngress.ports[0]!.cells[0]!)).toBe('')
    expect(['open', 'forwarded', 'closed', 'rejected', 'filtered', 'undecided', 'held'].map(outcomeWords)).toEqual(['gets through', 'passed on', 'no listener', 'refused', 'dropped', 'not decided', 'held'])
  })

  it('lists what a packet hangs on without the reason it has just given', () => {
    const cell = ownReason.ports[0]!.cells[0]!
    expect(cell.unknowns?.length).toBe(1)
    expect(hangsOn(cell)).toEqual([])
    expect(hangsOn({ ...cell, unknowns: [cell.why, 'the set allowed was not captured'] })).toEqual(['the set allowed was not captured'])
    // a reason of its own is kept, as written
    expect(hangsOn(port.cells[0]!)).toEqual(port.cells[0]!.unknowns)
    expect(hangsOn(atIngress.ports[0]!.cells[0]!)).toEqual([])
  })
})

describe('the ingress hook', () => {
  it('has a name and a plain phrase, like every other hook', () => {
    expect(hookName('ingress')).toEqual({ name: 'ingress', plain: 'as it arrives on the interface' })
    for (const hook of ['ingress', 'prerouting', 'route', 'input', 'forward', 'postrouting', 'output', 'deliver']) expect(hookName(hook).plain, hook).not.toBe('')
  })

  it('is a group of its own in the passage', () => {
    const cell = atIngress.ports[0]!.cells[0]!
    expect(passage(cell).map((g) => g.hook)).toEqual(['ingress'])
    expect(stepRows(cell).map((r) => [r.n, r.deciding, r.decisive])).toEqual([[1, true, true]])
    expect(endOf(cell)).toBe('stopped')
  })
})

describe('a rule too long for one line', () => {
  /** The groups alone, without the space between them. */
  const groups = (rule: string): string[] => ruleGroups(rule).filter((_, i) => i % 2 === 0)

  it('breaks before an option, which keeps what belongs to it, as the command breaks it', () => {
    expect(groups('-A FORWARD -j DOCKER-FORWARD')).toEqual(['-A FORWARD', '-j DOCKER-FORWARD'])
    expect(groups('-A DOCKER ! -i br-4c2f9a71d0e3 -p tcp -m tcp --dport 5432 -j DNAT --to-destination 203.0.113.2:5432')).toEqual([
      '-A DOCKER',
      '! -i br-4c2f9a71d0e3',
      '-p tcp',
      '-m tcp',
      '--dport 5432',
      '-j DNAT',
      '--to-destination 203.0.113.2:5432',
    ])
    // a negation stays with what it negates, wherever it stands
    expect(groups('-A DOCKER -d 203.0.113.2/32 ! -i br0 -o br0 -j ACCEPT')).toEqual(['-A DOCKER', '-d 203.0.113.2/32', '! -i br0', '-o br0', '-j ACCEPT'])
    expect(groups('-A INPUT -s ! 198.51.100.0/24 -p tcp -m tcp --dport 22 -j DROP')).toEqual(['-A INPUT', '-s ! 198.51.100.0/24', '-p tcp', '-m tcp', '--dport 22', '-j DROP'])
    // everything behind an option belongs to it, however much that is
    expect(groups('-A INPUT -m comment --comment "a long remark that will not fit on one line" -j ACCEPT')).toEqual(['-A INPUT', '-m comment', '--comment "a long remark that will not fit on one line"', '-j ACCEPT'])
    // a value that begins with a hyphen is not an option, and a bare "!" before a value is not a negated option
    expect(groups('-A INPUT -m length --length -1 -j DROP')).toEqual(['-A INPUT', '-m length', '--length -1', '-j DROP'])
    expect(groups('-A INPUT -p tcp ! --syn -m state --state NEW -j DROP')).toEqual(['-A INPUT', '-p tcp', '! --syn', '-m state', '--state NEW', '-j DROP'])
    expect(groups('-A OUTPUT -o - ! 5 -j DROP')).toEqual(['-A OUTPUT', '-o - ! 5', '-j DROP'])
  })

  it('leaves a rule written without options in one piece, to break between its words', () => {
    expect(ruleGroups('tcp dport 22 ip saddr @admins accept')).toEqual(['tcp dport 22 ip saddr @admins accept'])
    expect(ruleGroups('ip saddr != 198.51.100.0/24 tcp dport { 22, 80 } drop')).toEqual(['ip saddr != 198.51.100.0/24 tcp dport { 22, 80 } drop'])
    expect(ruleGroups('')).toEqual([''])
  })

  it('gives the rule back character for character when the pieces are put together', () => {
    const rules = [...new Set(report.ports.flatMap((p) => p.cells.flatMap((c) => c.steps.map((s) => s.rule ?? ''))))]
    expect(rules.length).toBeGreaterThan(10)
    for (const rule of rules) expect(ruleGroups(rule).join(''), rule).toBe(rule)
    // the space between two words is kept as it was written, a run of it and a tab as well
    const odd = '  -A INPUT  -m comment --comment "two  spaces"\t-j   ACCEPT '
    expect(ruleGroups(odd)).toEqual(['  -A INPUT', '  ', '-m comment', ' ', '--comment "two  spaces"', '\t', '-j   ACCEPT '])
    expect(ruleGroups(odd).join('')).toBe(odd)
    // a group and the space after it come in turn, so there is always a group last
    for (const rule of [...rules, odd]) {
      const pieces = ruleGroups(rule)
      expect(pieces.length % 2, rule).toBe(1)
      pieces.forEach((piece, i) => expect(/\S/.test(piece), `${rule} [${i}]`).toBe(i % 2 === 0 && rule !== ''))
    }
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
    expect(without((r) => (r.unfollowed = 'the chain ingress'))).toEqual(NOT)
    expect(without((r) => (r.unfollowed = [{ chain: 'ingress' }]))).toEqual(NOT)
    expect(without((r) => (r.partial = 'not every sender was asked'))).toEqual(NOT)
    expect(without((r) => (r.partial = [true]))).toEqual(NOT)
    expect(without((r) => (r.notes = [7]))).toEqual(NOT)
    expect(without((r) => ((port(r).cells as Record<string, unknown>[])[0]!.otherwise = ['closed']))).toEqual(NOT)
    expect(without((r) => ((port(r).cells as Record<string, unknown>[])[0]!.unknowns = 'a set'))).toEqual(NOT)
    expect(without((r) => ((port(r).cells as Record<string, unknown>[])[0]!.possible = [null]))).toEqual(NOT)
    expect(without((r) => (r.ports = [null]))).toEqual(NOT)
    expect(without((r) => delete port(r).cells)).toEqual(NOT)
    expect(without((r) => delete port(r).views)).toEqual(NOT)
    expect(without((r) => delete (port(r).cells as Record<string, unknown>[])[0]!.steps)).toEqual(NOT)
    // and nothing else about a whole report is asked for
    expect(without(() => undefined).ok).toBe(true)
    expect(without((r) => delete r.frontend).ok).toBe(true)
    expect(without((r) => delete r.detail).ok).toBe(true)
  })

  it('reads the chains not followed and how an undecided packet ends otherwise', () => {
    const got = readAnswer(JSON.stringify({ ok: true, version: 'dev', report: notFollowed }))
    expect(got.ok).toBe(true)
    if (!got.ok) return
    expect(got.report.unfollowed).toEqual([INGRESS])
    expect(got.report.ports[0]!.cells.map((c) => c.otherwise)).toEqual(['open', 'closed'])
    // both are left out of most reports
    for (const r of [ownReason, atIngress, notRead]) expect(readAnswer(JSON.stringify({ ok: true, version: 'dev', report: r })).ok).toBe(true)
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
