// From the report to what the page draws. Everything here is a reading of the engine's own
// fields: no verdict is made up on this side.
import type { Answer, Cell, CellClass, Port, Report, Step, Vantage, View } from './types'

/** The plain address of a port on the page: "tcp-5432". Letters, digits and hyphens only. */
export const portId = (p: Pick<Port, 'proto' | 'port'>): string => `${p.proto}-${p.port}`.toLowerCase().replace(/[^a-z0-9-]/g, '')

/** What is drawn in the water: the lane from where connections come from, up to the shoreline. */
export type Sea = 'through' | 'some' | 'stopped' | 'undecided' | 'none'
/** How the firewall tool's own list shows on the shoreline at this lane. */
export type Shore = 'gate' | 'part' | 'wall' | 'plain'
/** What is drawn on the machine's side of the shoreline. */
export type Land = 'through' | 'stub' | 'none'
/** What the lane ends in. */
export type Berth = 'answers' | 'empty' | 'none'

/** One port as one lane of the chart, seen from one place. */
export interface Lane {
  id: string
  port: Port
  view: View | undefined
  sea: Sea
  shore: Shore
  land: Land
  berth: Berth
  /** The finding contradicts the tool's list: the one loud kind of row. */
  loud: boolean
  /** Seen from this place, a packet gets through that the tool's list does not allow. */
  breach: boolean
  /** The title says more than the two columns do, so the row shows it. */
  remark: boolean
  /** Why an undecided port is undecided, where the fine print does not already say it for all. */
  reason: string | undefined
}

const reached = (c: Cell): boolean => c.class === 'open' || c.class === 'forwarded'

/** The view of a port from one place; views are in the order of the report's vantages. */
export function viewFrom(port: Port, vantage: Vantage | undefined, index: number): View | undefined {
  if (!vantage) return undefined
  return port.views.find((v) => v.vantage === vantage.id) ?? port.views[index]
}

/** The packets of a port that were sent from one place. */
export function cellsFrom(port: Port, vantage: Vantage | undefined): Cell[] {
  if (!vantage) return []
  return port.cells.filter((c) => c.vantage === vantage.id)
}

/** As many characters as a note on a lane has room for before it runs out of the water it is set on. */
const LANE_NOTE = 40

/**
 * What is set on a lane's own line: the view's note ("198.51.100.0/24 only"), or, where that
 * names more senders than a lane has room for, how many of them get through. The names
 * themselves stand in the row's "In fact" column, and each has a packet of its own in the passage.
 * A note that begins "at least" is of a scan that did not ask every sender: the count then says
 * the same, and no "only".
 */
export function laneNote(port: Port, view: View | undefined): string {
  const note = view?.note ?? ''
  if (!view || view.state !== 'some' || note.length <= LANE_NOTE) return note
  const named = new Set(port.cells.filter((c) => c.vantage === view.vantage && reached(c)).map((c) => c.from))
  if (named.size < 2) return note
  return note.startsWith('at least ') ? `at least ${named.size} named senders` : `${named.size} named senders only`
}

function shoreOf(report: Report, cells: Cell[]): Shore {
  if (!report.frontend) return 'plain'
  const said = cells.filter((c) => c.allowed !== undefined)
  if (said.length === 0) return 'wall'
  if (said.every((c) => c.allowed)) return 'gate'
  return said.some((c) => c.allowed) ? 'part' : 'wall'
}

/** A reason as a sentence, the way the engine sets one: a capital first, a full stop last. */
export function asSentence(s: string): string {
  if (!s) return ''
  const t = s.charAt(0).toUpperCase() + s.slice(1)
  return t.endsWith('.') ? t : `${t}.`
}

/** What the fine print says once for the whole chart: the rule sources not read, the chains not followed, what was not asked. */
const listed = (report: Report): string[] => [...(report.unread ?? []), ...(report.unfollowed ?? []), ...(report.partial ?? [])]

/**
 * True when everything an undecided port hangs on is in the fine print's lists, so the port
 * itself can stay quiet. The same test as the command's own report (Text in internal/scan/text.go).
 */
export function explained(report: Report, port: Port): boolean {
  const said = listed(report)
  if (port.why && said.includes(port.why)) return true
  let n = 0
  for (const cell of port.cells) {
    if (cell.class !== 'undecided') continue
    for (const u of cell.unknowns ?? []) {
      if (!said.includes(asSentence(u))) return false
      n++
    }
  }
  return n > 0
}

/** One port as a lane, drawn from the vantage at `index`. */
export function lane(report: Report, port: Port, index: number): Lane {
  const vantage = report.vantages[index]
  const view = viewFrom(port, vantage, index)
  const cells = cellsFrom(port, vantage)
  const base = {
    id: portId(port),
    port,
    view,
    shore: shoreOf(report, cells),
    loud: port.finding === 'exposed',
    breach: cells.some((c) => reached(c) && c.allowed === false),
    // the title is set under the reach only where it adds to it; an undecided port's does not
    remark: port.severity === 'high' || port.severity === 'medium' || port.severity === 'low',
    // an undecided port gives its own reason on its row, unless the fine print gives it once for all
    reason: port.finding === 'undecided' && !explained(report, port) ? port.why || undefined : undefined,
  }
  // bound to the machine itself: the lane never touches the water
  if (port.finding === 'local') return { ...base, sea: 'none', land: 'stub', berth: 'answers' }
  const there: Berth = port.service ? 'answers' : 'none'
  switch (view?.state) {
    case 'open':
      return { ...base, sea: 'through', land: 'through', berth: 'answers' }
    case 'some':
      return { ...base, sea: 'some', land: 'through', berth: 'answers' }
    case 'closed':
      return { ...base, sea: 'through', land: 'through', berth: 'empty' }
    case 'stopped':
      return { ...base, sea: 'stopped', land: 'none', berth: there }
    case 'undecided':
      return { ...base, sea: 'undecided', land: 'none', berth: there }
    default:
      return { ...base, sea: 'none', land: 'none', berth: there }
  }
}

/** Every port as a lane, in the order the report gives them. */
export const lanes = (report: Report, index: number): Lane[] => report.ports.map((p) => lane(report, p, index))

/** One step of a packet's path, with the marks the page puts on it. */
export interface StepRow {
  /** Its number on the path, from 1. */
  n: number
  step: Step
  /** Where the destination changes. */
  rewrite: boolean
  /** The rule or policy that settled it. */
  deciding: boolean
  /** The step that settled how the packet ended. */
  decisive: boolean
  /** A jump from chain to chain that carries none of the marks. */
  quiet: boolean
}

/** A run of steps at the same hook. */
export interface HookGroup {
  hook: string
  rows: StepRow[]
}

const same = (a: Step, b: Step | undefined): boolean =>
  !!b && a.kind === b.kind && a.hook === b.hook && a.family === b.family && a.table === b.table && a.chain === b.chain && a.rule === b.rule && a.effect === b.effect

function lastIndex(steps: Step[], want: Step | undefined): number {
  for (let i = steps.length - 1; i >= 0; i--) if (same(steps[i]!, want)) return i
  return -1
}

/** The steps of one packet with their marks, in order. */
export function stepRows(cell: Cell): StepRow[] {
  const rewrite = cell.steps.findIndex((s) => same(s, cell.rewrite))
  const deciding = lastIndex(cell.steps, cell.deciding)
  return cell.steps.map((step, i) => {
    // the engine flags the last step of every packet; where nothing was decided, nothing settled it
    const row = { n: i + 1, step, rewrite: i === rewrite, deciding: i === deciding, decisive: step.decisive === true && cell.class !== 'undecided' }
    return { ...row, quiet: step.kind === 'jump' && !row.rewrite && !row.deciding && !row.decisive }
  })
}

/** The steps of one packet grouped by hook, in the order the packet met them. */
export function passage(cell: Cell): HookGroup[] {
  const groups: HookGroup[] = []
  for (const row of stepRows(cell)) {
    const hook = row.step.hook ?? ''
    const last = groups[groups.length - 1]
    if (last && last.hook === hook) last.rows.push(row)
    else groups.push({ hook, rows: [row] })
  }
  return groups
}

/** The hook's name as the kernel has it, and what it means in plain words. */
export function hookName(hook: string): { name: string; plain: string } {
  switch (hook) {
    case 'ingress':
      return { name: 'ingress', plain: 'as it arrives on the interface' }
    case 'prerouting':
      return { name: 'prerouting', plain: 'on arrival, before routing' }
    case 'route':
      return { name: 'routing decision', plain: 'for this machine, or to be passed on' }
    case 'input':
      return { name: 'input', plain: 'addressed to this machine' }
    case 'forward':
      return { name: 'forward', plain: 'passed on to another machine' }
    case 'postrouting':
      return { name: 'postrouting', plain: 'on the way out' }
    case 'output':
      return { name: 'output', plain: 'sent by this machine' }
    case 'deliver':
      return { name: 'delivery', plain: 'who takes it' }
    default:
      return { name: hook || 'step', plain: '' }
  }
}

/** Where a step happened, the way the engine names places: "ip6 filter / INPUT". */
export function place(step: Step): string {
  if (!step.table) return ''
  const table = step.family && step.family !== 'ip' ? `${step.family} ${step.table}` : step.table
  return step.chain ? `${table} / ${step.chain}` : table
}

/** How a packet ended, in the engine's own definitions (internal/engine/api.go). */
export function classWords(c: CellClass | string): string {
  switch (c) {
    case 'open':
      return 'a program received it'
    case 'closed':
      return 'it got through and nothing was listening'
    case 'rejected':
      return 'a rule refused it and told the sender'
    case 'filtered':
      return 'dropped without a word'
    case 'forwarded':
      return 'let through to another machine'
    case 'undecided':
      return 'hangs on something Seaward cannot see'
    default:
      return ''
  }
}

/** How a packet ended, in the words of the person who sent it, as the command says it. */
export function outcomeWords(c: CellClass | string): string {
  switch (c) {
    case 'open':
      return 'gets through'
    case 'forwarded':
      return 'passed on'
    case 'closed':
      return 'no listener'
    case 'rejected':
      return 'refused'
    case 'filtered':
      return 'dropped'
    case 'undecided':
      return 'not decided'
    default:
      return c
  }
}

/**
 * The end a packet is told by. A packet that reaches nothing, whether a chain that was not
 * followed drops it or the followed rules have the last word, is told by how those rules end it.
 */
export function toldBy(cell: Cell): CellClass | string {
  return cell.otherwise === 'closed' || cell.otherwise === 'rejected' ? cell.otherwise : cell.class
}

/** The words a packet is labelled with, the same ones the command sets at the head of it. */
export const labelOf = (cell: Cell): string => outcomeWords(toldBy(cell))

/**
 * What "It ends" says of a packet: its label, and after it the engine's definition of that end.
 * Where the definition opens with the label ("dropped without a word"), the label is not said
 * twice. A packet told by how the followed rules end it has no definition: a chain that was not
 * followed may still drop it, and the sentence above it says so.
 */
export function endWords(cell: Cell): { label: string; more: string } {
  const label = labelOf(cell)
  const means = toldBy(cell) === cell.class ? classWords(cell.class) : ''
  if (!means) return { label, more: '' }
  return { label, more: means.startsWith(`${label} `) ? means.slice(label.length) : `: ${means}` }
}

/** The sentence for a packet that can end in more than one way; nothing for any other. */
export function eitherWay(cell: Cell): string {
  const possible = cell.possible ?? []
  if (possible.length < 2) return ''
  const lead = toldBy(cell) === cell.class ? 'It could end either way: ' : 'It does not get through either way: '
  return `${lead}${possible.map(outcomeWords).join(', or ')}.`
}

/** What a packet hangs on, without the entry its own reason already gives. */
export const hangsOn = (cell: Cell): string[] => (cell.unknowns ?? []).filter((u) => asSentence(u) !== cell.why)

/** True for a word that starts an option of a rule: "-j", "--dport". A bare "-" or "-1" is a value. */
const isOption = (w: string | undefined): boolean => !!w && /^-(-|[A-Za-z])/.test(w)

/**
 * A rule cut where it may break when it is too long for one line, the way the command breaks it
 * (wrapRule in internal/scan/text.go): before an option, which keeps what belongs to it, so
 * "-j ACCEPT" stays whole and so does "! -i eth0". The pieces come in turn, a group and then the
 * space after it, and put together again they are the rule, character for character. A rule
 * written without options, as nft writes them, is one piece and breaks between its words.
 */
export function ruleGroups(rule: string): string[] {
  const parts = rule.match(/\s+|\S+/g) ?? []
  const words = parts.filter((p) => /\S/.test(p))
  const out: string[] = []
  let group = ''
  let gap = ''
  let n = 0
  for (const part of parts) {
    if (!/\S/.test(part)) {
      gap = part
      continue
    }
    const i = n++
    let starts = false
    if (part === '!') starts = isOption(words[i + 1])
    else if (isOption(part)) starts = words[i - 1] !== '!'
    if (i === 0) {
      // whatever stands before the first word stays with it
      group = gap + part
    } else if (starts) {
      out.push(group, gap)
      group = part
    } else {
      group += gap + part
    }
    gap = ''
  }
  out.push(group + gap)
  return out
}

/** How the packet's own lane ends, for the drawing of its passage. */
export type End = 'berth' | 'empty' | 'stopped' | 'undecided'

export function endOf(cell: Cell): End {
  switch (toldBy(cell)) {
    case 'open':
    case 'forwarded':
      return 'berth'
    case 'closed':
      return 'empty'
    case 'undecided':
      return 'undecided'
    default:
      return 'stopped'
  }
}

/** True when this packet gets through although the tool's list does not allow it. */
export const contradicts = (cell: Cell): boolean => reached(cell) && cell.allowed === false

/** The packets of a port, those sent from the chosen place first, each group in report order. */
export function packetGroups(report: Report, port: Port, index: number): { vantage: Vantage | undefined; id: string; cells: Cell[] }[] {
  const ids: string[] = []
  for (const c of port.cells) if (!ids.includes(c.vantage)) ids.push(c.vantage)
  const chosen = report.vantages[index]?.id
  ids.sort((a, b) => Number(b === chosen) - Number(a === chosen))
  return ids.map((id) => ({ vantage: report.vantages.find((v) => v.id === id), id, cells: port.cells.filter((c) => c.vantage === id) }))
}

/** The sentences of the headline, so the page can set them on lines of their own. */
export function sentences(text: string): string[] {
  const out: string[] = []
  let from = 0
  // a full stop ends a sentence only where a space follows it: "198.51.100.0/24" stays whole
  for (let i = 0; i < text.length - 1; i++) {
    const c = text[i]
    if ((c === '.' || c === '!' || c === '?') && /\s/.test(text[i + 1]!)) {
      out.push(text.slice(from, i + 1).trim())
      from = i + 1
    }
  }
  out.push(text.slice(from).trim())
  return out.filter(Boolean)
}

/** Reads what seawardScan answered. Anything that is not a report becomes an error in plain words. */
const NOT_A_REPORT = 'The engine answered with something that is not a report.'

const isList = (x: unknown): x is unknown[] => Array.isArray(x)
const isThing = (x: unknown): x is Record<string, unknown> => !!x && typeof x === 'object' && !isList(x)

/**
 * True when the answer has every part the page reads without asking, so drawing it cannot fail.
 * A list the engine wrote as null (how Go writes one it never filled) is made an empty list first.
 */
function drawable(r: unknown): r is Report {
  if (!isThing(r) || typeof r.headline !== 'string' || typeof r.caveat !== 'string') return false
  const list = (of: Record<string, unknown>, key: string): unknown[] | null => {
    if (of[key] === null) of[key] = []
    const x = of[key]
    return isList(x) ? x : null
  }
  // a list of sentences that may be left out: absent, or a list with nothing but text in it
  const words = (of: Record<string, unknown>, key: string): boolean => of[key] === undefined || !!list(of, key)?.every((x) => typeof x === 'string')
  const vantages = list(r, 'vantages')
  const ports = list(r, 'ports')
  if (!isThing(r.counts) || !vantages || !ports) return false
  if (!vantages.every((v) => isThing(v) && typeof v.id === 'string')) return false
  if (r.frontend !== undefined && !(isThing(r.frontend) && typeof r.frontend.tool === 'string' && list(r.frontend, 'allows'))) return false
  if (!words(r, 'unread') || !words(r, 'unfollowed') || !words(r, 'partial') || !words(r, 'notes')) return false
  return ports.every((p) => {
    if (!isThing(p) || typeof p.proto !== 'string' || typeof p.port !== 'number') return false
    const views = list(p, 'views')
    const cells = list(p, 'cells')
    if (!views || !cells || !views.every(isThing)) return false
    return cells.every((c) => {
      if (!isThing(c) || !list(c, 'steps')?.every(isThing)) return false
      return words(c, 'possible') && words(c, 'unknowns') && (c.otherwise === undefined || typeof c.otherwise === 'string')
    })
  })
}

export function readAnswer(json: string): { ok: true; report: Report; version: string } | { ok: false; error: string; version: string } {
  let a: Partial<Answer>
  try {
    a = JSON.parse(json) as Partial<Answer>
  } catch {
    return { ok: false, error: NOT_A_REPORT, version: '' }
  }
  const version = typeof a?.version === 'string' ? a.version : ''
  if (a?.ok && drawable(a.report)) return { ok: true, report: a.report, version }
  // it says it has a report, and what it has cannot be drawn
  if (a?.ok && a.report) return { ok: false, error: NOT_A_REPORT, version }
  const said = typeof a?.error === 'string' && a.error.trim() ? a.error.trim() : 'The engine gave no report and no reason.'
  return { ok: false, error: said, version }
}
