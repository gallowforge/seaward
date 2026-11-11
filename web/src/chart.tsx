// The chart: every port is a lane from open water to a service, and the shoreline is the
// firewall. The shoreline is drawn as the tool's list has it (a gap where the list allows the
// port); the lane is drawn as the rules have it. Where the two disagree, the lane crosses
// unbroken shoreline, in the one colour the page keeps for that.
import { useLayoutEffect, useRef } from 'preact/hooks'
import { Passage } from './passage'
import type { Report, ViewState } from './types'
import { lanes, type Berth, type Land, type Lane, type Sea, type Shore } from './view'

interface ChartProps {
  report: Report
  vantage: number
  onVantage: (index: number) => void
  open: string | null
  onToggle: (id: string) => void
  onClose: () => void
}

/** Whether this lane, seen from here, is the contradiction itself: through, and not allowed. */
const crosses = (l: Lane): boolean => l.loud && l.land === 'through' && l.berth === 'answers'

const SEEN: Record<ViewState, string> = {
  open: 'it gets through',
  some: 'it gets through for some senders',
  stopped: 'it is stopped',
  closed: 'it gets through, and nothing is listening',
  undecided: 'it is not decided',
}

export function Chart({ report, vantage, onVantage, open, onToggle, onClose }: ChartProps) {
  const rows = lanes(report, vantage)
  const from = report.vantages[vantage]
  const tool = report.frontend?.tool
  // Opening one lane closes another, which moves the page under the pointer. Keep the lane
  // that was pressed where it was.
  const held = useRef<{ id: string; top: number } | null>(null)
  useLayoutEffect(() => {
    const was = held.current
    held.current = null
    if (!was) return
    const now = document.getElementById(was.id)?.getBoundingClientRect().top
    if (now !== undefined && Math.abs(now - was.top) > 1) scrollBy(0, now - was.top)
  }, [open])
  const toggle = (id: string) => {
    const top = document.getElementById(id)?.getBoundingClientRect().top
    held.current = top === undefined ? null : { id, top }
    onToggle(id)
  }
  const close = (id: string) => {
    onClose()
    requestAnimationFrame(() => document.getElementById(id)?.querySelector<HTMLElement>('.lane')?.focus())
  }

  return (
    <section id="chart" class="chart" aria-labelledby="chart-h">
      <div class="wrap chart-head">
        <div>
          <h2 id="chart-h">The chart</h2>
          <p class="chart-how">Every port is a lane from open water to a service. The shoreline is the firewall. Select a lane to follow a packet through the rules.</p>
        </div>
        {report.vantages.length > 1 && (
          <div class="seen" role="group" aria-label="Seen from">
            <span class="k" aria-hidden="true">
              Seen from
            </span>
            <div class="seen-list">
              {report.vantages.map((v, i) => (
                <button type="button" key={v.id} aria-pressed={i === vantage} title={v.label} onClick={() => onVantage(i)}>
                  {v.short}
                </button>
              ))}
            </div>
          </div>
        )}
      </div>
      <div class={tool ? 'strip' : 'strip no-tool'}>
        <div class="heads" aria-hidden="true">
          <span class="bg-land" />
          <span class="h-shore" />
          <span class="h-sea">{from ? from.short : 'open water'}</span>
          <span class="h-host">{report.host || 'this machine'}</span>
          <span class="h h-port">Port</span>
          <span class="h h-svc">Service</span>
          {tool && <span class="h h-says">{tool} says</span>}
          <span class="h h-fact">In fact</span>
        </div>
        {rows.length > 0 ? (
          <ol class="lanes">
            {rows.map((l) => (
              <LaneRow key={l.id} l={l} report={report} vantage={vantage} open={open === l.id} onToggle={toggle} onClose={close} />
            ))}
          </ol>
        ) : (
          <div class="heads none">
            <span class="bg-land" />
            <span class="h-shore" />
            <p class="none-said">The report lists no ports.</p>
          </div>
        )}
      </div>
    </section>
  )
}

interface RowProps {
  l: Lane
  report: Report
  vantage: number
  open: boolean
  onToggle: (id: string) => void
  onClose: (id: string) => void
}

function LaneRow({ l, report, vantage, open, onToggle, onClose }: RowProps) {
  const p = l.port
  const tool = report.frontend?.tool
  const from = report.vantages[vantage]
  const names = ['row', `sea-${l.sea}`, `shore-${l.shore}`, `land-${l.land}`, `berth-${l.berth}`]
  if (l.loud) names.push('loud')
  if (crosses(l)) names.push('hot')
  if (l.breach) names.push('breach')
  if (open) names.push('open')
  return (
    <li id={l.id} class={names.join(' ')}>
      <span class="bg-land" aria-hidden="true" />
      {open && <span class="bg-shore" aria-hidden="true" />}
      <a
        class="lane"
        href={`#${l.id}`}
        aria-expanded={open}
        aria-controls={open ? `${l.id}-passage` : undefined}
        onClick={(e) => {
          // a new tab or window is the browser's business
          if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey || e.button !== 0) return
          e.preventDefault()
          onToggle(l.id)
        }}
        onKeyDown={(e) => {
          // it opens and closes something, so Space works as it does on a button
          if (e.key === ' ' && !e.metaKey && !e.ctrlKey && !e.altKey) {
            e.preventDefault()
            onToggle(l.id)
          } else if (e.key === 'Escape' && open) {
            e.preventDefault()
            onClose(l.id)
          }
        }}
      >
        <span class="c port">
          <span class="sr">Port </span>
          <i class="sounding">
            {p.port}
            <sub>{p.proto}</sub>
          </i>
        </span>
        <span class="c sea" aria-hidden="true">
          <span class="run" />
          {l.view?.note && l.sea !== 'none' && <i class="remark">{l.view.note}</i>}
        </span>
        <span class="c shore" aria-hidden="true">
          <span class="run" />
          <span class="coast" />
          <span class="ring" />
        </span>
        <span class="c quay" aria-hidden="true">
          <span class="run" />
          <span class="berth" />
        </span>
        <span class="c svc">
          <span class="k">Service</span>
          <span class="v">{p.service ?? <span class="nil">none named</span>}</span>
        </span>
        {tool && (
          <span class="c says">
            <span class="k">{tool} says</span>
            <span class="v">{p.stated ?? <span class="nil">nothing</span>}</span>
          </span>
        )}
        <span class="c fact">
          <span class="k">In fact</span>
          <span class="v">{p.reach ?? p.title}</span>
          {l.view && from && l.port.finding !== 'local' && (
            <span class="sr">
              {' '}
              Seen from {from.short}: {SEEN[l.view.state] ?? l.view.state}
              {l.view.note ? `, ${l.view.note}` : ''}.
            </span>
          )}
          {l.view?.note && l.sea !== 'none' && !(p.reach ?? '').includes(l.view.note) && (
            <i class="remark-m" aria-hidden="true">
              {l.view.note}
            </i>
          )}
          {l.remark && p.reach && (
            <span class="title">
              {l.loud && <b class="over">Exposed</b>}
              {p.title}
            </span>
          )}
        </span>
        <span class="c caret" aria-hidden="true" />
      </a>
      {open && <Passage report={report} port={p} id={l.id} vantage={vantage} hot={l.loud} onClose={() => onClose(l.id)} />}
    </li>
  )
}

/** The kinds of lane the legend can explain. */
export type SymbolKind = 'exposed' | 'reach' | 'some' | 'empty' | 'stopped' | 'undecided' | 'local'

const GLYPHS: Record<SymbolKind, { sea: Sea; shore: Shore; land: Land; berth: Berth; hot?: boolean }> = {
  exposed: { sea: 'through', shore: 'wall', land: 'through', berth: 'answers', hot: true },
  reach: { sea: 'through', shore: 'gate', land: 'through', berth: 'answers' },
  some: { sea: 'some', shore: 'part', land: 'through', berth: 'answers' },
  empty: { sea: 'through', shore: 'gate', land: 'through', berth: 'empty' },
  stopped: { sea: 'stopped', shore: 'wall', land: 'none', berth: 'answers' },
  undecided: { sea: 'undecided', shore: 'wall', land: 'none', berth: 'none' },
  local: { sea: 'none', shore: 'wall', land: 'stub', berth: 'answers' },
}

/** One lane in small, for the legend. Drawn by the same rules as the lanes of the chart. */
export function Glyph({ kind, plain }: { kind: SymbolKind; plain?: boolean }) {
  const g = GLYPHS[kind]
  const shore = plain ? 'plain' : g.shore
  return (
    <span class={`glyph sea-${g.sea} shore-${shore} land-${g.land} berth-${g.berth}${g.hot ? ' loud hot breach' : ''}`} aria-hidden="true">
      <span class="c sea">
        <span class="run" />
      </span>
      <span class="c shore">
        <span class="run" />
        <span class="coast" />
        <span class="ring" />
      </span>
      <span class="c quay">
        <span class="run" />
        <span class="berth" />
      </span>
    </span>
  )
}

/** The symbols in use on the chart as it is drawn now, each with what it means. */
export function symbolsFor(report: Report, vantage: number): { kind: SymbolKind; says: string }[] {
  const rows = lanes(report, vantage)
  const tool = report.frontend?.tool
  const out: { kind: SymbolKind; says: string }[] = []
  const add = (kind: SymbolKind, says: string, when: (l: Lane) => boolean) => {
    if (rows.some(when)) out.push({ kind, says })
  }
  const through = (l: Lane) => l.sea === 'through' && l.berth === 'answers'
  add('exposed', `Reachable, and ${tool ?? 'the firewall tool'} does not allow it`, (l) => crosses(l) && l.breach)
  add('reach', tool ? `Reachable, as ${tool} allows` : 'Reachable', (l) => through(l) && !(crosses(l) && l.breach))
  add('some', 'Reachable for some senders only', (l) => l.sea === 'some')
  add('empty', 'Let through, and nothing is listening', (l) => l.berth === 'empty')
  add('stopped', 'Stopped by the firewall', (l) => l.sea === 'stopped')
  add('undecided', 'Not decided', (l) => l.sea === 'undecided')
  add('local', 'Listens on this machine only', (l) => l.land === 'stub')
  return out
}
