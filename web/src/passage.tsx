// The passage: one lane opened up. Each packet the engine followed is drawn as its own lane,
// step by step through the rules, with the same steps written out under it.
import { useLayoutEffect, useRef } from 'preact/hooks'
import type { Cell, Port, Report } from './types'
import { classWords, contradicts, endOf, hookName, packetGroups, passage, place, type HookGroup, type StepRow } from './view'

interface PassageProps {
  report: Report
  port: Port
  /** The lane's address on the page: "tcp-5432". */
  id: string
  vantage: number
  /** The port is exposed. */
  hot: boolean
  onClose: () => void
}

/**
 * Times each mark to the moment the drawn line reaches it, and lets a rule that is wider than
 * its box be scrolled from the keyboard. The page reads the same without either.
 */
function settle(root: HTMLElement | null): void {
  if (!root) return
  for (const packet of root.querySelectorAll<HTMLElement>('.packet')) {
    const way = packet.querySelector<HTMLElement>('.way')
    if (!way) continue
    const box = way.getBoundingClientRect()
    if (box.width <= 0) continue
    for (const mark of way.querySelectorAll<HTMLElement>('[data-n]')) {
      const m = mark.getBoundingClientRect()
      const at = Math.min(1, Math.max(0, (m.left + m.width / 2 - box.left) / box.width)).toFixed(3)
      mark.style.setProperty('--at', at)
      packet.querySelector<HTMLElement>(`.step[data-n="${mark.dataset.n}"]`)?.style.setProperty('--at', at)
    }
  }
  // a rule wider than its box can be reached and scrolled with the keys, and says what it is
  for (const rule of root.querySelectorAll<HTMLElement>('.rule')) {
    if (rule.scrollWidth > rule.clientWidth + 1) {
      rule.tabIndex = 0
      rule.setAttribute('role', 'group')
      rule.setAttribute('aria-label', `The rule at step ${rule.dataset.n ?? ''}, which scrolls sideways`)
    } else {
      rule.removeAttribute('tabindex')
      rule.removeAttribute('role')
      rule.removeAttribute('aria-label')
    }
  }
}

export function Passage({ report, port, id, vantage, hot, onClose }: PassageProps) {
  const groups = packetGroups(report, port, vantage)
  const tool = report.frontend?.tool
  const root = useRef<HTMLDivElement>(null)
  useLayoutEffect(() => settle(root.current), [report, id, vantage])
  // said once: the port's own reason goes at the top unless a packet below gives the same one
  const repeated = !!port.why && (groups[0]?.cells.some((c) => c.why === port.why) ?? false)
  return (
    <div
      class={hot ? 'passage hot' : 'passage'}
      id={`${id}-passage`}
      ref={root}
      role="region"
      aria-label={`The passage to ${port.proto} port ${port.port}`}
      onKeyDown={(e) => {
        if (e.key !== 'Escape') return
        e.stopPropagation()
        onClose()
      }}
    >
      <header class="pass-head">
        <div class="pass-what">
          <p class="k">The passage to</p>
          <h3>
            <i class="sounding">
              {port.port}
              <sub>{port.proto}</sub>
            </i>
            {port.service && <span class="pass-svc">{port.service}</span>}
          </h3>
        </div>
        <div class="pass-acts">
          <span class="pass-addr" title="The address of this lane">
            <span class="sr">Address of this lane: </span>#{id}
          </span>
          <button type="button" class="close" onClick={onClose}>
            <span class="close-x" aria-hidden="true" />
            Close
          </button>
        </div>
      </header>
      {port.why && !repeated && <p class="pass-why">{port.why}</p>}
      {groups.length === 0 && <p class="pass-none">The report follows no packet to this port.</p>}
      {groups.map((g, i) => {
        const name = g.vantage?.label ?? g.id
        const count = `${g.cells.length} ${g.cells.length === 1 ? 'packet' : 'packets'}`
        const packets = g.cells.map((c, n) => <Packet key={n} cell={c} tool={tool} />)
        return i === 0 ? (
          <section class="from" key={g.id}>
            <h4 class="from-h">
              <span class="k">Sent from</span> <i>{name}</i> <span class="from-n">{count}</span>
            </h4>
            {packets}
          </section>
        ) : (
          <details class="from" key={g.id} onToggle={() => settle(root.current)}>
            <summary class="from-h">
              <span class="k">Sent from</span> <i>{name}</i> <span class="from-n">{count}</span>
            </summary>
            {packets}
          </details>
        )
      })}
    </div>
  )
}

function Packet({ cell, tool }: { cell: Cell; tool: string | undefined }) {
  const hooks = passage(cell)
  const total = cell.steps.length
  const bad = contradicts(cell)
  const end = endOf(cell)
  // the whole passage is drawn in well under a second, however many steps it has
  const dur = Math.max(260, Math.min(640, total * 80))
  return (
    <article class={`packet end-${end}${bad ? ' bad' : ''}`} style={{ '--dur': `${dur}ms` }}>
      <h5 class="packet-h">
        From <i>{cell.from}</i> <span class="addr">({cell.src})</span> to <span class="addr">{cell.dst}</span>
        <span class="fam">{cell.ipv6 ? 'IPv6' : 'IPv4'}</span>
      </h5>
      <Track hooks={hooks} total={total} word={cell.class} />
      <div class="packet-body">
        <div class="packet-say">
          <p class="why">{cell.why}</p>
          <dl class="ends">
            <div>
              <dt>It ends</dt>
              <dd>
                <b>{cell.class}</b>
                {classWords(cell.class) && <span>: {classWords(cell.class)}</span>}
              </dd>
            </div>
            {cell.allowed !== undefined && (
              <div class={bad ? 'over' : ''}>
                <dt>{tool ?? 'The tool'} says</dt>
                <dd>
                  <b>{cell.allowed ? 'allowed' : 'not allowed'}</b>
                </dd>
              </div>
            )}
            {cell.possible && cell.possible.length > 0 && (
              <div>
                <dt>It could end</dt>
                <dd>{cell.possible.join(', or ')}</dd>
              </div>
            )}
            {cell.unknowns && cell.unknowns.length > 0 && (
              <div>
                <dt>It hangs on</dt>
                <dd>
                  <ul>
                    {cell.unknowns.map((u) => (
                      <li key={u}>{u}</li>
                    ))}
                  </ul>
                </dd>
              </div>
            )}
          </dl>
        </div>
        <ol class="hooks">
          {hooks.map((h, i) => {
            const name = hookName(h.hook)
            return (
              <li class="hook" key={i}>
                <p class="hook-h">
                  <b>{name.name}</b>
                  {name.plain && <span>{name.plain}</span>}
                </p>
                <ol class="steps" start={h.rows[0]?.n ?? 1}>
                  {h.rows.map((r) => (
                    <StepItem key={r.n} r={r} total={total} />
                  ))}
                </ol>
              </li>
            )
          })}
        </ol>
      </div>
    </article>
  )
}

const marks = (r: StepRow): string[] => {
  const out: string[] = []
  if (r.rewrite) out.push('Rewrites the destination')
  if (r.decisive) out.push('Settles it')
  else if (r.deciding) out.push('The deciding rule')
  return out
}

const markClass = (r: StepRow): string => `${r.quiet ? ' quiet' : ''}${r.rewrite ? ' rewrite' : ''}${r.deciding ? ' deciding' : ''}${r.decisive ? ' decisive' : ''}`

/** Where a mark sits along the drawn line before the page has been measured: evenly spaced. */
const at = (n: number, total: number): string => ((n - 0.5) / (total + 1)).toFixed(3)

function StepItem({ r, total }: { r: StepRow; total: number }) {
  const where = place(r.step)
  return (
    <li class={`step${markClass(r)}`} data-n={r.n} style={{ '--at': at(r.n, total) }}>
      <span class={`num${markClass(r)}`} aria-hidden="true">
        <b>{r.n}</b>
      </span>
      <div class="step-main">
        <p class="step-line">
          <span class="effect">{r.step.effect}</span>
          {where && <span class="place">{where}</span>}
          {marks(r).map((m) => (
            <span class="tag" key={m}>
              {m}
            </span>
          ))}
        </p>
        {r.step.rule && (
          <pre class="rule" data-n={r.n}>
            <code>{r.step.rule}</code>
          </pre>
        )}
      </div>
    </li>
  )
}

/** The packet's own lane: every step a numbered mark on the line, in the order it was met. */
function Track({ hooks, total, word }: { hooks: HookGroup[]; total: number; word: string }) {
  return (
    <div class="track" aria-hidden="true">
      <div class="way">
        <span class="t-line" />
        {hooks.map((h, i) => (
          <span class="t-hook" key={i}>
            <span class="t-nodes">
              {h.rows.map((r) => (
                <span class={`node${markClass(r)}`} key={r.n} data-n={r.n} style={{ '--at': at(r.n, total) }}>
                  <b>{r.n}</b>
                </span>
              ))}
            </span>
            <span class="t-name">{hookName(h.hook).name}</span>
          </span>
        ))}
        <span class="t-end" data-n={total + 1} style={{ '--at': '1' }}>
          <span class="t-glyph" />
        </span>
      </div>
      <span class="t-word">{word}</span>
    </div>
  )
}
