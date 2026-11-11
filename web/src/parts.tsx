// The parts of the page around the chart: the masthead, the verdict with its title block, the
// fine print, the place for the visitor's own snapshot, and the footer.
import type { ComponentChildren, Ref } from 'preact'
import { useRef } from 'preact/hooks'
import type { OwnState, Source } from './app'
import { Glyph, symbolsFor } from './chart'
import type { Mode } from './theme'
import type { Report, Sample } from './types'
import { sentences } from './view'

const REPO = 'https://github.com/gallowforge/seaward'

/** The mark: one lane through a gap in the shoreline, ending at a berth. */
export function Mark() {
  return (
    <svg class="mark" viewBox="0 0 24 24" width="24" height="24" aria-hidden="true" focusable="false">
      <path d="M15.5 2v6.5M15.5 15.5V22" />
      <path d="M2 12h17" />
      <circle cx="20.25" cy="12" r="2.25" />
    </svg>
  )
}

const MODES: { mode: Mode; name: string; says: string }[] = [
  { mode: 'system', name: 'Auto', says: 'Follow the system' },
  { mode: 'light', name: 'Day', says: 'Day colours' },
  { mode: 'dark', name: 'Night', says: 'Night colours' },
]

export function Masthead({ mode, choose, charted }: { mode: Mode; choose: (m: Mode) => void; charted: boolean }) {
  return (
    <header class="mast">
      <div class="wrap mast-in">
        <a class="brand" href="#top" aria-label="Seaward, top of the page">
          <Mark />
          <span>Seaward</span>
        </a>
        <nav class="mast-nav" aria-label="On this page">
          {charted && <a href="#chart">Chart</a>}
          {charted && <a href="#fine-print">Fine print</a>}
          <a href="#own">Your own server</a>
          <a href={REPO}>GitHub</a>
        </nav>
        <div class="theme" role="group" aria-label="Colours">
          {MODES.map((m) => (
            <button type="button" key={m.mode} aria-pressed={mode === m.mode} title={m.says} onClick={() => choose(m.mode)}>
              {m.name}
            </button>
          ))}
        </div>
      </div>
    </header>
  )
}

interface VerdictProps {
  report: Report | null
  source: Source | null
  samples: Sample[]
  busy: boolean
  failed: string | null
  headRef: Ref<HTMLHeadingElement>
  onSample: (s: Sample) => void
}

export function Verdict({ report, source, samples, busy, failed, headRef, onSample }: VerdictProps) {
  const said = report ? sentences(report.headline) : []
  // when a port is exposed, every sentence after the first is the tool being contradicted
  const overprint = !!report && report.counts.exposed > 0
  return (
    <section class="verdict wrap" aria-labelledby="verdict-h">
      <div class="verdict-main">
        <div aria-live="polite">
          <h1 id="verdict-h" ref={headRef} tabIndex={-1} class={report ? '' : 'waiting'}>
            {report
              ? said.map((s, i) => (
                  <span key={i} class={i > 0 && overprint ? 'said over' : 'said'}>
                    {s}{' '}
                  </span>
                ))
              : failed
                ? 'The sample could not be read.'
                : 'Reading the rules…'}
          </h1>
          {report?.detail && <p class="detail">{report.detail}</p>}
        </div>
        {failed && (
          <p class="failed" role="alert">
            {failed}
          </p>
        )}
        {!report && failed && (
          <p class="failed-more">
            The command does the same work without a browser: <code>sudo seaward scan</code>
          </p>
        )}
        {samples.length > 0 && (
          <div class="picker">
            <span class="k" id="picker-k">
              {source?.kind === 'file' ? 'Your file' : 'Sample'}
            </span>
            <div class="picker-body">
              {source?.kind === 'file' && (
                <p class="picker-file">
                  <code>{source.name}</code>, read in this page. Nothing was sent anywhere.
                </p>
              )}
              <div class="picker-list" role="group" aria-label={source?.kind === 'file' ? 'Go back to a sample' : 'Sample'}>
                {source?.kind === 'file' && <span class="picker-back">Back to a sample:</span>}
                {samples.map((s) => (
                  <button type="button" key={s.id} aria-pressed={source?.kind === 'sample' && source.sample.id === s.id} onClick={() => onSample(s)}>
                    {s.title}
                  </button>
                ))}
              </div>
              {source?.kind === 'sample' && <p class="picker-note">{source.sample.description}</p>}
              {source?.kind !== 'file' && (
                <a class="picker-own" href="#own">
                  Read your own server instead
                </a>
              )}
              {busy && report && (
                <span class="picker-busy" role="status">
                  Reading the rules…
                </span>
              )}
            </div>
          </div>
        )}
      </div>
      {report && <Cartouche report={report} />}
    </section>
  )
}

/** The chart's title block: what was charted, seen from where, and the limit of the survey. */
function Cartouche({ report }: { report: Report }) {
  const c = report.counts
  const figures: { n: number; of: string; over?: boolean }[] = [
    { n: report.ports.length, of: report.ports.length === 1 ? 'port' : 'ports' },
    { n: c.reachable, of: 'reachable' },
    { n: c.exposed, of: 'exposed', over: c.exposed > 0 },
    { n: c.stopped, of: 'stopped' },
    { n: c.quiet, of: 'quiet' },
    { n: c.undecided, of: 'undecided' },
  ]
  return (
    <section class="cartouche" aria-label="About this chart">
      <p class="cart-over">Approaches to</p>
      <p class="cart-host">{report.host || 'this machine'}</p>
      <dl class="cart-facts">
        <div>
          <dt>Seen from</dt>
          <dd class="of-sea">
            {report.vantages.length === 0 ? <span>no outside network interface</span> : report.vantages.map((v) => <span key={v.id}>{v.label}</span>)}
          </dd>
        </div>
        <div>
          <dt>Firewall tool</dt>
          <dd>{report.frontend ? `${report.frontend.tool}, default ${report.frontend.default}` : 'none reported'}</dd>
        </div>
      </dl>
      <dl class="cart-figures">
        {figures.map((f) => (
          <div key={f.of} class={f.over ? 'over' : ''}>
            <dt>{f.of}</dt>
            <dd>{f.n}</dd>
          </div>
        ))}
      </dl>
      <p class="cart-caveat">{report.caveat}</p>
    </section>
  )
}

/** The margin of the chart: its caution, the tool's own list, the symbols, and what was not asked, not read or not followed. */
export function FinePrint({ report, vantage }: { report: Report; vantage: number }) {
  const f = report.frontend
  const unread = report.unread ?? []
  const unfollowed = report.unfollowed ?? []
  const partial = report.partial ?? []
  const notes = report.notes ?? []
  const symbols = symbolsFor(report, vantage)
  return (
    <section id="fine-print" class="fine wrap" aria-labelledby="fine-h">
      <h2 id="fine-h" class="sr">
        Fine print
      </h2>
      {/* a scan that stopped at a ceiling comes first: every "nobody" on the chart is short of what was not asked */}
      {partial.length > 0 && (
        <div class="unread partial" role="note">
          <h3>Not asked</h3>
          <p>The scan stopped at a ceiling. What lies beyond it is not on the chart, so the chart rules nothing out.</p>
          <ul>
            {partial.map((u) => (
              <li key={u}>{u}</li>
            ))}
          </ul>
        </div>
      )}
      {unread.length > 0 && (
        <div class="unread" role="note">
          <h3>Could not be read</h3>
          <p>{unread.length === 1 ? 'This rule source exists on the machine and could not be read. What it holds is not on the chart.' : 'These rule sources exist on the machine and could not be read. What they hold is not on the chart.'}</p>
          <ul>
            {unread.map((u) => (
              <li key={u}>{u}</li>
            ))}
          </ul>
        </div>
      )}
      {unfollowed.length > 0 && (
        <div class="unfollowed" role="note">
          <h3>Not followed</h3>
          <p>{unfollowed.length === 1 ? 'This chain acts on packets outside the path Seaward follows. What it does to them is not on the chart.' : 'These chains act on packets outside the path Seaward follows. What they do to them is not on the chart.'}</p>
          <ul>
            {unfollowed.map((u) => (
              <li key={u}>{u}</li>
            ))}
          </ul>
        </div>
      )}
      <div class="fine-cols">
        <Note title="Caution">
          <p class="caution">{report.caveat}</p>
        </Note>
        <Note title={f ? `${f.tool}'s own list` : 'Firewall tool'}>
          {f ? (
            <>
              <p>
                Default: <b>{f.default}</b>. {f.allows.length === 0 ? 'It allows nothing by name.' : 'It allows:'}
              </p>
              {f.allows.length > 0 && (
                <ul class="allows">
                  {f.allows.map((a) => (
                    <li key={a}>{a}</li>
                  ))}
                </ul>
              )}
            </>
          ) : (
            <p>The report names none, so there is no list to compare the rules with.</p>
          )}
        </Note>
        {symbols.length > 0 && (
          <Note title="Symbols">
            <ul class="symbols">
              {symbols.map((s) => (
                <li key={s.kind}>
                  <Glyph kind={s.kind} plain={!f} />
                  <span>{s.says}</span>
                </li>
              ))}
            </ul>
          </Note>
        )}
        {notes.length > 0 && (
          <Note title="Notes">
            <ul class="notes">
              {notes.map((n) => (
                <li key={n}>{n}</li>
              ))}
            </ul>
          </Note>
        )}
      </div>
    </section>
  )
}

function Note({ title, children }: { title: string; children: ComponentChildren }) {
  return (
    <div class="note">
      <h3>{title}</h3>
      {children}
    </div>
  )
}

const COMMANDS: { run: string; does: string }[] = [
  { run: 'sudo seaward scan', does: 'The report for the machine it runs on.' },
  { run: 'sudo seaward why 5432', does: 'Follows a packet to one port, rule by rule.' },
  { run: 'sudo seaward scan --check', does: 'Exits with status 3 when anything is exposed, for CI.' },
]

export function Own({ state, dragging, onFile }: { state: OwnState; dragging: boolean; onFile: (f: File) => void }) {
  const input = useRef<HTMLInputElement>(null)
  return (
    <section id="own" class="own wrap" aria-labelledby="own-h">
      <h2 id="own-h">Your own server</h2>
      <div class="own-cols">
        <div class={dragging ? 'drop over' : 'drop'}>
          <p class="drop-how">
            Run <code class="cmd">sudo seaward snapshot -o server.snapshot</code> on the server, then drop the file here. It is read in this page and never leaves your browser.
          </p>
          <label class="file">
            <input
              ref={input}
              type="file"
              onChange={(e) => {
                const file = e.currentTarget.files?.[0]
                // cleared so that choosing the same file again is still a change
                e.currentTarget.value = ''
                if (file) onFile(file)
              }}
            />
            <span>Choose the snapshot file</span>
          </label>
          <div class="drop-state" role="status">
            {state.at === 'reading' && (
              <p>
                Reading <code>{state.name}</code>…
              </p>
            )}
            {state.at === 'read' && (
              <p>
                The page now shows <code>{state.name}</code>. <a href="#top">See the verdict</a>
              </p>
            )}
          </div>
          {state.at === 'refused' && (
            <div class="refused" role="alert">
              <p>
                <code>{state.name}</code> was not read. The engine says:
              </p>
              <pre>{state.error}</pre>
            </div>
          )}
        </div>
        <div class="cmds">
          <h3>On the server</h3>
          <dl>
            {COMMANDS.map((c) => (
              <div key={c.run}>
                <dt>
                  <code class="cmd">{c.run}</code>
                </dt>
                <dd>{c.does}</dd>
              </div>
            ))}
          </dl>
          <p class="cmds-note">Seaward only reads. It changes no rule and sends no packet.</p>
        </div>
      </div>
    </section>
  )
}

export function Footer({ version }: { version: string }) {
  return (
    <footer class="foot">
      <div class="wrap foot-in">
        <p class="foot-brand">
          <Mark />
          <span>Seaward{version ? ` ${version}` : ''}</span>
        </p>
        <p>
          <a href={REPO}>github.com/gallowforge/seaward</a>
        </p>
        <p>MIT licence</p>
        <p class="foot-note">The engine on this page is the command's own code, compiled to WebAssembly. Set in Instrument Sans and Spline Sans Mono.</p>
      </div>
    </footer>
  )
}
