import { useCallback, useEffect, useRef, useState } from 'preact/hooks'
import { Chart } from './chart'
import { ready, scan } from './engine'
import { FinePrint, Footer, Masthead, Own, Verdict } from './parts'
import { portFromHash, useOpenLane } from './route'
import { loadIndex, loadSnapshot } from './samples'
import { useTheme } from './theme'
import type { Report, Sample } from './types'
import { portId } from './view'

/** Where the report on the page came from. */
export type Source = { kind: 'sample'; sample: Sample } | { kind: 'file'; name: string }

/** What became of the visitor's own file. */
export type OwnState = { at: 'idle' } | { at: 'reading'; name: string } | { at: 'read'; name: string } | { at: 'refused'; name: string; error: string }

interface Shown {
  report: Report
  source: Source
}

/** A snapshot is text, a few hundred kilobytes at most. Anything this large is some other file. */
const LARGEST = 8 * 1024 * 1024

const said = (e: unknown): string => (e instanceof Error && e.message ? e.message : 'Something went wrong, and the browser gave no reason.')

/** Lets the page paint what it has just been told before the engine takes the thread. */
const breath = () => new Promise<void>((done) => setTimeout(done, 30))

export function App() {
  const [mode, choose] = useTheme()
  const lane = useOpenLane()
  const [samples, setSamples] = useState<Sample[]>([])
  const [shown, setShown] = useState<Shown | null>(null)
  const [failed, setFailed] = useState<string | null>(null)
  const [busy, setBusy] = useState(true)
  const [version, setVersion] = useState('')
  const [vantage, setVantage] = useState(0)
  const [own, setOwn] = useState<OwnState>({ at: 'idle' })
  // the newest request wins: an answer that comes back late is dropped
  const turn = useRef(0)
  // the visitor's own file has its own count: it takes the page only once the engine has read it,
  // so a file that is refused leaves whatever was shown, or on its way, alone
  const fileTurn = useRef(0)
  const top = useRef<HTMLHeadingElement>(null)

  const openSample = useCallback(async (sample: Sample, first: boolean) => {
    const mine = ++turn.current
    if (!first) {
      // a sample asked for while a file is still being read: the sample is the newer wish
      fileTurn.current++
      setOwn((o) => (o.at === 'reading' ? { at: 'idle' } : o))
    }
    setBusy(true)
    setFailed(null)
    try {
      const [text] = await Promise.all([loadSnapshot(sample), ready()])
      await breath()
      const answer = await scan(text)
      if (mine !== turn.current) return
      if (answer.version) setVersion(answer.version)
      if (!answer.ok) {
        setFailed(answer.error)
        return
      }
      if (!first) lane.go(null)
      setShown({ report: answer.report, source: { kind: 'sample', sample } })
      setVantage(0)
      // the page no longer shows the visitor's file; a refusal stays said until the next file
      setOwn((o) => (o.at === 'read' ? { at: 'idle' } : o))
    } catch (e) {
      if (mine === turn.current) setFailed(said(e))
    } finally {
      if (mine === turn.current) setBusy(false)
    }
  }, [])

  const openFile = useCallback(async (file: File) => {
    const mine = ++fileTurn.current
    setOwn({ at: 'reading', name: file.name })
    try {
      if (file.size > LARGEST) throw new Error(`This file is ${Math.round(file.size / 1024 / 1024)} MB. A snapshot is a text file, far smaller than that.`)
      const text = await file.text()
      await ready()
      await breath()
      const answer = await scan(text)
      if (mine !== fileTurn.current) return
      if (answer.version) setVersion(answer.version)
      if (!answer.ok) {
        setOwn({ at: 'refused', name: file.name, error: answer.error })
        return
      }
      // read: now it is the newest thing asked for, and a sample still on its way is dropped
      turn.current++
      setBusy(false)
      lane.go(null)
      setFailed(null)
      setShown({ report: answer.report, source: { kind: 'file', name: file.name } })
      setVantage(0)
      setOwn({ at: 'read', name: file.name })
      // the verdict is the answer: go to it, and tell a screen reader it changed
      requestAnimationFrame(() => {
        scrollTo({ top: 0 })
        top.current?.focus({ preventScroll: true })
      })
    } catch (e) {
      if (mine === fileTurn.current) setOwn({ at: 'refused', name: file.name, error: said(e) })
    }
  }, [])

  // on opening: the list of samples, the engine, and the first sample through it
  useEffect(() => {
    let live = true
    ready().catch(() => undefined)
    loadIndex().then(
      (list) => {
        if (!live) return
        setSamples(list)
        // a file dropped and read before the list came already has the page
        if (turn.current === 0) void openSample(list[0]!, true)
      },
      (e) => {
        if (!live) return
        if (turn.current === 0) setFailed(said(e))
        setBusy(false)
      },
    )
    return () => {
      live = false
    }
  }, [])

  // a file dropped anywhere on the page is read; without this the browser would leave the page for it
  const [dragging, setDragging] = useState(false)
  useEffect(() => {
    let depth = 0
    const files = (e: DragEvent) => Array.from(e.dataTransfer?.types ?? []).includes('Files')
    const over = (e: DragEvent) => {
      if (files(e)) e.preventDefault()
    }
    const enter = (e: DragEvent) => {
      if (!files(e)) return
      depth++
      setDragging(true)
    }
    const leave = (e: DragEvent) => {
      if (!files(e)) return
      depth = Math.max(0, depth - 1)
      if (depth === 0) setDragging(false)
    }
    const drop = (e: DragEvent) => {
      if (!files(e)) return
      e.preventDefault()
      depth = 0
      setDragging(false)
      const file = e.dataTransfer?.files[0]
      if (file) void openFile(file)
    }
    addEventListener('dragover', over)
    addEventListener('dragenter', enter)
    addEventListener('dragleave', leave)
    addEventListener('drop', drop)
    return () => {
      removeEventListener('dragover', over)
      removeEventListener('dragenter', enter)
      removeEventListener('dragleave', leave)
      removeEventListener('drop', drop)
    }
  }, [])

  const report = shown?.report ?? null
  const open = report && lane.open && report.ports.some((p) => portId(p) === lane.open) ? lane.open : null
  const seenFrom = report ? Math.min(vantage, Math.max(0, report.vantages.length - 1)) : 0

  // arriving by address (a link, back and forward, the first report): bring the lane into view
  const arrived = useRef(-1)
  useEffect(() => {
    if (!report || !open || arrived.current === lane.fromLink) return
    arrived.current = lane.fromLink
    // only when the address names the lane: at a part of the page ("#chart") the place is kept
    if (portFromHash(location.hash) === open) document.getElementById(open)?.scrollIntoView({ block: 'start' })
  }, [report, open, lane.fromLink])
  useEffect(() => {
    if (report && !open) arrived.current = lane.fromLink
  }, [report, open, lane.fromLink])

  const toggle = (id: string) => {
    arrived.current = lane.fromLink
    lane.go(open === id ? null : id)
  }

  return (
    <>
      <a class="skip" href={report ? '#chart' : '#own'}>
        {report ? 'Skip to the chart' : 'Skip to your own server'}
      </a>
      <Masthead mode={mode} choose={choose} charted={!!report} />
      <main id="top">
        <Verdict
          report={report}
          source={shown?.source ?? null}
          samples={samples}
          busy={busy}
          failed={failed}
          headRef={top}
          onSample={(s) => void openSample(s, false)}
        />
        {report && <Chart report={report} vantage={seenFrom} onVantage={setVantage} open={open} onToggle={toggle} onClose={() => lane.go(null)} />}
        {report && <FinePrint report={report} vantage={seenFrom} />}
        <Own state={own} dragging={dragging} onFile={(f) => void openFile(f)} />
      </main>
      <Footer version={version} />
    </>
  )
}
