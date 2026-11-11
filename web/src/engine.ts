// The page's door to the engine: the real Seaward engine, compiled to WebAssembly
// (cmd/seaward-wasm) and running in this tab. Both files sit beside the page, and the
// snapshot never leaves it: there is no server to send anything to.
import type { Report } from './types'
import { readAnswer } from './view'

interface GoRuntime {
  importObject: WebAssembly.Imports
  run(instance: WebAssembly.Instance): Promise<void>
}

declare global {
  /** Go's loader, wasm_exec.js. */
  var Go: (new () => GoRuntime) | undefined
  /** Set by the engine when it has started: snapshot text in, one JSON answer out. */
  var seawardScan: ((snapshot: string) => string) | undefined
  /** Called by the engine once, when seawardScan is there. */
  var seawardReady: (() => void) | undefined
}

const beside = (file: string) => new URL(file, document.baseURI).href

function script(src: string): Promise<void> {
  return new Promise((done, fail) => {
    const s = document.createElement('script')
    s.src = src
    s.onload = () => done()
    s.onerror = () => fail(new Error('wasm_exec.js, the loader for the engine, did not load.'))
    document.head.append(s)
  })
}

async function instantiate(url: string, imports: WebAssembly.Imports): Promise<WebAssembly.Instance> {
  // compiling while it downloads needs the host to name the type; any other host gets the plain way
  if (typeof WebAssembly.instantiateStreaming === 'function') {
    try {
      return (await WebAssembly.instantiateStreaming(fetch(url), imports)).instance
    } catch {
      /* fall through */
    }
  }
  const r = await fetch(url)
  if (!r.ok) throw new Error(`seaward.wasm, the engine, did not load (HTTP ${r.status}).`)
  return (await WebAssembly.instantiate(await r.arrayBuffer(), imports)).instance
}

async function start(): Promise<(snapshot: string) => string> {
  if (globalThis.seawardScan) return globalThis.seawardScan
  if (typeof WebAssembly !== 'object') throw new Error('This browser has no WebAssembly, which the engine runs on.')
  if (!globalThis.Go) await script(beside('wasm_exec.js'))
  if (!globalThis.Go) throw new Error('wasm_exec.js loaded and did not define the loader.')
  const go = new globalThis.Go()
  const up = new Promise<'up'>((done) => {
    globalThis.seawardReady = () => done('up')
  })
  const instance = await instantiate(beside('seaward.wasm'), go.importObject)
  // run() resolves when the program exits, and this one stays loaded for as long as the page is open
  const gone = go.run(instance).then(
    () => 'gone' as const,
    () => 'gone' as const,
  )
  let timer: ReturnType<typeof setTimeout> | undefined
  const late = new Promise<'late'>((done) => {
    timer = setTimeout(() => done('late'), 20000)
  })
  const how = await Promise.race([up, gone, late])
  clearTimeout(timer)
  if (how === 'gone') throw new Error('The engine stopped before it was ready.')
  if (!globalThis.seawardScan) throw new Error('The engine did not start.')
  return globalThis.seawardScan
}

let engine: Promise<(snapshot: string) => string> | undefined

/** One start that worked is kept; one that failed is forgotten, so the next request tries again. */
function started(): Promise<(snapshot: string) => string> {
  engine ??= start().catch((e: unknown) => {
    engine = undefined
    throw e
  })
  return engine
}

/** Downloads and starts the engine, once. */
export function ready(): Promise<void> {
  return started().then(() => undefined)
}

export type Scan = { ok: true; report: Report; version: string } | { ok: false; error: string; version: string }

/** Reads one snapshot. The engine's own error text comes back as it is. */
export async function scan(snapshot: string): Promise<Scan> {
  const run = await started()
  return readAnswer(run(snapshot))
}
