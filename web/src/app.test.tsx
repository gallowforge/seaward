// The whole page with the engine and the sample files stood in for: what is on the page when a
// sample, a visitor's file and a second sample cross each other on the way.
import { render } from 'preact'
import { act } from 'preact/test-utils'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { App } from './app'
import { ready, scan } from './engine'
import type { Scan } from './engine'
import { loadIndex, loadSnapshot } from './samples'
import { noTool } from './testdata/cases'
import shop from './testdata/shop-1.report.json'
import type { Report, Sample } from './types'

vi.mock('./engine', () => ({ ready: vi.fn(), scan: vi.fn() }))
vi.mock('./samples', () => ({ loadIndex: vi.fn(), loadSnapshot: vi.fn() }))

const shopReport = shop as unknown as Report
const LIST: Sample[] = [
  { id: 'shop-1', file: 'shop-1.snapshot', title: 'shop-1', description: 'A shop server.' },
  { id: 'edge-2', file: 'edge-2.snapshot', title: 'edge-2', description: 'A gateway.' },
]
const REFUSAL = 'snapshot: this is not a Seaward snapshot'

/** A promise the test settles when it chooses, to hold one answer back. */
function held<T>() {
  let give!: (value: T) => void
  const wait = new Promise<T>((done) => {
    give = done
  })
  return { wait, give }
}

let host: HTMLElement
const head = () => host.querySelector('h1')!.textContent!.trim()
const own = () => host.querySelector('#own')!
/** Long enough for the page's pause before the engine, and for what follows it. */
const pass = (ms = 80) => act(() => new Promise<void>((done) => setTimeout(done, ms)))
/** Gives the file input a file, as choosing one does. */
const choose = (name: string, text: string) =>
  act(() => {
    const input = host.querySelector<HTMLInputElement>('#own input[type=file]')!
    Object.defineProperty(input, 'files', { configurable: true, value: [{ name, size: text.length, text: () => Promise.resolve(text) }] })
    input.dispatchEvent(new Event('change', { bubbles: true }))
  })
const sampleButton = (title: string) => [...host.querySelectorAll<HTMLButtonElement>('.picker-list button')].find((b) => b.textContent === title)!

beforeEach(() => {
  history.replaceState(null, '', '/')
  vi.stubGlobal('matchMedia', () => ({ matches: false, addEventListener: () => undefined, removeEventListener: () => undefined }))
  vi.stubGlobal('scrollTo', () => undefined)
  vi.mocked(ready).mockResolvedValue(undefined)
  vi.mocked(loadIndex).mockResolvedValue(LIST)
  // the stand-in engine: the snapshot text says which answer it gives
  vi.mocked(scan).mockImplementation(async (text: string): Promise<Scan> => {
    if (text === 'shop') return { ok: true, report: shopReport, version: '0.1.0' }
    if (text === 'edge') return { ok: true, report: noTool, version: '0.1.0' }
    return { ok: false, error: REFUSAL, version: '0.1.0' }
  })
  host = document.createElement('div')
  document.body.append(host)
})
afterEach(() => {
  render(null, host)
  host.remove()
  vi.unstubAllGlobals()
  vi.resetAllMocks()
})

describe('the page, while answers are on their way', () => {
  it('loads the first sample on opening, and names the engine in the footer', async () => {
    vi.mocked(loadSnapshot).mockResolvedValue('shop')
    await act(() => render(<App />, host))
    expect(head()).toBe('Reading the rules…')
    await pass()
    expect(head()).toBe(shopReport.headline)
    expect(sampleButton('shop-1').getAttribute('aria-pressed')).toBe('true')
    expect(host.querySelector('footer')!.textContent).toContain('0.1.0')
    expect(host.querySelector('.skip')!.getAttribute('href')).toBe('#chart')
  })

  it('still shows the first sample when a file is refused before the sample has arrived', async () => {
    const slow = held<string>()
    vi.mocked(loadSnapshot).mockReturnValue(slow.wait)
    await act(() => render(<App />, host))
    await pass()
    await choose('notes.txt', 'not a snapshot')
    await pass()
    expect(own().querySelector('[role=alert]')!.textContent).toContain(REFUSAL)
    expect(head()).toBe('Reading the rules…')
    // with no chart yet, nothing links to one
    expect(host.querySelector('.skip')!.getAttribute('href')).toBe('#own')
    slow.give('shop')
    await pass()
    expect(head()).toBe(shopReport.headline)
    // the refusal stays said: it is about the visitor's file, not about the sample
    expect(own().querySelector('[role=alert]')!.textContent).toContain('notes.txt was not read.')
  })

  it('keeps a file that was read when the first sample arrives after it', async () => {
    const slow = held<string>()
    vi.mocked(loadSnapshot).mockReturnValue(slow.wait)
    await act(() => render(<App />, host))
    await pass()
    await choose('server.snapshot', 'edge')
    await pass()
    expect(head()).toBe(noTool.headline)
    expect(host.querySelector('.picker-file')!.textContent).toContain('server.snapshot')
    slow.give('shop')
    await pass()
    expect(head()).toBe(noTool.headline)
    expect(own().querySelector('.drop-state')!.textContent).toContain('The page now shows server.snapshot.')
    expect(host.querySelector('.picker-busy')).toBeNull()
  })

  it('drops a file still being read when a sample is asked for, and does not go on saying it is reading', async () => {
    vi.mocked(loadSnapshot).mockImplementation(async (s) => (s.id === 'edge-2' ? 'edge' : 'shop'))
    await act(() => render(<App />, host))
    await pass()
    const text = held<string>()
    await act(() => {
      const input = host.querySelector<HTMLInputElement>('#own input[type=file]')!
      Object.defineProperty(input, 'files', { configurable: true, value: [{ name: 'server.snapshot', size: 4, text: () => text.wait }] })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })
    expect(own().querySelector('.drop-state')!.textContent).toContain('Reading server.snapshot')
    await act(() => sampleButton('edge-2').click())
    await pass()
    expect(head()).toBe(noTool.headline)
    expect(own().querySelector('.drop-state')!.textContent).toBe('')
    text.give('shop')
    await pass()
    expect(head()).toBe(noTool.headline)
    expect(sampleButton('edge-2').getAttribute('aria-pressed')).toBe('true')
    expect(own().querySelector('.drop-state')!.textContent).toBe('')
  })

  it('says so when the list of samples does not load, and still reads a file', async () => {
    vi.mocked(loadIndex).mockRejectedValue(new Error('The list of samples did not load (HTTP 404).'))
    await act(() => render(<App />, host))
    await pass()
    expect(head()).toBe('The sample could not be read.')
    expect(host.querySelector('.verdict [role=alert]')!.textContent).toBe('The list of samples did not load (HTTP 404).')
    await choose('server.snapshot', 'shop')
    await pass()
    expect(head()).toBe(shopReport.headline)
    expect(host.querySelector('.verdict [role=alert]')).toBeNull()
  })

  it('refuses a file far too large to be a snapshot without reading it', async () => {
    vi.mocked(loadSnapshot).mockResolvedValue('shop')
    await act(() => render(<App />, host))
    await pass()
    const read = vi.fn(() => Promise.resolve('shop'))
    await act(() => {
      const input = host.querySelector<HTMLInputElement>('#own input[type=file]')!
      Object.defineProperty(input, 'files', { configurable: true, value: [{ name: 'disk.img', size: 40 * 1024 * 1024, text: read }] })
      input.dispatchEvent(new Event('change', { bubbles: true }))
    })
    await pass()
    expect(read).not.toHaveBeenCalled()
    expect(own().querySelector('[role=alert]')!.textContent).toContain('This file is 40 MB.')
    expect(head()).toBe(shopReport.headline)
  })
})
