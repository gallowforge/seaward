// The open lane and the address bar: what a visitor does with links, the keys, back and forward.
import { render } from 'preact'
import { act } from 'preact/test-utils'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'
import { Chart } from './chart'
import { useOpenLane } from './route'
import shop from './testdata/shop-1.report.json'
import type { Report } from './types'

const report = shop as unknown as Report

/** The chart, wired to the address the way the page wires it. */
function Page() {
  const lane = useOpenLane()
  return <Chart report={report} vantage={0} onVantage={() => undefined} open={lane.open} onToggle={(id) => lane.go(lane.open === id ? null : id)} onClose={() => lane.go(null)} />
}

let host: HTMLElement
const opened = (): string[] => [...host.querySelectorAll('.lanes > li.open')].map((li) => li.id)
const link = (id: string) => host.querySelector<HTMLAnchorElement>(`#${id} a.lane`)!
/** Lets the browser's own events (hashchange, popstate) arrive, and the page answer them. */
const settle = () => act(() => new Promise<void>((done) => setTimeout(done, 20)))
const press = (el: Element, key: string) => act(() => void el.dispatchEvent(new KeyboardEvent('keydown', { key, bubbles: true, cancelable: true })))
const click = (el: Element) => act(() => void el.dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, button: 0 })))
/** What following a link to a part of the page does: a new entry, with nothing kept in it. */
const follow = async (hash: string) => {
  location.hash = hash
  await settle()
}

beforeEach(async () => {
  history.replaceState(null, '', '/')
  host = document.createElement('div')
  document.body.append(host)
})
afterEach(() => {
  render(null, host)
  host.remove()
})
const show = () => act(() => render(<Page />, host))

describe('a lane and its address', () => {
  it('opens the lane the address names, and none for any other address', async () => {
    history.replaceState(null, '', '/#tcp-8081')
    await show()
    expect(opened()).toEqual(['tcp-8081'])
    expect(link('tcp-8081').getAttribute('aria-expanded')).toBe('true')
    expect(link('tcp-8081').getAttribute('aria-controls')).toBe('tcp-8081-passage')
    expect(link('tcp-22').getAttribute('aria-expanded')).toBe('false')
  })

  it('writes the address when a lane is opened, and clears it when it is closed', async () => {
    await show()
    expect(opened()).toEqual([])
    await click(link('tcp-5432'))
    expect(opened()).toEqual(['tcp-5432'])
    expect(location.hash).toBe('#tcp-5432')
    await click(link('tcp-22'))
    expect(opened()).toEqual(['tcp-22'])
    expect(location.hash).toBe('#tcp-22')
    await click(link('tcp-22'))
    expect(opened()).toEqual([])
    expect(location.hash).toBe('')
  })

  it('leaves a click with a modifier key to the browser', async () => {
    await show()
    // the page's own handler has run by the time the click reaches the document; whether it took the
    // click is read there, and then the click is stopped, because this test browser has no second tab
    let taken: boolean | undefined
    const after = (e: Event) => {
      taken = e.defaultPrevented
      e.preventDefault()
    }
    document.addEventListener('click', after)
    await act(() => void link('tcp-22').dispatchEvent(new MouseEvent('click', { bubbles: true, cancelable: true, button: 0, ctrlKey: true })))
    document.removeEventListener('click', after)
    expect(taken).toBe(false)
    expect(opened()).toEqual([])
    expect(location.hash).toBe('')
  })

  it('opens with Space as well as Enter, and closes with Escape from the lane or from inside the passage', async () => {
    await show()
    await press(link('tcp-80'), ' ')
    expect(opened()).toEqual(['tcp-80'])
    await press(link('tcp-80'), 'Escape')
    expect(opened()).toEqual([])
    await press(link('tcp-80'), ' ')
    await press(host.querySelector('#tcp-80-passage .close')!, 'Escape')
    expect(opened()).toEqual([])
    // Escape on a closed lane is not the page's to take
    const e = new KeyboardEvent('keydown', { key: 'Escape', bubbles: true, cancelable: true })
    link('tcp-80').dispatchEvent(e)
    expect(e.defaultPrevented).toBe(false)
  })

  it('follows a typed address, and ignores one that names no port', async () => {
    await show()
    await follow('#udp-53')
    expect(opened()).toEqual(['udp-53'])
    await follow('#tcp-99999')
    expect(opened()).toEqual(['udp-53'])
    await follow('')
    expect(opened()).toEqual([])
  })

  it('keeps the open lane when a link goes to a part of the page', async () => {
    await show()
    await click(link('tcp-443'))
    await follow('#fine-print')
    expect(opened()).toEqual(['tcp-443'])
    expect(location.hash).toBe('#fine-print')
  })

  it('goes back to what each address was left with', async () => {
    await show()
    // at a part of the page with nothing open, then a lane: back must close it again
    await follow('#chart')
    await click(link('tcp-5432'))
    expect(opened()).toEqual(['tcp-5432'])
    history.back()
    await settle()
    expect(location.hash).toBe('#chart')
    expect(opened()).toEqual([])
    history.forward()
    await settle()
    expect(opened()).toEqual(['tcp-5432'])
    // a part of the page reached with a lane open is left with that lane, and comes back with it
    await follow('#own')
    await click(link('tcp-22'))
    expect(opened()).toEqual(['tcp-22'])
    history.back()
    await settle()
    expect(location.hash).toBe('#own')
    expect(opened()).toEqual(['tcp-5432'])
  })
})
