// The page's addresses: one plain hash per port ("#tcp-5432"), so a lane can be linked to.
import { useEffect, useRef, useState } from 'preact/hooks'

const PORT = /^#?([a-z][a-z0-9]{0,15})-([0-9]{1,5})$/

/** The port a hash names, as the id its lane carries, or null when the hash names no port. */
export function portFromHash(hash: string): string | null {
  const m = PORT.exec(hash.trim().toLowerCase())
  if (!m) return null
  const n = Number(m[2])
  if (n < 1 || n > 65535) return null
  return `${m[1]}-${n}`
}

/** True for the address of the page itself, with nothing after it. */
export const isBare = (hash: string): boolean => hash === '' || hash === '#'

/** The address of the page with this lane open, or with none open. */
export const hashFor = (id: string | null): string => (id ? `#${id}` : '')

/** The lane a history entry was left with, when the page wrote it down there. */
function kept(state: unknown): { lane: string | null } | null {
  if (!state || typeof state !== 'object' || !('lane' in state)) return null
  const lane = (state as { lane: unknown }).lane
  return { lane: typeof lane === 'string' ? portFromHash(lane) : null }
}

function keep(lane: string | null, how: 'push' | 'replace', url?: string): void {
  try {
    if (how === 'push') history.pushState({ lane }, '', url)
    else history.replaceState({ lane }, '')
  } catch {
    /* a page opened from a file may refuse: the lane still opens */
  }
}

/** Where the visitor is: the open lane, and a way to open another or close it. */
export function useOpenLane(): { open: string | null; fromLink: number; go: (id: string | null) => void } {
  const [open, setOpen] = useState<string | null>(() => kept(history.state)?.lane ?? portFromHash(location.hash))
  // counts arrivals by address (a typed or followed link, back and forward), which should scroll
  const [fromLink, setFromLink] = useState(0)
  const now = useRef(open)
  now.current = open
  useEffect(() => {
    const read = () => {
      const named = portFromHash(location.hash)
      const was = kept(history.state)
      if (was) {
        // back or forward to an entry this page has been at: the lane it was left with
        setOpen(was.lane)
      } else if (named || isBare(location.hash)) {
        setOpen(named)
      } else {
        // a part of the page ("#chart"), by a link in it: the open lane stays as it is, and the
        // entry is told so, so that coming back to it later finds the same lane open
        keep(now.current, 'replace')
        return
      }
      if (named) setFromLink((n) => n + 1)
    }
    addEventListener('hashchange', read)
    addEventListener('popstate', read)
    return () => {
      removeEventListener('hashchange', read)
      removeEventListener('popstate', read)
    }
  }, [])
  const go = (id: string | null) => {
    const hash = hashFor(id)
    if (hash !== location.hash) keep(id, 'push', hash || location.pathname + location.search)
    else keep(id, 'replace')
    setOpen(id)
  }
  return { open, fromLink, go }
}
