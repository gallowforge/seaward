// Day, night, or whatever the system says. public/theme.js applies the choice before the first
// paint; this is the same rule for when it changes later.
import { useEffect, useState } from 'preact/hooks'

export type Mode = 'system' | 'light' | 'dark'

const KEY = 'seaward:theme'
/** The page ground in each theme, for the browser's own chrome. Keep in step with styles.css. */
const GROUND = { light: '#f8f6ef', dark: '#0a141f' } as const

function stored(): Mode {
  try {
    const m = localStorage.getItem(KEY)
    if (m === 'light' || m === 'dark') return m
  } catch {
    /* storage is blocked: follow the system */
  }
  return 'system'
}

function apply(mode: Mode): void {
  const dark = mode === 'dark' || (mode !== 'light' && matchMedia('(prefers-color-scheme: dark)').matches)
  document.documentElement.dataset.theme = dark ? 'dark' : 'light'
  document.querySelector('meta[name="theme-color"]')?.setAttribute('content', dark ? GROUND.dark : GROUND.light)
}

/** The chosen mode, and a way to choose another. The choice is remembered when storage allows. */
export function useTheme(): [Mode, (m: Mode) => void] {
  const [mode, setMode] = useState<Mode>(stored)
  useEffect(() => {
    apply(mode)
    if (mode !== 'system') return
    const system = matchMedia('(prefers-color-scheme: dark)')
    const follow = () => apply('system')
    system.addEventListener('change', follow)
    return () => system.removeEventListener('change', follow)
  }, [mode])
  const choose = (next: Mode) => {
    try {
      if (next === 'system') localStorage.removeItem(KEY)
      else localStorage.setItem(KEY, next)
    } catch {
      /* the choice lasts for this visit only */
    }
    setMode(next)
  }
  return [mode, choose]
}
