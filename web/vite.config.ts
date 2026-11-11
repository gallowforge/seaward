import { existsSync, readdirSync, readFileSync, statSync } from 'node:fs'
import { join } from 'node:path'
import { fileURLToPath } from 'node:url'
import preact from '@preact/preset-vite'
import type { Plugin } from 'vite'
import { defineConfig } from 'vitest/config'

const here = (p: string) => fileURLToPath(new URL(p, import.meta.url))
const SAMPLES = here('../samples')
const PAGES = here('../pages')

/**
 * The sample servers live in ../samples: the snapshot files and index.json, which lists them.
 * The build copies them beside the page; the dev server hands them out from where they are, and
 * the engine (seaward.wasm, wasm_exec.js) from ../pages when `npm run engine` has put it there.
 */
function samples(): Plugin {
  const listed = (): { file: string }[] => {
    const index = JSON.parse(readFileSync(join(SAMPLES, 'index.json'), 'utf8')) as unknown
    if (!Array.isArray(index) || index.length === 0) throw new Error('samples/index.json must be a list with at least one sample')
    for (const s of index as { id?: unknown; file?: unknown; title?: unknown; description?: unknown }[]) {
      for (const key of ['id', 'file', 'title', 'description'] as const) {
        if (typeof s[key] !== 'string' || !s[key]) throw new Error(`samples/index.json: every sample needs "${key}"`)
      }
      // the page keeps only the entries it can address (src/samples.ts), so the build asks the same
      if (!/^[a-z0-9][a-z0-9-]*$/.test(s.id as string)) throw new Error(`samples/index.json: the id "${String(s.id)}" must be lower-case letters, digits and hyphens`)
      if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(s.file as string)) throw new Error(`samples/index.json: "${String(s.file)}" is not a plain file name`)
      if (!existsSync(join(SAMPLES, s.file as string))) throw new Error(`samples/index.json names ${String(s.file)}, which is not in samples/`)
    }
    return index as { file: string }[]
  }
  return {
    name: 'seaward-samples',
    generateBundle() {
      // every snapshot in the folder, and whatever else the list names, so no listed sample is missing
      const files = new Set([...readdirSync(SAMPLES).filter((f) => f.endsWith('.snapshot')), ...listed().map((s) => s.file)])
      this.emitFile({ type: 'asset', fileName: 'samples/index.json', source: readFileSync(join(SAMPLES, 'index.json')) })
      for (const file of files) this.emitFile({ type: 'asset', fileName: `samples/${file}`, source: readFileSync(join(SAMPLES, file)) })
    },
    configureServer(server) {
      server.middlewares.use((req, res, next) => {
        const path = decodeURIComponent((req.url ?? '').split('?')[0] ?? '')
        const sample = /^\/samples\/([A-Za-z0-9][A-Za-z0-9._-]*)$/.exec(path)
        const engine = /^\/(seaward\.wasm|wasm_exec\.js)$/.exec(path)
        const file = sample ? join(SAMPLES, sample[1]!) : engine ? join(PAGES, engine[1]!) : ''
        if (!file || !existsSync(file) || !statSync(file).isFile()) return next()
        res.setHeader('Content-Type', file.endsWith('.wasm') ? 'application/wasm' : file.endsWith('.js') ? 'text/javascript' : file.endsWith('.json') ? 'application/json' : 'text/plain; charset=utf-8')
        res.end(readFileSync(file))
      })
    },
  }
}

/**
 * The built page promises that a snapshot never leaves it. This makes the browser hold it to
 * that: nothing may be fetched from, or sent to, any host but the page's own.
 */
function policy(): Plugin {
  const rules = [
    "default-src 'none'",
    "script-src 'self' 'wasm-unsafe-eval'",
    "style-src 'self'",
    "font-src 'self'",
    "img-src 'self'",
    "connect-src 'self'",
    "base-uri 'none'",
    "form-action 'none'",
  ]
  return {
    name: 'seaward-content-policy',
    apply: 'build',
    transformIndexHtml: () => [{ tag: 'meta', attrs: { 'http-equiv': 'Content-Security-Policy', content: rules.join('; ') }, injectTo: 'head-prepend' }],
  }
}

export default defineConfig({
  // GitHub Pages serves the site from a folder, so every address is relative
  base: './',
  plugins: [preact(), samples(), policy()],
  build: {
    outDir: '../pages',
    emptyOutDir: true,
    target: 'es2022',
    // fonts are files, never inline data
    assetsInlineLimit: 0,
    cssCodeSplit: false,
    reportCompressedSize: false,
  },
  test: {
    environment: 'jsdom',
    // one test reads a stylesheet as text (render.test.tsx); left at its default, vitest hands
    // every stylesheet over empty
    css: true,
  },
})
