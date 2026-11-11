// Builds the engine for the browser and puts it beside the built page, the way the Makefile's
// pages target does: ../pages/seaward.wasm and Go's loader, wasm_exec.js.
import { execFileSync } from 'node:child_process'
import { copyFileSync, mkdirSync } from 'node:fs'
import { fileURLToPath } from 'node:url'
import { join } from 'node:path'

const repo = fileURLToPath(new URL('../..', import.meta.url))
const out = join(repo, 'pages')
mkdirSync(out, { recursive: true })
execFileSync('go', ['build', '-trimpath', '-ldflags', '-s -w', '-o', join(out, 'seaward.wasm'), './cmd/seaward-wasm'], {
  cwd: repo,
  env: { ...process.env, GOOS: 'js', GOARCH: 'wasm' },
  stdio: 'inherit',
})
const goroot = execFileSync('go', ['env', 'GOROOT'], { encoding: 'utf8' }).trim()
copyFileSync(join(goroot, 'lib', 'wasm', 'wasm_exec.js'), join(out, 'wasm_exec.js'))
console.log('engine: pages/seaward.wasm and pages/wasm_exec.js')
