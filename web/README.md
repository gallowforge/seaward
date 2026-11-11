# Seaward, in the browser

The demo page: the command's own engine, compiled to WebAssembly, reading a sample snapshot or one you drop in. Nothing leaves the page.

- Run: `npm install`, `npm run engine` once (it builds the engine into `../pages/`, where the dev server looks for it), then `npm run dev`.
- Build: `npm run build` writes the static site to `../pages/` and empties that folder first, so `npm run engine` (Go, `GOOS=js GOARCH=wasm`) goes after it. `npm run preview` serves the result on port 4319.
- Test: `npm test` (report-to-view logic, the `#tcp-5432` addresses, and the page rendered from small reports) and `npm run typecheck`.
- Samples are the files listed in `../samples/index.json`; the build copies them in. Fonts are in `src/assets/fonts/` with their licence texts.
