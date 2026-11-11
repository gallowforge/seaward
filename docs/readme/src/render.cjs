// Compose Glass scenes from the captured pages, on the GPU.
//   node render.cjs <layout>:<dark|light>:still:<out.png>[:<phase>] ...  one still per job (of a loop: the moment 0..1)
//   node render.cjs <layout>:<dark|light>:anim:<frames>:<outDir> ...     numbered frames of a loop
//                   (<frames> may be the word loop: as many as the layout says one turn of it takes)
// Reads docs/readme/build/shots (made by capture.cjs) and the demo's two type families from web/src/assets/fonts.
// three and playwright come from this folder's node_modules (npm ci).
const { chromium } = require('playwright');
const path = require('path'), fs = require('fs'), { pathToFileURL } = require('url');
const SRC = __dirname, SHOTS = path.resolve(SRC, '..', 'build', 'shots');
const FONTS = path.resolve(SRC, '..', '..', '..', 'web', 'src', 'assets', 'fonts');
const THREE_DIR = path.dirname(require.resolve('three'));
const MIME = { '.js': 'text/javascript', '.html': 'text/html', '.png': 'image/png', '.json': 'application/json', '.woff2': 'font/woff2' };

function file(url) {
  const p = decodeURIComponent(new URL(url).pathname);
  if (p.startsWith('/three/')) return path.join(THREE_DIR, p.slice(7));
  if (p.startsWith('/shots/')) return path.join(SHOTS, p.slice(7));
  if (p.startsWith('/fonts/')) return path.join(FONTS, path.basename(p));
  return path.join(SRC, p.replace(/^\/src\//, ''));
}

(async () => {
  const jobs = process.argv.slice(2).map(j => j.split(':'));
  const { LAYOUTS } = await import(pathToFileURL(path.join(SRC, 'layouts.js')).href);
  const browser = await chromium.launch({ args: ['--use-angle=vulkan', '--enable-features=Vulkan', '--ignore-gpu-blocklist', '--enable-gpu'] });
  for (const [layout, theme, mode, a, b] of jobs) {
    const L = LAYOUTS[layout];
    if (!L) throw new Error('unknown layout ' + layout);
    const ctx = await browser.newContext({ viewport: { width: L.css[0], height: L.css[1] }, deviceScaleFactor: L.dpr });
    const page = await ctx.newPage();
    page.on('console', m => { if (m.type() === 'error' || m.type() === 'warning') console.log('[page]', m.text().slice(0, 2000)); });
    page.on('pageerror', e => console.log('[pageerror]', e.message));
    await page.route('http://glass.local/**', r => {
      const f = file(r.request().url());
      if (fs.existsSync(f)) r.fulfill({ path: f, contentType: MIME[path.extname(f)] || 'application/octet-stream' });
      // the numbers band needs no capture: before the first whole build the two measurement files are simply empty
      else if (path.dirname(f) === SHOTS && path.extname(f) === '.json') r.fulfill({ contentType: MIME['.json'], body: '{}' });
      else { console.log('404', path.relative(SRC, f)); r.fulfill({ status: 404, body: '' }); }
    });
    await page.goto(`http://glass.local/src/scene.html?layout=${layout}&theme=${theme}&ss=2${process.env.GLASS_ALSO || ''}`);   // GLASS_ALSO='&nowin' shows the chart alone
    await page.waitForFunction(() => window.__ready !== undefined, null, { timeout: 30000 });
    await page.evaluate(() => window.__ready);
    await page.waitForTimeout(300);
    const t0 = Date.now();
    if (mode === 'still') {
      await page.evaluate(p => window.renderAt(p), +b || 0);
      await page.screenshot({ path: a });
    } else {
      const n = a === 'loop' ? L.frames : +a; fs.mkdirSync(b, { recursive: true });
      if (!(n > 0)) throw new Error(`how many frames of ${layout}?`);
      for (let i = 0; i < n; i++) {
        await page.evaluate(p => window.renderAt(p), i / n);
        await page.screenshot({ path: path.join(b, `f${String(i).padStart(4, '0')}.png`) });
      }
    }
    console.log(layout, theme, mode, ((Date.now() - t0) / 1000).toFixed(1) + 's');
    await ctx.close();
  }
  await browser.close();
})().catch(e => { console.error(e); process.exit(1); });
