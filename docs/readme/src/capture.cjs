// Capture Seaward for the Glass scenes, in its night theme and its day theme.
//   node capture.cjs [the binary] [the built demo]     everything (defaults: ../../../bin/seaward, ../../../pages)
//   ONLY=terms,demo node capture.cjs ...               only those parts
// Two kinds of capture, both the real thing:
//   terms    command-line sessions, run for real in a work folder under build/ and typeset with the demo's own
//            stylesheet, so they use its type and its colours. The command shown is the command that ran.
//   demo     the demo page (the engine as WebAssembly, reading the sample servers), 1024 px wide at 2x and
//            390 px wide at 3x, while its own controls are used: the lane of port 5432 is opened and its packet
//            is drawn rule by rule, then the sample "shop-1, fixed" is chosen. The chart is photographed at every
//            step of that, with the page's own animation stepped by hand; the verdict and the deciding rule are
//            photographed on their own, to be lifted out.
// The demo is a static folder; this script serves it itself, on a free port, for as long as it runs.
// Named elements are measured into build/shots/boxes.json ([x, y, w, h, background] in capture pixels) so a scene
// can lift one out of its screen by name. The scenes only crop, place and light what is captured here.
const { chromium } = require('playwright');
const { spawnSync } = require('child_process');
const http = require('http'), path = require('path'), fs = require('fs'), { pathToFileURL } = require('url');

const ROOT = path.resolve(__dirname, '..', '..', '..');
const BIN = path.resolve(process.argv[2] || path.join(ROOT, 'bin', 'seaward'));
const PAGES = path.resolve(process.argv[3] || path.join(ROOT, 'pages'));
const BUILD = path.resolve(__dirname, '..', 'build');
const SHOTS = path.join(BUILD, 'shots'), WORK = path.join(BUILD, 'work');
const ONLY = process.env.ONLY ? process.env.ONLY.split(',') : ['terms', 'demo'];
const DESK = { width: 1120, height: 940, dpr: 2 };          // the demo itself is visited 1024 px wide (see VISITS)
const PHONE = { width: 390, height: 1500, dpr: 3 };      // taller than a phone, so a scene can read further down the page
const COLS = 64;                                         // the width of the terminal the sessions run in
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

// ---------- the demo, served from its folder ----------
const MIME = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript', '.css': 'text/css', '.json': 'application/json', '.svg': 'image/svg+xml',
  '.wasm': 'application/wasm', '.woff2': 'font/woff2', '.png': 'image/png', '.snapshot': 'text/plain; charset=utf-8', '.txt': 'text/plain; charset=utf-8' };
// `extra` maps a path to a page made here (the typeset terminal), served beside the demo's own files.
function serve(extra = {}) {
  const server = http.createServer((req, res) => {
    const p = decodeURIComponent(new URL(req.url, 'http://x').pathname);
    if (extra[p]) { res.writeHead(200, { 'content-type': MIME['.html'] }); res.end(extra[p]()); return; }
    const f = path.join(PAGES, p.endsWith('/') ? p + 'index.html' : p);
    if (!f.startsWith(PAGES + path.sep) || !fs.existsSync(f) || !fs.statSync(f).isFile()) { res.writeHead(404); res.end(); return; }
    res.writeHead(200, { 'content-type': MIME[path.extname(f)] || 'application/octet-stream', 'cache-control': 'no-store' });
    fs.createReadStream(f).pipe(res);
  });
  return new Promise((ok, no) => {
    server.once('error', no);
    server.listen(0, '127.0.0.1', () => ok({ url: `http://127.0.0.1:${server.address().port}`, stop: () => new Promise((r) => server.close(r)) }));
  });
}
// The page keeps its theme in storage and reads it before the first paint.
async function context(browser, scheme, phone, extra = {}) {
  const ctx = await browser.newContext(phone
    ? { viewport: { width: PHONE.width, height: PHONE.height }, deviceScaleFactor: PHONE.dpr, colorScheme: scheme, isMobile: true, hasTouch: true, reducedMotion: 'reduce', ...extra }
    : { viewport: { width: DESK.width, height: DESK.height }, deviceScaleFactor: DESK.dpr, colorScheme: scheme, reducedMotion: 'reduce', ...extra });
  await ctx.addInitScript((s) => { try { localStorage.setItem('seaward:theme', s); } catch { /* the system's scheme says the same */ } }, scheme);
  return ctx;
}

// A mark is { css, text?, index?, to?, more?, and? }: the element matching `css` whose text holds `text` (index -1 =
// the last match). `to` stretches it over the siblings after it, as far as the first one whose text holds `to`,
// and `more` over that many siblings beyond; `and` joins it with the first match of another selector. A mark that
// is not on a screen is left out.
async function marksOf(page, marks, k, clip = { x: 0, y: 0 }) {
  return page.evaluate(({ marks, k, clip }) => {
    const cv = document.createElement('canvas'); cv.width = cv.height = 1;
    const cx = cv.getContext('2d', { willReadFrequently: true });
    const rgba = (css) => { cx.clearRect(0, 0, 1, 1); cx.fillStyle = css; cx.fillRect(0, 0, 1, 1); return cx.getImageData(0, 0, 1, 1).data; };
    const join = (r, o) => { const left = Math.min(r.left, o.left), top = Math.min(r.top, o.top);
      return { left, top, right: Math.max(r.right, o.right), bottom: Math.max(r.bottom, o.bottom) }; };
    const out = {};
    for (const [key, m] of Object.entries(marks)) {
      const els = [...document.querySelectorAll(m.css)].filter((el) => (el.offsetParent !== null || el === document.body) && (!m.text || el.textContent.includes(m.text)));
      const el = els[m.index === -1 ? els.length - 1 : (m.index || 0)];
      if (!el) continue;
      let r = el.getBoundingClientRect();
      if (m.to) {
        let e = el, found = el.textContent.includes(m.to);
        while (!found && e.nextElementSibling) { e = e.nextElementSibling; r = join(r, e.getBoundingClientRect()); found = e.textContent.includes(m.to); }
        if (!found) continue;
        for (let i = 0; i < (m.more || 0) && e.nextElementSibling; i++) { e = e.nextElementSibling; r = join(r, e.getBoundingClientRect()); }
      }
      if (m.and) {
        const other = document.querySelector(m.and);
        if (!other) continue;
        r = join(r, other.getBoundingClientRect());
      }
      let e = el, d = [0, 0, 0, 0];
      while (e && d[3] < 250) { d = rgba(getComputedStyle(e).backgroundColor); e = e.parentElement; }
      const hex = '#' + [d[0], d[1], d[2]].map((v) => v.toString(16).padStart(2, '0')).join('');
      out[key] = [(r.left + window.scrollX - clip.x) * k, (r.top + window.scrollY - clip.y) * k, (r.right - r.left) * k, (r.bottom - r.top) * k].map(Math.round).concat(hex);
    }
    return out;
  }, { marks, k, clip });
}

// ---------- the command line ----------
// The tool colours and wraps what it prints only for a real terminal, so every command runs in one, COLS wide
// (util-linux `script` gives it the terminal). The sample files are copied into the work folder and the binary is
// linked there as `seaward`, so the command typeset in the picture is the command that ran.
function prepare() {
  fs.mkdirSync(path.join(WORK, 'bin'), { recursive: true });
  for (const f of fs.readdirSync(WORK)) if (f !== 'bin') fs.unlinkSync(path.join(WORK, f));
  const link = path.join(WORK, 'bin', 'seaward');
  if (fs.existsSync(link) || fs.lstatSync(link, { throwIfNoEntry: false })) fs.unlinkSync(link);
  fs.symlinkSync(BIN, link);
  for (const f of ['shop-1', 'shop-1-fixed', 'shop-1-no-root']) fs.copyFileSync(path.join(ROOT, 'samples', f + '.snapshot'), path.join(WORK, f + '.snapshot'));
}
function run(cmd, cwd = WORK) {
  const env = { ...process.env, PATH: path.join(WORK, 'bin') + path.delimiter + process.env.PATH, TERM: 'xterm-256color' };
  delete env.NO_COLOR;
  const r = spawnSync('script', ['-qec', `stty cols ${COLS} rows 60; ${cmd}`, '/dev/null'], { cwd, env, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'], maxBuffer: 1 << 26 });
  if (r.error) throw r.error;
  if (r.status !== 0) throw new Error(`"${cmd}" ended with ${r.status}:\n${r.stdout}${r.stderr}`);
  return r.stdout.replace(/\r/g, '').replace(/\n+$/, '');
}
const said = (note, cmd, cwd) => ({ note, cmd, out: run(cmd, cwd) });
function sessions() {
  prepare();
  return {
    // what ufw allows against what can really be reached
    scan: [said(null, 'seaward scan -f shop-1.snapshot')],
    // one packet, rule by rule
    why: [said(null, 'seaward why 5432 -f shop-1.snapshot')],
    // the same server after its three published ports were bound to this machine only
    fixed: [said(null, 'seaward scan -f shop-1-fixed.snapshot')],
    // the same server read without root
    unknown: [said(null, 'seaward scan -f shop-1-no-root.snapshot')],
    // nothing to install on the server: a shell script collects, and the reading happens anywhere
    snapshot: [
      said('The collector is a plain shell script. Read it before you run it.', 'seaward snapshot --script > seaward-snapshot.sh'),
      said(null, 'wc -l seaward-snapshot.sh'),
      said(null, 'head -n 4 seaward-snapshot.sh'),
      said('It writes one text file. Any machine can read that.', 'seaward scan -f shop-1.snapshot'),
    ],
    // the proof: every scenario built in the real kernel, in private namespaces, and compared with the engine
    kernel: [
      said('Rulesets are loaded into the real kernel and probed with real packets.', 'make lab', ROOT),
      said('A scenario is a ruleset, its listeners and its probes.', 'cat internal/lab/scenarios/docker-publish-beats-ufw-input.txt', ROOT),
    ],
  };
}
// What is lifted out of each session.
const TERM_MARKS = {
  scan: { verdict: { css: '.t-blk', text: 'can be reached from outside' }, exposed: { css: '.t-o', text: 'tcp 5432', to: 'ufw does not allow it' },
    block: { css: '.t-blk', text: 'tcp 5432' } },
  why: { port: { css: '.t-blk', index: 0 }, through: { css: '.t-blk', text: 'gets through' },
    rewrite: { css: '.t-o', text: 'destination becomes', to: '--to-destination', more: 1 },
    accept: { css: '.t-o', text: 'filter DOCKER          accept', to: '-j ACCEPT' },
    steps: { css: '.t-o', text: 'nat PREROUTING', to: 'listening on port 5432' } },
  fixed: { verdict: { css: '.t-blk', text: 'can be reached from outside' } },
  unknown: { verdict: { css: '.t-blk', text: 'could not be read, so nothing is decided' }, unread: { css: '.t-blk', text: 'not read' } },
  snapshot: { script: { css: '.t-run', text: 'head -n 4' }, head: { css: '.t-run:nth-of-type(3) .t-out' }, count: { css: '.t-run', text: 'wc -l' },
    verdict: { css: '.t-blk', text: 'can be reached from outside' } },
  kernel: { result: { css: '.t-o', text: 'scenarios,' }, run: { css: '.t-run', text: 'make lab' }, about: { css: '.t-o', text: 'about:', to: 'never meets INPUT' } },
};
// The figures the pictures quote, each taken from what was printed just now. A picture cannot state a number the
// tool did not give: layouts.js names these, and the scene fills them in.
const plain = (s) => s.replace(/\x1b\[[0-9;]*m/g, '');
const count = (n) => Number(n).toLocaleString('en-US');
function facts(told) {
  const json = (file) => JSON.parse(spawnSync(BIN, ['scan', '-f', file, '--json'], { cwd: WORK, encoding: 'utf8', maxBuffer: 1 << 26 }).stdout);
  const need = (v, what) => { if (v === null || v === undefined || Number.isNaN(v)) throw new Error('the output no longer says ' + what); return v; };
  const shop = json('shop-1.snapshot'), blind = json('shop-1-no-root.snapshot'), mended = json('shop-1-fixed.snapshot');
  const allowed = need((shop.headline.match(/allows only (\d+) of them/) || [])[1], 'how many reachable ports the firewall tool allows');
  if (shop.counts.reachable - shop.counts.exposed !== +allowed) throw new Error('the headline and the counts of shop-1 disagree');
  // one trace is a run of numbered steps; the first is the packet that gets through
  const traces = [];
  for (const l of plain(told.why[0].out).split('\n')) {
    const step = l.match(/^[ >] +(\d+)  \S/);
    if (step && +step[1] === 1) traces.push({ steps: 0, rules: 0 });
    if (!traces.length) continue;
    if (step) traces[traces.length - 1].steps = +step[1];
    else if (/^\s+-A /.test(l)) traces[traces.length - 1].rules++;
  }
  const lab = plain(told.kernel[0].out).match(/(\d+) scenarios, .*?(\d+) probes, .*?(\d+) disagreements/);
  need(lab, 'how the lab run went');
  const out = {
    scan: { reachable: shop.counts.reachable, allowed: +allowed, exposed: shop.counts.exposed, ports: shop.ports.length },
    fixed: { reachable: mended.counts.reachable, exposed: mended.counts.exposed },
    why: { steps: need(traces[0] && traces[0].steps, 'the steps of a packet'), rules: traces[0].rules, packets: traces.length },
    lab: { scenarios: count(lab[1]), probes: count(lab[2]), disagreements: count(lab[3]) },
    unknown: { undecided: blind.counts.undecided, unread: blind.unread.length, called: blind.counts.reachable + blind.counts.stopped + blind.counts.quiet },
    snapshot: { lines: count(need((told.snapshot[1].out.match(/^\s*(\d+)\s/) || [])[1], 'how long the collector script is')) },
  };
  // the numbers band is written by hand in numbers.json; say so when the run just made disagrees with it
  const band = JSON.parse(fs.readFileSync(path.join(__dirname, 'numbers.json'), 'utf8')).figures.map((f) => f.value);
  for (const [i, v] of [out.lab.scenarios, out.lab.probes, out.lab.disagreements].entries())
    if (band[i] !== v) throw new Error(`numbers.json says ${band[i]} where this run of \`make lab\` says ${v}`);
  return out;
}
const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
// One printed line: the terminal's colour codes become spans, and a line too long for the terminal wraps under
// its own text. Seaward wraps its own lines; only other programs' lines (make, cat, head) ever do.
function printed(l) {
  const lead = l.match(/^(\s*)/)[1].replace(/\t/g, '    ').length;
  let html = '', on = [];
  for (const part of l.replace(/^\s+/, '').split(/(\x1b\[[0-9;]*m)/)) {
    const m = part.match(/^\x1b\[([0-9;]*)m$/);
    if (m) { on = m[1] === '' || m[1] === '0' ? [] : on.concat(m[1].split(';').filter((c) => c !== '0')); continue; }
    if (part === '') continue;
    html += on.length ? `<span class="${on.map((c) => 'a' + c).join(' ')}">${esc(part)}</span>` : esc(part);
  }
  return `<div class="t-o"${lead ? ` style="margin-left:${lead}ch"` : ''}>${html}</div>`;
}
// Blank lines split what was printed into blocks, so a scene can lift one of them.
const blocks = (out) => out === '' ? '' : out.split(/\n{2,}/).map((b) => `<div class="t-blk">${b.split('\n').map(printed).join('')}</div>`).join('');
const terminal = (steps) => `<div class="term">${steps.map((s) =>
  `<section class="t-run${s.note ? ' told' : ''}">${s.note ? `<p class="t-note">${esc(s.note)}</p>` : ''}<div class="t-cmd"><span class="p">$ </span>${esc(s.cmd)}</div>` +
  `<div class="t-out">${blocks(s.out)}</div></section>`).join('')}</div>`;
// The terminal's page: the demo's stylesheet for its fonts and its colours, and the setting below.
const SET = `
html, body { margin: 0; min-width: 0; background: var(--paper); }
:root { --t-amber: #8a6a12; --t-green: #2c7a52; --t-cyan: #2a6c93; }
html[data-theme='dark'] { --t-amber: #dcc277; --t-green: #7fcaa0; --t-cyan: #74b6dc; }
.term { box-sizing: content-box; width: ${COLS}ch; padding: 24px 30px 30px; background: var(--paper); color: var(--ink);
  font: 400 13.5px/1.56 var(--mono); font-variant-ligatures: none; font-synthesis: none; tab-size: 8; }
.term .a1 { font-weight: 650; } .term .a2 { color: var(--ink-3); }
.term .a31 { color: var(--alarm); } .term .a33 { color: var(--t-amber); } .term .a32 { color: var(--t-green); } .term .a36 { color: var(--t-cyan); }
.term .t-run + .t-run { margin-top: 14px; }
.term .t-run.told + .t-run.told, .term .t-run + .t-run.told { margin-top: 22px; padding-top: 20px; border-top: 1px solid var(--rule); }
.term .t-note { margin: 0 0 12px; font: 500 15px/1.4 var(--sans); letter-spacing: 0; text-transform: none; color: var(--ink); max-width: 34rem; text-wrap: balance; }
.term .t-cmd { padding-left: 2ch; text-indent: -2ch; white-space: pre-wrap; overflow-wrap: anywhere; font-weight: 500; }
.term .t-cmd .p { color: var(--ink-3); font-weight: 400; }
.term .t-out:not(:empty) { margin-top: 8px; }
.term .t-blk + .t-blk { margin-top: 1.56em; }
.term .t-blk, .term .t-o { width: fit-content; max-width: 100%; }
.term .t-o { white-space: pre-wrap; overflow-wrap: anywhere; min-height: 1.56em; }`;
function termPage(body, scheme) {
  const css = fs.readFileSync(path.join(PAGES, 'index.html'), 'utf8').match(/href="\.?\/?(assets\/[^"]+\.css)"/);
  if (!css) throw new Error('no stylesheet in the demo: ' + PAGES);
  return `<!doctype html><html lang="en" data-theme="${scheme}"><head><meta charset="utf-8"><link rel="stylesheet" href="/${css[1]}"><style>${SET}</style></head><body>${body}</body></html>`;
}
async function terms(browser, boxes) {
  const told = sessions();
  fs.writeFileSync(path.join(SHOTS, 'facts.json'), JSON.stringify(facts(told), null, 1));
  let now = '';
  const d = await serve({ '/__term.html': () => now });
  try {
    for (const scheme of ['dark', 'light']) {
      const ctx = await context(browser, scheme, false, { viewport: { width: 900, height: 700 } });
      const page = await ctx.newPage();
      for (const [name, steps] of Object.entries(told)) {
        now = termPage(terminal(steps), scheme);
        await page.goto(d.url + '/__term.html');
        await page.evaluate(() => document.fonts.ready);
        await page.waitForTimeout(250);
        const file = `${name}-${scheme}`, term = page.locator('.term');
        const at = await term.boundingBox();
        boxes[file] = await marksOf(page, { ...TERM_MARKS[name], _page: { css: 'body' } }, DESK.dpr, at);
        // where each printed line begins and ends, so that a pane can be cut between two lines and never through one
        boxes[file]._rows = await page.evaluate(([k, top]) => [...document.querySelectorAll('.t-o, .t-cmd, .t-note')].flatMap((e) => {
          const r = e.getBoundingClientRect(), lh = parseFloat(getComputedStyle(e).lineHeight), n = Math.max(1, Math.round(r.height / lh));
          return r.height ? Array.from({ length: n }, (_, i) => [Math.round((r.top - top + i * lh) * k), Math.round((r.top - top + (i + 1) * lh) * k)]) : [];
        }), [DESK.dpr, at.y]);
        await term.screenshot({ path: path.join(SHOTS, file + '.png') });
        console.log(file);
      }
      await ctx.close();
    }
  } finally { await d.stop(); }
}

// ---------- the demo ----------
// One visit for each width and each theme. The window is tall, so the whole way from the verdict to the passage
// is on screen at once and nothing has to scroll. What is done on the page is what a visitor does: the lane of
// port 5432 is selected, and then a sample is chosen in the sample switcher. The passage draws itself with CSS
// animations; they are held and stepped by hand, REPLAY.step ms a frame, so every build photographs the same
// moments. The chart is photographed from its header row down, in this order: 0 shop-1 at rest; 1..turn the
// passage being drawn; turn+1 the passage at rest; turn+2 the fixed server. At the phone's width the head of the
// page (the verdict and the sample switcher) is photographed too: 0 shop-1, 1 the fixed server.
const VISITS = [
  { name: 'chart', phone: false, width: 1024, tall: 2400, deep: 760 },
  { name: 'm-chart', phone: true, width: PHONE.width, tall: 3800, deep: 1000, head: ['m-head', 720] },
];
const LANE = 'tcp-5432', FIXED = 'shop-1, fixed', FIRST = 'shop-1';
async function visit(browser, d, scheme, v, boxes, { turn: N, step: STEP }) {
  const k = v.phone ? PHONE.dpr : DESK.dpr;
  const ctx = await context(browser, scheme, v.phone, { reducedMotion: 'no-preference', viewport: { width: v.width, height: v.tall } });
  const page = await ctx.newPage();
  const errors = [];
  page.on('pageerror', (e) => errors.push(e.message));
  await page.goto(d.url + '/');
  await page.waitForFunction(() => document.querySelector('ol.lanes') && !document.querySelector('h1.waiting'), null, { timeout: 30000 });
  await page.evaluate(() => document.fonts.ready);
  await page.waitForTimeout(300);
  const said = () => page.evaluate(() => document.getElementById('verdict-h').textContent.trim());
  const blur = () => page.evaluate(() => { if (document.activeElement instanceof HTMLElement) document.activeElement.blur(); });
  // a press with no pointer, so nothing is left hovered
  const choose = async (label) => {
    const was = await said();
    await page.evaluate((label) => [...document.querySelectorAll('.picker-list button')].find((b) => b.textContent === label).click(), label);
    await page.waitForFunction((was) => { const h = document.getElementById('verdict-h'); return h && !h.classList.contains('waiting') && h.textContent.trim() !== was; }, was, { timeout: 30000 });
    await page.waitForTimeout(150);
    await blur();
  };
  let n = 0, heads = 0;
  const still = async () => { if (await page.evaluate(() => scrollY) !== 0) throw new Error('the demo scrolled: the window is not tall enough'); };
  // the chart, from its header row down; `marks` names what a scene may lift out of this frame
  const shot = async (marks) => {
    await still();
    const top = await page.evaluate(() => Math.round(document.querySelector('.strip').getBoundingClientRect().top));
    const clip = { x: 0, y: top, width: v.width, height: v.deep }, file = `${v.name}-${String(n++).padStart(2, '0')}-${scheme}`;
    if (marks) boxes[file] = await marksOf(page, marks, k, clip);
    await page.screenshot({ path: path.join(SHOTS, file + '.png'), clip });
  };
  // the head of the page
  const head = async () => {
    if (!v.head) return;
    await still();
    const clip = { x: 0, y: 0, width: v.width, height: v.head[1] }, file = `${v.head[0]}-${String(heads++).padStart(2, '0')}-${scheme}`;
    boxes[file] = await marksOf(page, { say: { css: '#verdict-h' }, why: { css: '.verdict-main .detail' }, picker: { css: '.picker' } }, k, clip);
    await page.screenshot({ path: path.join(SHOTS, file + '.png'), clip });
  };
  const lane = { css: `#${LANE} > .lane` };
  const says = [await said()];
  await head();
  await shot({ lane, heads: { css: '.heads' } });

  // the lane is selected: the passage opens under it and draws the packet's way, mark by mark
  await page.evaluate((id) => { document.querySelector(`#${id} > .lane`).click(); }, LANE);
  await page.waitForSelector(`#${LANE}-passage`);
  await page.evaluate(() => { for (const a of document.getAnimations()) a.pause(); });
  await blur();
  if (!(await page.evaluate(() => document.getAnimations().length))) throw new Error('the passage no longer draws itself: nothing to step');
  for (let i = 0; i < N; i++) {
    await page.evaluate((t) => { for (const a of document.getAnimations()) a.currentTime = t; }, i * STEP);
    await shot();
  }
  await page.evaluate(() => { for (const a of document.getAnimations()) { try { a.finish(); } catch { /* one that never ends */ } } });
  await page.waitForTimeout(120);
  const inside = `#${LANE}-passage`;
  await shot({ lane, passage: { css: inside }, head: { css: `${inside} .pass-head` }, track: { css: `${inside} .track` }, why: { css: `${inside} .packet-say` },
    rewrite: { css: `${inside} .step.rewrite` }, rule: { css: `${inside} .step.deciding` } });

  // the fixed server, chosen in the sample switcher
  await choose(FIXED);
  says.push(await said());
  await head();
  await shot({ lane, heads: { css: '.heads' } });
  // and the way back, which the loop takes: the first sample again gives the first picture
  await choose(FIRST);
  says.push(await said());
  if (says[2] !== says[0]) throw new Error('choosing the first sample again did not bring its verdict back');
  if (errors.length) throw new Error('the demo page reported: ' + errors.join(' / '));
  console.log(`${v.name}-${scheme}: ${n} frames; ${says.slice(0, 2).join(' / ')}`);
  await ctx.close();
}
async function demo(browser, boxes, replay) {
  for (const f of fs.readdirSync(SHOTS)) if (/^(m-)?(chart|head)-\d+-/.test(f)) fs.unlinkSync(path.join(SHOTS, f));
  const d = await serve();
  try {
    for (const scheme of ['dark', 'light']) for (const v of VISITS) await visit(browser, d, scheme, v, boxes, replay);
  } finally { await d.stop(); }
}

(async () => {
  if (!fs.existsSync(BIN)) throw new Error(`no binary at ${BIN}: run \`make build\` first`);
  if (!fs.existsSync(path.join(PAGES, 'index.html'))) throw new Error(`no demo at ${PAGES}: run \`make demo\` first`);
  fs.mkdirSync(SHOTS, { recursive: true });
  const boxFile = path.join(SHOTS, 'boxes.json');
  const boxes = fs.existsSync(boxFile) ? JSON.parse(fs.readFileSync(boxFile, 'utf8')) : {};
  const { REPLAY } = await import(pathToFileURL(path.join(__dirname, 'layouts.js')).href);
  const browser = await chromium.launch();
  try {
    if (ONLY.includes('terms')) await terms(browser, boxes);
    if (ONLY.includes('demo')) await demo(browser, boxes, REPLAY);
  } finally { await browser.close(); }
  fs.writeFileSync(boxFile, JSON.stringify(boxes, null, 1));
})().catch((e) => { console.error(e); process.exit(1); });
