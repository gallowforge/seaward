// Seaward's README scenes: which captures lie where on the chart, what is lifted out of them, and the words
// beside them. The pictures inside the glass are made by capture.cjs from real command-line sessions and from
// the built demo; this file only crops, places and lights them. Sizes are CSS px of the picture.
// A figure written {{like.this}} is filled in from build/shots/facts.json, which capture.cjs writes from what the
// tool printed, so a number in a picture is always one the tool gave.
import NUMBERS from './numbers.json' with { type: 'json' };

// The hero's moving part, as capture.cjs photographs it: `turn` frames of the passage of port 5432 being drawn,
// `step` ms apart (twelve a second).
export const REPLAY = { turn: 11, step: 1000 / 12 };

// ---------- the chart ----------
// Seaward's own colours, from the demo's stylesheet: deep water by night and paper by day, the blue a chart
// prints over shallow water, its contour blue, and one overprint magenta, kept for the one thing it means in the
// product: the firewall tool's list says otherwise.
const NIGHT = { page: '#0d1117',
  env: { top: '#0b1826', bot: '#091420', haze: '#0e2234', hazeStr: 0.55, glows: [[0.70, 0.55, 0.55, 0.035, '#1f5d86']],
    shoal: '#12395a', shoalStr: 0.80, shoalFall: 0.56, line: '#4a8fba', chart: [0.05, 1.45, 0.085, 0.60], lines: 8, lineFall: 0.86, lineWidth: 0.5,
    ink: '#9db4c6', inkAmt: 0.50 },
  glass: { tint: [0.030, 0.046, 0.062], transmit: 0.80, fog: '#0a141f', light: [-700, 800, 900], rim: 0.85, spec: 0.36, glow: 0.35, shadow: 0.34, levels: 5, caustic: 0,
    neat: 3.5, neatCol: '#9fc4dc', neatAmt: 0.16, ghost: 0.12 },
  bloom: 0.30, bloomThresh: 0.62 };
const DAY = { page: '#ffffff',
  env: { top: '#f8f6ef', bot: '#f8f6ef', haze: '#fdfcf8', hazeStr: 0.5, glows: [],
    shoal: '#cfe5f1', shoalStr: 0.95, shoalFall: 0.58, line: '#6ea5c4', chart: [0.05, 1.45, 0.085, 0.80], lines: 8, lineFall: 0.86, lineWidth: 0.5,
    ink: '#5c6975', inkAmt: 0.62, shadow: 0.55, shadowCol: '#dde2e6', shadowDir: [0.022, -0.036] },
  glass: { tint: [0.060, 0.060, 0.056], transmit: 0.92, fog: '#f8f6ef', light: [-700, 800, 900], rim: 0.95, spec: 0.28, glow: 0.0, shadow: 0.13, levels: 5, caustic: 0.06,
    neat: 3.5, neatCol: '#16212b', neatAmt: 0.13, ghost: 0.12 },
  bloom: 0.0, bloomThresh: 0.95 };
const merge = (a, b) => { const o = { ...a }; for (const k in b) o[k] = (b[k] && typeof b[k] === 'object' && !Array.isArray(b[k])) ? merge(a[k] || {}, b[k]) : b[k]; return o; };
const ALARM = (n) => (n ? '#ff4f9b' : '#c2136b');

// ---------- the type ----------
const C = {
  kick: { night: { color: '#7f9bb0' }, day: { color: '#5c6975' } },
  name: { night: { color: '#eef2f5' }, day: { color: '#16212b' } },
  head: { night: { color: '#eef2f5' }, day: { color: '#16212b' } },
  line: { night: { color: '#a3b0bb' }, day: { color: '#44525e' } },
  fact: { night: { color: '#e4eaef' }, day: { color: '#16212b' } },
  big: { night: { color: '#e9eef2' }, day: { color: '#16212b' } },
  rule: { night: { borderColor: 'rgba(211,219,226,0.20)' }, day: { borderColor: 'rgba(22,33,43,0.20)' } },
  hair: { night: { background: 'rgba(211,219,226,0.14)' }, day: { background: 'rgba(22,33,43,0.13)' } },
};
const T = (cls, html, x, y, style = {}, align) => ({ cls, html, x, y, align, style, ...C[cls] });
// what a figure counts is set in the second ink
const FACT = (v, l, over) => `<b${over ? ' style="color:var(--alarm)"' : ''}>${v}</b><span style="color:var(--ink2)">${l}</span>`;
// the words the firewall tool's list would have you believe, in the overprint
const OVER = (s) => `<span style="color:var(--alarm)">${s}</span>`;

// ---------- the panes ----------
const BG = (n) => (n ? '#0a141f' : '#f8f6ef');       // the demo's and the terminal's ground, keyed out so they lie on the glass
const tx = (screen, n) => `${screen}-${n ? 'dark' : 'light'}.png`;
// what is lifted out of a pane: its own ground keyed to glass, a soft shadow on the pane behind
const LIFT = (n) => ({ key: 'auto', keyAmt: n ? 0.30 : 0.80, shadowOff: n ? [0, -14, 36] : [8, -18, 24], shadow: n ? 0.50 : 0.20, align: 0.9 });
const WIN = (n, screen, crop, pos, extra = {}) => ({ tex: tx(screen, n), crop, ...pos, key: BG(n), keyAmt: n ? 0.42 : 0.62, bezel: 8, radius: 13, ...extra });

// ---------- a feature panel: the words on the left, one pane on the right, one element lifted out of it ----------
function panel(o) {
  const DY = o.dy ?? -20, ty = (o.ty ?? 90) + DY, hl = o.headLines ?? 2;
  const headY = ty + 25, lineY = headY + hl * 35 + 17, ry = (o.ry ?? 318) + DY;
  return {
    css: [840, o.h || 420], fade: [36, 36, 30, 36], cam: [12, 5], pool: o.pool || [0.68, 0.52, 0.40, 0.70], clear: [[-40, -40, 300, 460]],
    soundings: o.soundings || [[350, 50, '22'], [322, 118, '80'], [338, 196, '443'], [320, 292, '6379'], [368, 386, '9100'], [470, 404, '111'], [700, 406, '8125']],
    night: merge(NIGHT, o.night || {}), day: merge(DAY, o.day || {}),
    windows: (n) => o.win(n, false).map((w) => (w.parent !== undefined ? w : { ...w, y: w.y + DY })),
    type: [
      T('kick', o.kick, 2, ty, { fontSize: '11px' }),
      T('head', o.head, 1, headY, { fontSize: '33px' }),
      T('line', o.line, 2, lineY, { fontSize: '15.5px', whiteSpace: 'normal', width: '292px' }),
      T('rule', '', 2, ry, { width: '300px' }),
      ...o.facts.map((fc, i) => T('fact', FACT(...fc), 2 + i * 102, ry + 19, { width: '92px', whiteSpace: 'normal' })),
    ],
  };
}
// The same panel for a phone: the words on top, the glass under them, the three numbers at the foot.
function panelPhone(o) {
  const ry = o.ryp ?? 600;
  return {
    css: [381, o.hp || 730], dpr: 1080 / 381, fade: [10, 10, 24, 28], cam: [8, 4], pool: o.poolPhone || [0.5, 0.54, 0.80, 0.40], chart: o.chartPhone || [0.035, 1.5, 0.10, 0.62], lines: 4, clear: [[-40, -40, 421, 188], [-40, 602, 421, 770]],
    soundings: o.soundingsPhone || [[26, 224, '22'], [334, 228, '443'], [16, 560, '9100'], [152, 574, '80'], [326, 564, '8125']],
    night: merge(NIGHT, o.night || {}), day: merge(DAY, o.day || {}),
    windows: (n) => o.win(n, true),
    type: [
      T('kick', o.kick, 4, 24, { fontSize: '10.5px' }),
      T('head', o.head, 2, 47, { fontSize: '30px', whiteSpace: 'normal', width: '376px' }),
      T('line', o.line, 4, 47 + (o.headLinesPhone ?? 2) * 32 + 14, { fontSize: '15px', whiteSpace: 'normal', width: '360px' }),
      T('rule', '', 4, ry, { width: '372px' }),
      ...o.facts.map((fc, i) => T('fact', FACT(...fc), 4 + i * 124, ry + 19, { width: '112px', whiteSpace: 'normal' })),
    ],
  };
}
// One pane and what is lifted out of it. `g` says which capture, which part of it, where it lies and what is
// lifted (`box`, or `boxes` for two); `g.phone` says the same for the phone picture.
function glass(n, ph, g) {
  const s = ph ? { ...g, ...g.phone } : g;
  const card = (box, extra) => ({ parent: 0, box, pad: [14, 7], lift: 60, breathe: [10, 0.25], bezel: 6, radius: 10, ...LIFT(n), glow: 0.25, ...(s.card || {}), ...(extra || {}) });
  return [
    WIN(n, s.screen, s.crop, { z: ph ? -40 : -60, rot: ph ? [3, -7, 0] : [3, -13, 0], ...s.at }, { breathe: [8, 0.0], ...(s.win || {}) }),
    ...(s.boxes ? s.boxes.map(([box, extra]) => card(box, extra)) : [card(s.box)]),
  ];
}

const PANELS = {
  exposed: {
    kick: '<i>$</i> seaward scan', head: `${OVER('The firewall says closed.')}<br>The kernel says open.`,
    line: 'Seven ports can be reached from outside. ufw allows only four of them. Docker published the other three with rules of its own.',
    facts: [['{{scan.reachable}}', 'reachable from outside'], ['{{scan.allowed}}', 'of them allowed by&nbsp;ufw'], ['{{scan.exposed}}', 'exposed', true]],
    win: (n, ph) => glass(n, ph, {
      screen: 'scan', crop: [0, 0, 1144, 1054], at: { x: 586, y: 228, w: 364 }, box: 'verdict', card: { grow: 1.1, shift: [0, 0] },
      phone: { crop: [30, 0, 1084, 900], at: { x: 190.5, y: 392, w: 345 }, card: { grow: 1.03, pad: [6, 7], lift: 46, shift: [2, 0] }, win: { until: 'rewritten' } },
    }),
  },
  why: {
    kick: '<i>$</i> seaward why 5432', head: 'Every answer<br>names its rule.',
    line: 'Ask about one port and Seaward walks a packet through the loaded rules. It quotes the rule that rewrote it and the rule that let it in.',
    facts: [['{{why.steps}}', 'steps on this packet&rsquo;s path'], ['{{why.rules}}', 'rules quoted as they are&nbsp;loaded'], ['{{why.packets}}', 'packets followed, IPv4 and&nbsp;IPv6']],
    win: (n, ph) => glass(n, ph, {
      screen: 'why', crop: [0, 548, 1144, 1054], at: { x: 586, y: 228, w: 364 }, boxes: [['rewrite', { shift: [0, 7] }], ['accept', { shift: [0, 7], breathe: [10, 0.6] }]], card: { grow: 1.0, pad: [14, 2], wide: 10, bezel: 4, lift: 48 }, win: { until: 'steps' },
      phone: { crop: [30, 548, 1084, 900], at: { x: 190.5, y: 392, w: 345 }, boxes: [['rewrite', { shift: [0, 6] }], ['accept', { shift: [0, 6], breathe: [10, 0.6] }]], card: { grow: 1.0, lift: 46, pad: [14, 2], wide: 8, bezel: 5 } },
    }),
  },
  kernel: {
    kick: '<i>$</i> make lab', head: 'Checked against<br>the real kernel.',
    line: 'Each scenario loads its rules into a real kernel, in a private network namespace, and sends real packets. The engine has to predict every one.',
    facts: [['{{lab.scenarios}}', 'written scenarios'], ['{{lab.probes}}', 'real packets sent'], ['{{lab.disagreements}}', 'disagreements']],
    win: (n, ph) => glass(n, ph, {
      screen: 'kernel', crop: [0, 0, 1144, 1054], at: { x: 586, y: 228, w: 364 }, box: 'result', card: { grow: 1.04, shift: [0, 0] }, win: { until: 'about' },
      // a phone's pane opens at the command: the sentence over it in the session says what the words above the pane say
      phone: { crop: [30, 100, 1084, 900], at: { x: 190.5, y: 392, w: 345 }, card: { grow: 1.12, pad: [4, 7], lift: 46, shift: [-9, -1.5] } },
    }),
  },
  unknown: {
    kick: '<i>$</i> seaward scan <i>&nbsp;# without sudo</i>', head: 'When it cannot know,<br>it says so.',
    line: 'Without root the kernel keeps its firewall rules to itself. Seaward then marks every port undecided. It does not guess that one is closed.',
    facts: [['{{unknown.undecided}}', 'ports left undecided'], ['{{unknown.unread}}', 'rule sets it could not&nbsp;read'], ['{{unknown.called}}', 'ports called open or&nbsp;closed']],
    win: (n, ph) => glass(n, ph, {
      screen: 'unknown', crop: [0, 0, 1144, 1054], at: { x: 586, y: 228, w: 364 }, box: 'verdict', card: { grow: 1.1, shift: [0, 0] },
      phone: { crop: [30, 0, 1084, 900], at: { x: 190.5, y: 392, w: 345 }, card: { grow: 1.04, pad: [6, 7], lift: 46, shift: [0, 0] } },
    }),
  },
  snapshot: {
    kick: '<i>$</i> seaward snapshot --script', head: 'Read a server<br>from your laptop.',
    line: 'The collector is a short shell script of read-only commands. Run it on the server, carry the text file back, and scan it anywhere.',
    facts: [['{{snapshot.lines}}', 'lines of plain shell'], ['1', 'text file to carry&nbsp;back'], ['0', 'things installed on the&nbsp;server']],
    win: (n, ph) => glass(n, ph, {
      screen: 'snapshot', crop: [0, 0, 1144, 1054], at: { x: 586, y: 228, w: 364 }, box: 'script', card: { grow: 1.0, shift: [0, -7] },
      phone: { crop: [30, 0, 1084, 900], at: { x: 190.5, y: 392, w: 345 }, card: { grow: 1.0, lift: 46, shift: [0, -6] } },
    }),
  },
};

// ---------- the numbers ----------
const FIGURES = NUMBERS.figures.map((f) => [f.value, f.label]);
const NUMBER_COLS = [156, 178, 124, 142, 150];      // how wide each of the five columns is: a label takes two lines at most

export const LAYOUTS = {
  numbers: {
    css: [840, 168], fade: [30, 30, 20, 20], cam: [6, 2], pool: [0.5, 0.5, 0.78, 1.5], chart: [0.085, 1.8, 0.05, 0.6], lines: 4,
    soundings: [],
    night: merge(NIGHT, { env: { glows: [[0.5, 0.5, 0.5, 0.03, '#1f5d86']] } }), day: DAY,
    windows: () => [{ x: 420, y: 84, w: 776, crop: [0, 0, 776, 100], z: 0, rot: [0, 0, 0], bezel: 10, radius: 14, breathe: [4, 0], glow: 0.0, shadowOff: [0, -10, 36] }],
    type: FIGURES.map(([v, l], i) => T('big', `<b style="font-size:40px">${v}</b><span style="font-size:12.5px;margin-top:9px;color:var(--ink2);white-space:normal;width:${NUMBER_COLS[i] - 22}px">${l}</span>`,
      58 + NUMBER_COLS.slice(0, i).reduce((a, b) => a + b, 0), 44)),
  },
  // a phone gets the five as a list: the figure, then what it counts, one to a line
  'numbers-phone': {
    css: [381, 388], dpr: 1080 / 381, fade: [16, 16, 18, 18], cam: [4, 2], pool: [0.5, 0.5, 0.85, 1.25], chart: [0.03, 1.8, 0.02, 0.6], lines: 3,
    soundings: [],
    night: merge(NIGHT, { env: { glows: [[0.5, 0.5, 0.6, 0.03, '#1f5d86']] } }), day: DAY,
    windows: () => [{ x: 190.5, y: 194, w: 337, crop: [0, 0, 337, 324], z: 0, rot: [0, 0, 0], bezel: 10, radius: 14, breathe: [3, 0], glow: 0.0, shadowOff: [0, -10, 30] }],
    type: FIGURES.flatMap(([v, l], i) => [
      ...(i ? [T('hair', '', 44, 57 + i * 60 - 13, { width: '293px' })] : []),
      T('big', `<b style="font-size:33px">${v}</b>`, 44, 57 + i * 60),
      T('big', `<span style="font-size:14px;color:var(--ink2);white-space:normal;width:178px">${l}</span>`, 160, 57 + i * 60 + (l.length > 26 ? 0 : 10)),
    ]),
  },
};
for (const [name, o] of Object.entries(PANELS)) { LAYOUTS[name] = panel(o); LAYOUTS[`${name}-phone`] = panelPhone(o); }

// ---------- the hero ----------
// Three real surfaces: the demo's chart of shop-1 (1024 px wide), the head of the same page at a phone's width,
// and a terminal with the same scan. The loop does what a visitor does: it reads the verdict, opens the lane of
// port 5432 and watches its packet drawn rule by rule, then picks the fixed server in the sample switcher.
// What happens in the glass is capture.cjs's photographs of the page, one for each frame; only the lifting is ours.
// Lifted in turn: the lane of the exposed port, the way its packet took, and the fixed server's verdict.
const frac = (x) => x - Math.floor(x), ease = (x) => x * x * (3 - 2 * x);
const TURN = REPLAY.turn, OPEN = TURN + 1, FIXED = TURN + 2;   // the chart's frames: 0 at rest, 1..TURN the passage being drawn, OPEN, FIXED
const HERO_LOOP = { hold: 20, sink: 5, open: 2, draw: TURN, land: 2, rise: 6, read: 22, drop: 5, fix: 3, up: 6, rest: 18, down: 5, back: 3, lift: 6 };
export const HERO_FRAMES = Object.values(HERO_LOOP).reduce((a, b) => a + b, 0);
// Where the loop stands at a phase: which photograph each pane shows (two of them and how far between, where one
// gives way to the next) and how far out each lifted element is.
function heroPlay(phase) {
  let f = Math.round(frac(phase) * HERO_FRAMES * 1000) / 1000, u = 0;
  const part = (name) => { const n = HERO_LOOP[name]; if (f < n) { u = (f + 1) / (n + 1); return true; } f -= n; return false; };
  const on = (i) => ({ from: i, to: i, mix: 0 }), go = (a, b) => ({ from: a, to: b, mix: ease(u) });
  const at = (chart, head, out = {}) => ({ cues: { chart, head, lane: { lift: 0 }, track: { lift: 0 }, kept: { lift: 0 }, ...out } });
  if (part('hold')) return at(on(0), on(0), { lane: { lift: 1 } });                   // shop-1: seven reachable, four allowed
  if (part('sink')) return at(on(0), on(0), { lane: { lift: 1 - ease(u) } });
  if (part('open')) return at(go(0, 1), on(0));                                       // the lane of 5432 is opened
  if (part('draw')) return at(on(1 + Math.floor(f)), on(0));                          // its packet is drawn, one photograph a frame
  if (part('land')) return at(go(TURN, OPEN), on(0));
  if (part('rise')) return at(on(OPEN), on(0), { track: { lift: ease(u) } });
  if (part('read')) return at(on(OPEN), on(0), { track: { lift: 1 } });               // the way it took, to the rule that let it in
  if (part('drop')) return at(on(OPEN), on(0), { track: { lift: 1 - ease(u) } });
  if (part('fix')) return at(go(OPEN, FIXED), go(0, 1));                              // the fixed server is chosen
  if (part('up')) return at(on(FIXED), on(1), { kept: { lift: ease(u) } });
  if (part('rest')) return at(on(FIXED), on(1), { kept: { lift: 1 } });               // reachable and allowed agree
  if (part('down')) return at(on(FIXED), on(1), { kept: { lift: 1 - ease(u) } });
  if (part('back')) return at(go(FIXED, 0), go(1, 0));
  part('lift'); return at(on(0), on(0), { lane: { lift: ease(u) } });
}
const MARK = '<svg viewBox="0 0 24 24" aria-hidden="true"><path d="M15.5 2v6.5M15.5 15.5V22"/><path d="M2 12h17"/><circle cx="20.25" cy="12" r="2.25"/></svg>';
const SAYS = 'Which ports on this server can really be reached from outside, and the rule that decides each one.';
const shots = (name, n) => Array.from({ length: FIXED + 1 }, (_, i) => tx(`${name}-${String(i).padStart(2, '0')}`, n));
const heads = (n) => [tx('m-head-00', n), tx('m-head-01', n)], says = (n) => [tx('m-say-00', n), tx('m-say-01', n)], scans = (n) => [tx('scan', n), tx('fixed', n)];
const CARD = (n, o) => ({ parent: 1, pad: [10, 0], lift: 66, bezel: 5, radius: 9, breathe: [6, 0.25], afloat: true, glow: 0.25, ...LIFT(n), ...o });

LAYOUTS.hero = {
  css: [840, 560], fade: [40, 40, 30, 46], cam: [10, 4], motion: 0.75, pool: [0.56, 0.50, 0.62, 0.70], play: heroPlay, frames: HERO_FRAMES, driftEvery: 2, moored: true,
  clear: [[-40, -40, 430, 172]],
  soundings: [[470, 58, '8125'], [520, 150, '111'], [236, 232, '53'], [30, 222, '22'], [244, 430, '80'], [226, 528, '443'], [470, 530, '9100'], [700, 524, '8443']],
  night: NIGHT, day: DAY,
  windows: (n) => [
    WIN(n, 'scan', [0, 0, 1144, 746], { x: 664, y: 124, w: 284, z: -420, rot: [4, -14, 0] }, { seq: scans(n), cue: 'head', still: true, fog: 0.18 }),
    WIN(n, 'chart-00', [0, 0, 2048, 1048], { x: 514, y: 358, w: 478, z: -60, rot: [3, -11, 0] }, { seq: shots('chart', n), cue: 'chart', still: true, snap: false }),
    WIN(n, 'm-head-00', [0, 0, 1170, 1800], { x: 120, y: 378, w: 158, z: 110, rot: [2, 9, 0] }, { seq: heads(n), cue: 'head', still: true, snap: false, radius: 15 }),
    CARD(n, { frame: 0, box: 'lane', cue: 'lane', pad: [10, -10], grow: 0.95, lift: 56, shift: [-1, 0.6] }),
    CARD(n, { frame: OPEN, box: 'track', cue: 'track', pad: [14, 2], shift: [-1, 0] }),
    CARD(n, { parent: 2, frame: 1, box: 'say', cue: 'kept', pad: [30, 24], lift: 56, grow: 1.04, shift: [0.4, 0] }),
  ],
  type: [
    T('name', MARK + 'Seaward', 0, 30, { fontSize: '58px' }),
    T('line', SAYS, 2, 108, { fontSize: '16.5px', whiteSpace: 'normal', width: '384px' }),
  ],
};

// A phone gets the same three surfaces and the same loop, with the chart as the demo draws it at a phone's width.
// The head of the page is shown as far as the verdict and no further (m-say), so that the pane can be large enough
// for its words to be read on a phone: the sample switcher under it is small print at this size.
LAYOUTS['hero-phone'] = {
  css: [381, 640], dpr: 1080 / 381, fade: [14, 14, 24, 30], cam: [7, 3], motion: 0.75, pool: [0.52, 0.62, 0.85, 0.55], chart: [0.035, 1.5, 0.10, 0.62], lines: 5, play: heroPlay, frames: HERO_FRAMES, driftEvery: 2, moored: true,
  clear: [[-40, -40, 421, 150]],
  soundings: [[20, 196, '22'], [28, 562, '80'], [182, 606, '443'], [300, 606, '9100'], [46, 262, '53']],
  night: NIGHT, day: DAY,
  windows: (n) => [
    WIN(n, 'scan', [0, 0, 1144, 620], { x: 232, y: 214, w: 252, z: -360, rot: [4, -10, 0] }, { seq: scans(n), cue: 'head', still: true, fog: 0.18 }),
    WIN(n, 'm-chart-00', [0, 0, 1170, 1752], { x: 262, y: 426, w: 204, z: -40, rot: [2, -8, 0] }, { seq: shots('m-chart', n), cue: 'chart', still: true, snap: false, radius: 15 }),
    WIN(n, 'm-say-00', [24, 0, 1122, 1083], { x: 84, y: 500, w: 144, z: 30, rot: [2, 9, 0] }, { seq: says(n), cue: 'head', still: true, snap: false, radius: 14 }),
    CARD(n, { frame: 0, box: 'lane', cue: 'lane', pad: [0, 0], grow: 0.93, lift: 50, shift: [-0.4, -0.2] }),
    CARD(n, { frame: OPEN, box: 'track', cue: 'track', pad: [24, 16], lift: 50, shift: [-0.4, 0] }),
    CARD(n, { parent: 2, frame: 1, box: 'say', cue: 'kept', pad: [30, 24], lift: 44, grow: 1.04, shift: [0.3, 0] }),
  ],
  type: [
    T('name', MARK + 'Seaward', 2, 20, { fontSize: '46px' }),
    T('line', SAYS, 4, 82, { fontSize: '15px', whiteSpace: 'normal', width: '366px' }),
  ],
};

// The plate for the repository's social preview and the demo's link card: the same page at a phone's width, its
// verdict on one pane and its chart on the other, the lane of the exposed port lifted. A still, dark only.
LAYOUTS.social = {
  css: [640, 320], fade: [26, 26, 22, 26], cam: [0, 0], motion: 0, pool: [0.70, 0.52, 0.46, 0.80],
  clear: [[-40, -40, 300, 360]],
  soundings: [[318, 36, '22'], [316, 296, '443'], [470, 22, '8125'], [552, 300, '9100']],
  night: NIGHT, day: DAY,
  windows: (n) => [
    WIN(n, 'm-head-00', [0, 0, 1170, 1746], { x: 368, y: 164, w: 128, z: -90, rot: [2, 10, 0] }, { snap: false, radius: 14 }),
    WIN(n, 'm-chart-00', [0, 0, 1170, 1230], { x: 522, y: 160, w: 172, z: -20, rot: [2, -9, 0] }, { snap: false, radius: 14 }),
    CARD(n, { box: 'lane', pad: [14, 0], grow: 0.92, lift: 46, shift: [-0.4, -0.2] }),
  ],
  type: [
    T('name', MARK + 'Seaward', 30, 92, { fontSize: '46px' }),
    T('line', SAYS, 32, 154, { fontSize: '14.5px', whiteSpace: 'normal', width: '246px' }),
  ],
};

for (const k in LAYOUTS) LAYOUTS[k].dpr = LAYOUTS[k].dpr || 2;
// the inks a picture's words may name: var(--ink2) and var(--alarm)
export const INKS = { night: { '--ink2': '#94a2ae', '--alarm': ALARM(true) }, day: { '--ink2': '#50606c', '--alarm': ALARM(false) } };
