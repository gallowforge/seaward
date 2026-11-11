// Glass: real pages and real tool output as panes of frosted glass, lying over a sea chart.
// A small custom compositor on three.js: the chart (water, depth contours that ring the glass, soundings) ->
// per-pane backdrop blur -> glass shader (frost, bevel refraction, chromatic edge, rim light, keyed content) ->
// bloom -> composite. Everything is a periodic function of one phase, so any loop length closes perfectly.
import * as THREE from 'three';
import { LAYOUTS, INKS } from './layouts.js';
THREE.ColorManagement.enabled = false;   // colours are display values, as written

const Q = new URLSearchParams(location.search);
const LAYOUT = LAYOUTS[Q.get('layout') || 'hero'];
const NIGHT = (Q.get('theme') || 'dark') === 'dark';
const SS = +(Q.get('ss') || 2);                       // supersampling factor
const DPR = window.devicePixelRatio || 1;
const [CW, CH] = LAYOUT.css;                         // CSS size of the image
const OW = Math.round(CW * DPR), OH = Math.round(CH * DPR);
const IW = OW * SS, IH = OH * SS;                     // internal render size
const TH = NIGHT ? LAYOUT.night : LAYOUT.day;         // theme block of the layout

const canvas = document.getElementById('c');
const renderer = new THREE.WebGLRenderer({ canvas, antialias: false, alpha: false, preserveDrawingBuffer: true, powerPreference: 'high-performance' });
renderer.setPixelRatio(DPR);
renderer.setSize(CW, CH);
renderer.autoClear = false;
renderer.outputColorSpace = THREE.LinearSRGBColorSpace; // we work in display values end to end
const MAXANISO = renderer.capabilities.getMaxAnisotropy();

const rt = (w, h, hf = true) => new THREE.WebGLRenderTarget(Math.max(1, Math.round(w)), Math.max(1, Math.round(h)), {
  type: hf ? THREE.HalfFloatType : THREE.UnsignedByteType, minFilter: THREE.LinearFilter, magFilter: THREE.LinearFilter,
  depthBuffer: false, stencilBuffer: false, generateMipmaps: false, wrapS: THREE.ClampToEdgeWrapping, wrapT: THREE.ClampToEdgeWrapping });

const rtScene = rt(IW, IH);
const LEVELS = 6;
const down = [], up = [];
for (let i = 1; i <= LEVELS; i++) down.push(rt(IW / 2 ** i, IH / 2 ** i));
for (let i = 1; i <= LEVELS; i++) up.push(rt(IW / 2 ** i, IH / 2 ** i));
const bDown = [], bUp = [];
for (let i = 1; i <= 6; i++) { bDown.push(rt(IW / 2 ** i, IH / 2 ** i)); bUp.push(rt(IW / 2 ** i, IH / 2 ** i)); }

// ---------- fullscreen passes ----------
const FSV = `varying vec2 vUv; void main(){ vUv = position.xy * 0.5 + 0.5; gl_Position = vec4(position.xy, 0.0, 1.0); }`;
const fsGeo = new THREE.BufferGeometry();
fsGeo.setAttribute('position', new THREE.Float32BufferAttribute([-1, -1, 0, 3, -1, 0, -1, 3, 0], 3));
const fsMesh = new THREE.Mesh(fsGeo); fsMesh.frustumCulled = false;
const fsScene = new THREE.Scene(); fsScene.add(fsMesh);
const fsCam = new THREE.OrthographicCamera(-1, 1, 1, -1, 0, 1);
const fsMat = (frag, uniforms, extra = {}) => new THREE.ShaderMaterial({ vertexShader: FSV, fragmentShader: frag, uniforms, depthTest: false, depthWrite: false, ...extra });
function pass(mat, target, clear = true) {
  fsMesh.material = mat; renderer.setRenderTarget(target);
  if (clear) renderer.clear(true, false, false);
  renderer.render(fsScene, fsCam);
}

const GLSL_COMMON = /* glsl */`
float hash12(vec2 p){ vec3 p3 = fract(vec3(p.xyx) * .1031); p3 += dot(p3, p3.yzx + 33.33); return fract((p3.x + p3.y) * p3.z); }
float vnoise(vec2 p){ vec2 i = floor(p), f = fract(p); vec2 u = f*f*(3.0-2.0*f);
  return mix(mix(hash12(i), hash12(i+vec2(1,0)), u.x), mix(hash12(i+vec2(0,1)), hash12(i+vec2(1,1)), u.x), u.y); }
float fbm(vec2 p){ float s = 0.0, a = 0.5; mat2 m = mat2(1.6, 1.2, -1.2, 1.6); for (int i = 0; i < 5; i++){ s += a * vnoise(p); p = m * p; a *= 0.5; } return s; }
float sdRoundBox(vec2 p, vec2 b, float r){ vec2 q = abs(p) - b + r; return length(max(q, 0.0)) + min(max(q.x, q.y), 0.0) - r; }
vec2 sdRoundBoxDir(vec2 p, vec2 b, float r){ vec2 q = abs(p) - b + r; vec2 g;
  if (q.x > 0.0 && q.y > 0.0) g = normalize(q); else g = (q.x > q.y) ? vec2(1.0, 0.0) : vec2(0.0, 1.0);
  return g * sign(p + 1e-6); }
`;

const DOWN = fsMat(/* glsl */`
uniform sampler2D tSrc; uniform vec2 uTexel; uniform float uOff; uniform float uThresh; uniform float uKnee; varying vec2 vUv;
vec3 pre(vec3 c){ if (uThresh <= 0.0) return c; float l = max(c.r, max(c.g, c.b)); float s = clamp(l - uThresh + uKnee, 0.0, 2.0*uKnee); s = s*s/(4.0*uKnee + 1e-4); return c * max(s, l - uThresh) / max(l, 1e-4); }
void main(){ vec2 o = uTexel * uOff;
  vec3 s = pre(texture2D(tSrc, vUv).rgb) * 4.0;
  s += pre(texture2D(tSrc, vUv - o).rgb); s += pre(texture2D(tSrc, vUv + o).rgb);
  s += pre(texture2D(tSrc, vUv + vec2(o.x, -o.y)).rgb); s += pre(texture2D(tSrc, vUv - vec2(o.x, -o.y)).rgb);
  gl_FragColor = vec4(s / 8.0, 1.0); }`, { tSrc: { value: null }, uTexel: { value: new THREE.Vector2() }, uOff: { value: 1 }, uThresh: { value: 0 }, uKnee: { value: 0.2 } });
const UP = fsMat(/* glsl */`
uniform sampler2D tSrc; uniform sampler2D tAdd; uniform float uAddW; uniform vec2 uTexel; uniform float uOff; varying vec2 vUv;
void main(){ vec2 h = uTexel * 0.5 * uOff; vec3 s = vec3(0.0);
  s += texture2D(tSrc, vUv + vec2(-h.x*2.0, 0.0)).rgb; s += texture2D(tSrc, vUv + vec2(-h.x, h.y)).rgb * 2.0;
  s += texture2D(tSrc, vUv + vec2(0.0, h.y*2.0)).rgb; s += texture2D(tSrc, vUv + vec2(h.x, h.y)).rgb * 2.0;
  s += texture2D(tSrc, vUv + vec2(h.x*2.0, 0.0)).rgb; s += texture2D(tSrc, vUv + vec2(h.x, -h.y)).rgb * 2.0;
  s += texture2D(tSrc, vUv + vec2(0.0, -h.y*2.0)).rgb; s += texture2D(tSrc, vUv + vec2(-h.x, -h.y)).rgb * 2.0;
  vec3 c = s / 12.0; if (uAddW > 0.0) c = mix(c, texture2D(tAdd, vUv).rgb, uAddW);
  gl_FragColor = vec4(c, 1.0); }`, { tSrc: { value: null }, tAdd: { value: null }, uAddW: { value: 0 }, uTexel: { value: new THREE.Vector2() }, uOff: { value: 1 } });

// Blur `src` through a down/up chain; returns {sharp, frost}
function blurChain(src, dn, upl, levels, off, thresh = 0) {
  let s = src;
  for (let i = 0; i < levels; i++) {
    DOWN.uniforms.tSrc.value = s.texture; DOWN.uniforms.uTexel.value.set(1 / s.width, 1 / s.height);
    DOWN.uniforms.uOff.value = off; DOWN.uniforms.uThresh.value = i === 0 ? thresh : 0;
    pass(DOWN, dn[i]); s = dn[i];
  }
  for (let i = levels - 2; i >= 1; i--) {
    UP.uniforms.tSrc.value = s.texture; UP.uniforms.uTexel.value.set(1 / s.width, 1 / s.height); UP.uniforms.uOff.value = off;
    UP.uniforms.uAddW.value = 0;
    pass(UP, upl[i]); s = upl[i];
  }
  return { sharp: dn[0], frost: s };
}

// ---------- the chart ----------
// Deep water by night, paper by day. The panes of glass are the land: depth contours ring them, closer together
// near the glass, and the water between the nearest of them takes the shallow tint, in steps, as a chart prints it.
// The soundings are drawn once into a texture (the sample server's own port numbers), so they lie on the chart
// and blur behind the glass like everything else on it.
const E = TH.env;
const MAXW = 8;
const ENV = fsMat(/* glsl */`
${GLSL_COMMON}
uniform vec2 uRes; uniform float uPhase; uniform vec2 uCamOff; uniform float uDay;
uniform vec3 uTop, uBot, uHaze; uniform float uHazeStr;
uniform vec4 uGlow[4]; uniform vec3 uGlowCol[4];
uniform vec4 uQa[${MAXW}]; uniform vec4 uQb[${MAXW}]; uniform vec4 uQc[${MAXW}]; uniform float uShadowStr; uniform vec3 uShadowCol;
uniform vec4 uRa[${MAXW}]; uniform vec4 uRb[${MAXW}]; uniform float uRn[${MAXW}];
uniform vec3 uShoal, uLine; uniform vec4 uChart; uniform vec4 uChartK; uniform float uTide; uniform float uLineFall;
uniform sampler2D tInk; uniform vec3 uInk; uniform float uInkAmt;
uniform vec3 uPage; uniform vec4 uPool; uniform vec4 uClear[2]; uniform vec2 uCss;
varying vec2 vUv;
float sdQuad(vec2 p, vec2 a, vec2 b, vec2 c, vec2 d){
  vec2 v[4]; v[0]=a; v[1]=b; v[2]=c; v[3]=d;
  float dd = dot(p - v[0], p - v[0]); float s = 1.0;
  for (int i = 0, j = 3; i < 4; j = i, i++){
    vec2 e = v[j] - v[i]; vec2 w = p - v[i];
    vec2 b2 = w - e * clamp(dot(w, e) / dot(e, e), 0.0, 1.0); dd = min(dd, dot(b2, b2));
    bvec3 cnd = bvec3(p.y >= v[i].y, p.y < v[j].y, e.x * w.y > e.y * w.x);
    if (all(cnd) || all(not(cnd))) s *= -1.0;
  }
  return s * sqrt(dd);
}
float smin(float a, float b, float k){ float h = clamp(0.5 + 0.5 * (b - a) / k, 0.0, 1.0); return mix(b, a, h) - k * h * (1.0 - h); }
void main(){
  float asp = uRes.x / uRes.y; float th = uPhase * 6.2831853;
  vec2 A = vec2(asp, 1.0);
  vec2 uv = vUv + uCamOff;
  vec2 p = vec2(uv.x * asp, uv.y);
  vec3 c = mix(uBot, uTop, smoothstep(0.0, 1.0, uv.y));
  // water is never one flat colour
  float h1 = fbm(p * 1.4 + vec2(cos(th), sin(th)) * 0.20 + 3.1);
  float h2 = fbm(p * 2.9 - vec2(sin(th), cos(th)) * 0.14 + 7.7);
  float haze = smoothstep(0.25, 0.85, h1 * 0.65 + h2 * 0.45);
  c = mix(c, uHaze, haze * uHazeStr);
  for (int i = 0; i < 4; i++){
    vec4 g = uGlow[i]; if (g.w <= 0.0) continue;
    vec2 gp = vec2(g.x * asp, g.y);
    float dd = length((p - gp) * vec2(1.0, 1.3)) / g.z;
    c += uGlowCol[i] * g.w * exp(-dd * dd * 2.2);
  }
  // the stage: outside it the scene is exactly the page colour, so the image has no box
  vec2 pq = (vUv - uPool.xy) / uPool.zw;
  float pool = 1.0 - smoothstep(0.45, 1.0, length(pq));
  pool = pool * pool * (3.0 - 2.0 * pool);
  // depth: how far this point of the chart is from the nearest pane, as the panes stood at the start of the loop
  float d = 1e3; float lineAmt = 0.0;
  float reach = 1.0 - smoothstep(0.62, 1.32, length(pq));     // the lines and the soundings run further out than the tint
  for (int i = 0; i < ${MAXW}; i++){
    if (uRn[i] <= 0.0) continue;
    d = smin(d, sdQuad(p, uRa[i].xy * A, uRa[i].zw * A, uRb[i].xy * A, uRb[i].zw * A) / uRn[i], 0.05);
  }
  if (d < 100.0){
    // the contours hug the glass and wander more the further out they lie
    float wander = (fbm(p * 1.6 + 11.3 + vec2(cos(th), sin(th)) * uTide) - 0.5) * 1.5 + (fbm(p * 4.3 + 4.7 - vec2(sin(th), cos(th)) * uTide) - 0.5) * 0.45;
    float dd = max(d + uChart.z * wander * smoothstep(0.0, 0.2, d), 0.0);
    float u = log(1.0 + dd / uChart.x) / log(uChart.y);      // a contour wherever u is a whole number
    float band = floor(u);
    c = mix(c, uShoal, clamp(uChartK.x * pow(uChartK.y, band), 0.0, 1.0) * mix(1.0, pool, 0.6));
    float k = floor(u + 0.5);
    float e = abs(u - k) / max(fwidth(u), 1e-5);              // pixels to the nearest contour
    float line = (1.0 - smoothstep(uChartK.z - 0.7, uChartK.z + 0.7, e)) * step(0.5, k) * step(k, uChartK.w + 0.5);
    lineAmt = clamp(line * uChart.w * pow(uLineFall, k - 1.0), 0.0, 1.0) * reach;
  }
  // nothing is drawn where the words stand
  float open = 1.0;
  for (int i = 0; i < 2; i++){
    vec4 r = uClear[i]; if (r.z <= r.x) continue;
    vec2 q = max(max(r.xy - vUv, vUv - r.zw), 0.0) * uCss;
    open *= smoothstep(0.0, 26.0, length(q));
  }
  c = mix(uPage, c, pool);
  // soundings, and the contours broken round them
  vec2 ink = texture2D(tInk, uv).rg;
  c = mix(c, uLine, lineAmt * open * (1.0 - smoothstep(0.1, 0.6, ink.g)));
  c = mix(c, uInk, ink.r * uInkAmt * reach * open);
  // day: the glass lies a little above the paper and shades it
  if (uDay > 0.5){
    float shade = 0.0;
    for (int i = 0; i < ${MAXW}; i++){
      vec4 qa = uQa[i]; if (uQc[i].w <= 0.0) continue;
      vec4 qb = uQb[i]; vec2 off = uQc[i].xy; float blur = uQc[i].z;
      float ds = sdQuad(p - off, qa.xy * A, qa.zw * A, qb.xy * A, qb.zw * A) + 0.012;
      shade = max(shade, (1.0 - smoothstep(-blur, blur, ds)) * uQc[i].w);
    }
    c *= mix(vec3(1.0), uShadowCol, shade * uShadowStr);
  }
  gl_FragColor = vec4(c, 1.0);
}`, {
  uRes: { value: new THREE.Vector2(IW, IH) }, uPhase: { value: 0 }, uCamOff: { value: new THREE.Vector2() }, uDay: { value: NIGHT ? 0 : 1 },
  uTop: { value: new THREE.Color(E.top) }, uBot: { value: new THREE.Color(E.bot) }, uHaze: { value: new THREE.Color(E.haze) }, uHazeStr: { value: E.hazeStr },
  uGlow: { value: [0, 1, 2, 3].map(i => E.glows && E.glows[i] ? new THREE.Vector4(...E.glows[i].slice(0, 4)) : new THREE.Vector4(0, 0, 1, 0)) },
  uGlowCol: { value: [0, 1, 2, 3].map(i => new THREE.Color(E.glows && E.glows[i] ? E.glows[i][4] : '#000')) },
  uQa: { value: Array.from({ length: MAXW }, () => new THREE.Vector4()) }, uQb: { value: Array.from({ length: MAXW }, () => new THREE.Vector4()) },
  uQc: { value: Array.from({ length: MAXW }, () => new THREE.Vector4()) }, uShadowStr: { value: E.shadow || 0 }, uShadowCol: { value: new THREE.Color(E.shadowCol || '#fff') },
  uRa: { value: Array.from({ length: MAXW }, () => new THREE.Vector4()) }, uRb: { value: Array.from({ length: MAXW }, () => new THREE.Vector4()) },
  uRn: { value: Array.from({ length: MAXW }, () => 0) },
  // chart: [first depth, growth from one contour to the next, how far they wander, line strength]; chartK: [shoal tint, its falloff per band, line half-width px, lines]
  uShoal: { value: new THREE.Color(E.shoal) }, uLine: { value: new THREE.Color(E.line) },
  uChart: { value: new THREE.Vector4(...(LAYOUT.chart || E.chart)) },
  uChartK: { value: new THREE.Vector4(E.shoalStr, E.shoalFall, (E.lineWidth ?? 0.5) * DPR * SS, LAYOUT.lines ?? E.lines ?? 6) }, uTide: { value: LAYOUT.tide ?? 0 }, uLineFall: { value: E.lineFall ?? 0.84 },
  tInk: { value: null }, uInk: { value: new THREE.Color(E.ink) }, uInkAmt: { value: E.inkAmt ?? 0 },
  uPage: { value: new THREE.Color(TH.page) }, uPool: { value: new THREE.Vector4(...(LAYOUT.pool || [0.5, 0.5, 0.75, 0.85])) },
  // clear: up to two boxes [left, top, right, bottom] in CSS px that the chart keeps free for the words
  uCss: { value: new THREE.Vector2(CW, CH) },
  uClear: { value: [0, 1].map(i => { const r = (LAYOUT.clear || [])[i]; return r ? new THREE.Vector4(r[0] / CW, 1 - r[3] / CH, r[2] / CW, 1 - r[1] / CH) : new THREE.Vector4(0, 0, 0, 0); }) },
}, { extensions: { derivatives: true } });

// The soundings: [x, y, text, size] in CSS px of the picture, set in the italic the demo uses for a port number.
async function soundings() {
  const cv = document.createElement('canvas'); cv.width = IW; cv.height = IH;
  const x = cv.getContext('2d'), k = IW / CW;
  x.fillStyle = '#000'; x.fillRect(0, 0, IW, IH);
  await document.fonts.load('italic 500 20px "Instrument Sans"');
  x.textBaseline = 'alphabetic'; x.lineJoin = 'round';
  // red is the figure; green is the room a contour leaves round it, as a chart breaks a line for a depth
  for (const [sx, sy, text, size = 10.5] of (LAYOUT.soundings || [])) {
    x.font = `italic 500 ${size * k}px "Instrument Sans"`;
    x.filter = `blur(${1.6 * k}px)`; x.strokeStyle = '#0f0'; x.fillStyle = '#0f0'; x.lineWidth = 9 * k;
    x.strokeText(text, sx * k, sy * k); x.fillText(text, sx * k, sy * k);
  }
  x.filter = 'none'; x.globalCompositeOperation = 'lighter'; x.fillStyle = '#f00';
  for (const [sx, sy, text, size = 10.5] of (LAYOUT.soundings || [])) {
    x.font = `italic 500 ${size * k}px "Instrument Sans"`; x.fillText(text, sx * k, sy * k);
  }
  const t = new THREE.CanvasTexture(cv); t.colorSpace = THREE.NoColorSpace; t.minFilter = THREE.LinearFilter; t.magFilter = THREE.LinearFilter; t.generateMipmaps = false;
  return t;
}

// ---------- camera ----------
const FOV = 30;
const D = (CH / 2) / Math.tan(THREE.MathUtils.degToRad(FOV / 2));  // 1 world unit = 1 CSS px at z = 0
const camera = new THREE.PerspectiveCamera(FOV, CW / CH, 10, 20000);
const camStill = camera.clone();
camera.position.set(0, 0, D);

// ---------- textures ----------
const loader = new THREE.TextureLoader();
const texCache = {};
function loadTex(src) {
  if (!texCache[src]) texCache[src] = new Promise((res, rej) => loader.load('/shots/' + src, t => {
    t.colorSpace = THREE.NoColorSpace; t.anisotropy = MAXANISO; t.generateMipmaps = true;
    t.minFilter = THREE.LinearMipmapLinearFilter; t.magFilter = THREE.LinearFilter; res(t);
  }, undefined, rej));
  return texCache[src];
}
function avgColor(img, crop) {
  const c = document.createElement('canvas'); c.width = 16; c.height = 16; const x = c.getContext('2d');
  x.drawImage(img, crop[0], crop[1], crop[2], crop[3], 0, 0, 16, 16);
  const d = x.getImageData(0, 0, 16, 16).data; let r = 0, g = 0, b = 0;
  for (let i = 0; i < d.length; i += 4) { r += d[i]; g += d[i + 1]; b += d[i + 2]; }
  const n = d.length / 4; return new THREE.Color(r / n / 255, g / n / 255, b / n / 255);
}

function capColor(c, cap) { const m = Math.max(c.r, c.g, c.b); if (m > cap) c.multiplyScalar(cap / m); return c; }

// ---------- the glass window ----------
const WIN_V = /* glsl */`
varying vec2 vLocal; varying vec3 vViewPos; varying vec3 vT; varying vec3 vB; varying vec3 vN;
void main(){
  vLocal = position.xy;
  vec4 mv = modelViewMatrix * vec4(position, 1.0); vViewPos = mv.xyz;
  vT = normalize(normalMatrix * vec3(1.0, 0.0, 0.0)); vB = normalize(normalMatrix * vec3(0.0, 1.0, 0.0)); vN = normalize(normalMatrix * vec3(0.0, 0.0, 1.0));
  gl_Position = projectionMatrix * mv;
}`;
const WIN_F = /* glsl */`
${GLSL_COMMON}
uniform vec2 uRes; uniform sampler2D tFrost; uniform sampler2D tSharp;
uniform vec2 uHalf; uniform float uRadius; uniform float uBevel;
uniform sampler2D tContent; uniform sampler2D tContentB; uniform vec2 uTexSizeB; uniform float uMix; uniform float uHoleAmt[3]; uniform float uOpacity; uniform float uHasContent; uniform vec4 uCRect; uniform float uCRadius; uniform vec4 uCrop; uniform vec2 uTexSize;
uniform vec3 uKey; uniform float uKeyAmt; uniform float uLodBias; uniform float uDefocus;
uniform float uNight; uniform vec3 uTintAdd; uniform float uTransmit; uniform float uFog; uniform vec3 uFogCol;
uniform vec3 uLightPos; uniform float uRim; uniform float uSpec; uniform vec3 uGlowCol; uniform float uGlow; uniform float uShadow;
uniform vec4 uShadowOff; uniform vec4 uHole[3]; uniform float uContentGain; uniform float uRefract; uniform float uPhase; uniform float uCaustic;
uniform float uNeat; uniform vec3 uNeatCol; uniform float uNeatAmt; uniform float uHoleGhost;
varying vec2 vLocal; varying vec3 vViewPos; varying vec3 vT; varying vec3 vB; varying vec3 vN;

vec3 spectral(float x){ return clamp(vec3(abs(x * 6.0 - 3.0) - 1.0, 2.0 - abs(x * 6.0 - 2.0), 2.0 - abs(x * 6.0 - 4.0)), 0.0, 1.0); }

// shade the pane
vec4 glassElement(vec2 p, vec2 half_, float rad, float bevel, float d, float px, vec2 suv, out float maskOut){
  float aa = px * (1.0 + uDefocus);
  float mask = 1.0 - smoothstep(-aa, aa, d);
  maskOut = mask;
  vec2 g = sdRoundBoxDir(p, half_, rad);
  float t = clamp(-d / bevel, 0.0, 1.0);          // 0 at the edge, 1 past the bevel
  float e = 1.0 - t;
  float slope = e / sqrt(max(1.0 - e * e, 0.02));  // quarter-round profile
  slope = min(slope, 5.0);
  vec3 nl = normalize(vec3(g * slope * 0.9, 1.0));
  vec3 n = normalize(vT * nl.x + vB * nl.y + vN * nl.z);
  vec3 V = normalize(-vViewPos);
  // refraction: the bevel bends what is behind it, a little more for red than for blue
  vec2 off = -(n.xy - vN.xy) * uRefract / uRes * (0.35 + e * e * 1.6);
  float lens = smoothstep(0.0, 1.0, e);
  vec3 sharp = vec3(texture2D(tSharp, suv + off * 1.06).r, texture2D(tSharp, suv + off).g, texture2D(tSharp, suv + off * 0.94).b);
  vec3 frost = vec3(texture2D(tFrost, suv + off * 1.08).r, texture2D(tFrost, suv + off).g, texture2D(tFrost, suv + off * 0.92).b);
  vec3 behind = mix(frost, sharp, lens * 0.55);
  vec3 col = behind * uTransmit + uTintAdd;
  // light: one soft key light (top left, in front) plus its reflection sliding over the face as the camera moves
  vec3 L = normalize(uLightPos - vViewPos);
  vec3 H = normalize(L + V);
  float face = pow(max(dot(vN, H), 0.0), 14.0);
  float spec = pow(max(dot(n, H), 0.0), 90.0);
  vec2 l2 = normalize(vec2(-0.62, 0.78));
  float facing = dot(g, l2);
  float edgeLine = 1.0 - smoothstep(0.0, 1.35 * px, -d);
  float rimBand = smoothstep(bevel * 1.1, 0.0, -d);
  float rim = edgeLine * (0.30 + 0.70 * max(facing, 0.0)) + edgeLine * 0.45 * max(-facing, 0.0);
  rim += rimBand * rimBand * (0.16 * max(facing, 0.0) + 0.07 * max(-facing, 0.0));
  col += vec3(1.0) * (rim * uRim + spec * uSpec * e + face * uSpec * 0.08);
  // glass edges in daylight read darker just inside the bright line (internal reflection)
  float inner = smoothstep(bevel * 1.6, bevel * 0.35, -d) * (1.0 - edgeLine);
  col *= 1.0 - inner * (uNight > 0.5 ? 0.10 : 0.07) * (0.6 + 0.4 * max(-facing, 0.0));
  // the content's own light lives in the glass around it
  col += uGlowCol * uGlow * 0.10 * smoothstep(bevel * 3.0, 0.0, -d);
  return vec4(col, 1.0);
}

void main(){
  vec2 p = vLocal;
  vec2 suv = gl_FragCoord.xy / uRes;
  float px = length(fwidth(p)) * 0.7071;
  // elements
  float dWin = sdRoundBox(p, uHalf, uRadius);
  vec3 col = vec3(0.0); float alpha = 0.0;
  // ---- outside: a soft contact shadow (day) or the screen's own light in the water around it (night)
  {
    vec2 so = uShadowOff.z > 0.5 ? uShadowOff.xy : (uNight > 0.5 ? vec2(0.0, -10.0) : vec2(3.0, -8.0));
    float blur = uShadowOff.z > 0.5 ? uShadowOff.w : (uNight > 0.5 ? 60.0 : 22.0);
    float ds = sdRoundBox(p - so, uHalf - vec2(6.0), uRadius);
    float sh = 1.0 - smoothstep(-blur, blur * 1.1, ds);
    float ds2 = sdRoundBox(p - so * 0.35, uHalf - vec2(2.0), uRadius);
    float contact = 1.0 - smoothstep(-6.0, 16.0, ds2);
    float outside = smoothstep(-0.5 * px, 1.5 * px, dWin);
    float a = (sh * 0.55 + contact * 0.45) * uShadow * outside;
    vec3 glow = vec3(0.0);
    if (uNight > 0.5) {
      float dg = max(dWin, 0.0);
      glow = uGlowCol * uGlow * (exp(-dg / 70.0) * 0.55 + exp(-dg / 18.0) * 0.45) * outside;
      glow *= 1.0 - smoothstep(60.0, 146.0, dg);   // the light is gone before this pane's mesh ends (150 out), so it leaves no box in the water
      glow *= 0.75 + 0.25 * smoothstep(uHalf.y, -uHalf.y, p.y);
    } else {
      // caustic: light focused by the bevel lands as a bright, faintly spectral line inside the shadow edge
      float dc = sdRoundBox(p - so * 1.15, uHalf - vec2(4.0), uRadius);
      float band = exp(-pow((dc + 7.0) / 5.0, 2.0)) * outside;
      float side = smoothstep(-0.2, 0.6, dot(normalize(p - so + 1e-4), normalize(so)));
      glow = (vec3(1.0, 0.97, 0.9) * 0.8 + spectral(clamp(0.5 + (dc + 7.0) / 22.0, 0.0, 1.0)) * 0.35) * band * side * uCaustic;
    }
    col = glow; alpha = a;
  }
  // ---- glass elements
  float m;
  if (dWin < 2.0 * px) {
    vec4 g = glassElement(p, uHalf, uRadius, uBevel, dWin, px, suv, m);
    vec3 c = g.rgb;
    vec2 cc = (uCRect.xy + uCRect.zw) * 0.5, ch = (uCRect.zw - uCRect.xy) * 0.5;
    float dc = sdRoundBox(p - cc, ch, uCRadius);
    // the neatline: a chart's border is two rules, so the glass carries a hairline of its own just outside what it shows
    if (uNeat > 0.0) c = mix(c, uNeatCol, (1.0 - smoothstep(0.3 * px, 1.05 * px, abs(dc - uNeat))) * uNeatAmt);
    if (uHasContent > 0.5) {
      float cm = 1.0 - smoothstep(-px * (1.0 + uDefocus), px * (1.0 + uDefocus), dc);
      if (cm > 0.0) {
        vec2 uv = (p - uCRect.xy) / (uCRect.zw - uCRect.xy);      // 0..1, y up
        vec2 tuv = vec2((uCrop.x + uv.x * uCrop.z) / uTexSize.x, 1.0 - (uCrop.y + (1.0 - uv.y) * uCrop.w) / uTexSize.y);
        vec3 s = texture2D(tContent, tuv, uLodBias).rgb;
        if (uMix > 0.0) {   // a sequence between two of its frames
          vec2 tuvB = vec2((uCrop.x + uv.x * uCrop.z) / uTexSizeB.x, 1.0 - (uCrop.y + (1.0 - uv.y) * uCrop.w) / uTexSizeB.y);
          s = mix(s, texture2D(tContentB, tuvB, uLodBias).rgb, uMix);
        }
        // un-blend the app's flat background so its UI floats on the glass
        vec3 diff = s - uKey;
        vec3 ap = max(diff / max(1.0 - uKey, 1e-3), -diff / max(uKey, 1e-3));
        float a = clamp(max(ap.r, max(ap.g, ap.b)), 0.0, 1.0);
        vec3 fg = uKey + diff / max(a, 1e-3);
        vec3 under = mix(uKey, c, uKeyAmt);
        for (int i = 0; i < 3; i++) {   // where a card was lifted out, the pane keeps only clear glass and a faint ghost
          vec4 ho = uHole[i]; if (ho.z <= ho.x) continue;
          float dh = sdRoundBox(p - (ho.xy + ho.zw) * 0.5, (ho.zw - ho.xy) * 0.5, 9.0);
          float hm = (1.0 - smoothstep(-5.0, 7.0, dh)) * uHoleAmt[i];
          a *= mix(1.0, uHoleGhost, hm); under = mix(under, c, hm * 0.85);
        }
        vec3 app = mix(under, clamp(fg, 0.0, 1.0), a) * uContentGain;
        // a hairline where the content meets the glass
        float hl = 1.0 - smoothstep(0.0, 1.2 * px, -dc);
        app = mix(app, uNight > 0.5 ? app * 0.6 : app * 0.86, hl * 0.6);
        c = mix(c, app, cm);
      }
    }
    // depth haze for far windows
    c = mix(c, uFogCol, uFog);
    col = mix(col * (1.0 - m), c, m); alpha = mix(alpha, 1.0, m);
  }
  gl_FragColor = vec4(col, alpha) * uOpacity;   // premultiplied
}`;

function makeWindow(spec, tex) {
  const scale = (D - spec.z) / D;           // spec sizes are apparent CSS px at the screen
  const bez = spec.bezel ?? 8;
  const crop = spec.crop || [0, 0, tex ? tex.image.width : 1, tex ? tex.image.height : 1];
  let cw = spec.w, chh;
  if (spec.h && !spec.w) { chh = spec.h; cw = chh * crop[2] / crop[3]; } else chh = cw * crop[3] / crop[2];
  const hw = cw / 2 + bez, hh = chh / 2 + bez;
  const half = new THREE.Vector2(hw, hh);
  const pad = 150;
  const geo = new THREE.PlaneGeometry(2 * hw + 2 * pad, 2 * hh + 2 * pad, 1, 1);
  const radius = spec.radius ?? Math.min(15, Math.min(hw, hh) * 0.2);
  const uniforms = {
    uRes: { value: new THREE.Vector2(IW, IH) }, tFrost: { value: null }, tSharp: { value: null },
    uHalf: { value: half }, uRadius: { value: radius }, uBevel: { value: spec.bevel ?? Math.min(bez * 1.25, 12) },
    tContent: { value: tex }, uHasContent: { value: tex ? 1 : 0 },
    uCRect: { value: new THREE.Vector4(-cw / 2, -chh / 2, cw / 2, chh / 2) }, uCRadius: { value: Math.max(radius - bez, 3) },
    uCrop: { value: new THREE.Vector4(...crop) }, uTexSize: { value: new THREE.Vector2(tex ? tex.image.width : 1, tex ? tex.image.height : 1) },
    uKey: { value: new THREE.Color(spec.key || '#000') }, uKeyAmt: { value: spec.keyAmt ?? 0 },
    uLodBias: { value: spec.lod ?? 0 }, uDefocus: { value: spec.defocus ?? 0 },
    uNight: { value: NIGHT ? 1 : 0 }, uTintAdd: { value: new THREE.Color(...TH.glass.tint) }, uTransmit: { value: TH.glass.transmit },
    uFog: { value: spec.fog ?? 0 }, uFogCol: { value: new THREE.Color(TH.glass.fog) },
    uLightPos: { value: new THREE.Vector3(...TH.glass.light) }, uRim: { value: TH.glass.rim }, uSpec: { value: TH.glass.spec },
    uGlowCol: { value: tex ? capColor(avgColor(tex.image, crop).multiplyScalar(spec.glowGain ?? 1.6), 0.32) : new THREE.Color(0.3, 0.3, 0.3) }, uGlow: { value: spec.glow ?? TH.glass.glow },
    uShadow: { value: spec.shadow ?? TH.glass.shadow },
    uContentGain: { value: spec.gain ?? 1 }, uRefract: { value: (spec.refract ?? 26) * DPR * SS }, uPhase: { value: 0 },
    uCaustic: { value: TH.glass.caustic ?? 0 },
    uHole: { value: [new THREE.Vector4(), new THREE.Vector4(), new THREE.Vector4()] }, uHoleAmt: { value: [1, 1, 1] }, uHoleGhost: { value: spec.ghost ?? TH.glass.ghost ?? 0.1 }, uOpacity: { value: 1 },
    uNeat: { value: spec.neat ?? TH.glass.neat ?? 0 }, uNeatCol: { value: new THREE.Color(TH.glass.neatCol || '#fff') }, uNeatAmt: { value: spec.neatAmt ?? TH.glass.neatAmt ?? 0 },
    tContentB: { value: tex }, uTexSizeB: { value: new THREE.Vector2(1, 1) }, uMix: { value: 0 },
    uShadowOff: { value: spec.shadowOff ? new THREE.Vector4(spec.shadowOff[0], spec.shadowOff[1], 1, spec.shadowOff[2]) : new THREE.Vector4() },
  };
  if (spec.glowColor) uniforms.uGlowCol.value = new THREE.Color(spec.glowColor);
  const mat = new THREE.ShaderMaterial({ vertexShader: WIN_V, fragmentShader: WIN_F, uniforms, transparent: true, depthTest: false, depthWrite: false,
    blending: THREE.CustomBlending, blendSrc: THREE.OneFactor, blendDst: THREE.OneMinusSrcAlphaFactor, blendSrcAlpha: THREE.OneFactor, blendDstAlpha: THREE.OneMinusSrcAlphaFactor,
    extensions: { derivatives: true } });
  const mesh = new THREE.Mesh(geo, mat); mesh.frustumCulled = false;
  if (spec.parentRef) mesh.matrixAutoUpdate = false; else mesh.scale.setScalar(scale);
  const sc = new THREE.Scene(); sc.add(mesh);
  // apparent centre (CSS px, y down) -> world position at depth z
  const base = new THREE.Vector3((spec.x - CW / 2) * scale, (CH / 2 - spec.y) * scale, spec.z);
  return { spec, mesh, scene: sc, mat, base, cw, chh, crop };
}

// ---------- composite ----------
const COMP = fsMat(/* glsl */`
${GLSL_COMMON}
uniform sampler2D tScene; uniform sampler2D tBloom; uniform float uBloom; uniform vec3 uPage; uniform vec2 uOut;
uniform vec4 uFade; uniform float uFadeR; uniform float uShoulder; uniform float uVig; uniform vec3 uVigCol;
varying vec2 vUv;
void main(){
  vec3 c = texture2D(tScene, vUv).rgb;
  c += texture2D(tBloom, vUv).rgb * uBloom;
  // gentle shoulder so highlights roll off instead of clipping
  vec3 over = max(c - uShoulder, 0.0); c = min(c, uShoulder) + over / (1.0 + over * 2.2);
  vec2 px = vUv * uOut;
  float dv = length((vUv - 0.5) * vec2(1.0, uOut.y / uOut.x) * 1.6);
  c = mix(c, uVigCol, smoothstep(0.35, 1.2, dv) * uVig);
  // dissolve into the page colour at the edges, so the scene has no box
  vec2 hb = uOut * 0.5;
  float d = sdRoundBox(px - hb, hb - vec2(1.0), uFadeR);
  vec2 q = min(px, uOut - px);
  float fx = smoothstep(0.0, uFade.x, q.x) * smoothstep(0.0, uFade.y, uOut.x - px.x);
  float fy = smoothstep(0.0, uFade.z, uOut.y - px.y) * smoothstep(0.0, uFade.w, px.y);
  float f = fx * fy;
  c = mix(uPage, c, f);
  c += (hash12(gl_FragCoord.xy) - 0.5) / 255.0;
  gl_FragColor = vec4(c, 1.0);
}`, { tScene: { value: rtScene.texture }, tBloom: { value: null }, uBloom: { value: TH.bloom }, uPage: { value: new THREE.Color(TH.page) },
  uOut: { value: new THREE.Vector2(OW, OH) }, uFade: { value: new THREE.Vector4(...(TH.fade || LAYOUT.fade).map(v => v * DPR)) }, uFadeR: { value: 0 }, uShoulder: { value: NIGHT ? 0.86 : 1.0 },
  uVig: { value: TH.vig ?? 0 }, uVigCol: { value: new THREE.Color(TH.page) } });

// ---------- typography ----------
// A figure written {{name.of.it}} is one the tool printed when the captures were made (facts.json).
function buildType(facts) {
  const box = document.getElementById('type');
  box.innerHTML = '';
  for (const [k, v] of Object.entries(NIGHT ? INKS.night : INKS.day)) box.style.setProperty(k, v);
  const said = (html) => html.replace(/\{\{([\w.]+)\}\}/g, (_, name) => {
    const v = name.split('.').reduce((o, k) => (o == null ? o : o[k]), facts);
    if (v === undefined || v === null) throw new Error('no figure "' + name + '" in facts.json');
    return v;
  });
  for (const t of LAYOUT.type) {
    const el = document.createElement('div');
    el.className = 'el ' + (t.cls || '');
    el.innerHTML = said(t.html);
    const st = { ...(t.style || {}), ...((NIGHT ? t.night : t.day) || {}) };
    Object.assign(el.style, st);
    el.style.left = t.x + 'px'; el.style.top = t.y + 'px';
    if (t.align === 'center') el.style.transform = 'translateX(-50%)';
    if (t.align === 'right') el.style.transform = 'translateX(-100%)';
    box.appendChild(el);
  }
}

// ---------- assemble ----------
let windows = [], ringed = false;
async function init() {
  canvas.style.width = CW + 'px'; canvas.style.height = CH + 'px';
  const specs = LAYOUT.windows(NIGHT);
  // a window with `seq` plays a list of captures (its `tex` first); LAYOUT.play says which of them, frame by frame
  const seqs = await Promise.all(specs.map(s => s.seq ? Promise.all(s.seq.map(loadTex)) : Promise.resolve(null)));
  const texes = await Promise.all(specs.map((s, i) => seqs[i] ? Promise.resolve(seqs[i][0]) : s.tex ? loadTex(s.tex) : Promise.resolve(null)));
  // boxes of the named elements of each capture, measured when it was made (texture px)
  const BOX = await fetch('/shots/boxes.json').then(r => r.json()).catch(() => ({}));
  const made = [];
  // a pane of terminal output is cut between two printed lines, never through one
  for (const s of specs) {
    const rows = s.parent === undefined && s.tex && s.crop && s.snap !== false && BOX[s.tex.replace(/\.png$/, '')] && BOX[s.tex.replace(/\.png$/, '')]._rows;
    if (!rows || !rows.length) continue;
    const near = (y, edge) => rows.map(r => r[edge]).reduce((a, b) => (Math.abs(b - y) < Math.abs(a - y) ? b : a));
    const top = s.crop[1] > 0 ? Math.max(0, near(s.crop[1], 0) - 8) : 0, bottom = near(s.crop[1] + s.crop[3], 1) + 8;
    s.crop = [s.crop[0], top, s.crop[2], bottom - top];
  }
  specs.forEach((s, i) => { if (s.parent === undefined) { made[i] = makeWindow(s, texes[i]); made[i].seq = seqs[i]; } });
  specs.forEach((s, i) => {
    if (s.parent === undefined) return;
    // what is lifted out of a playing pane comes from one moment of it: `frame` says which capture of its sequence
    const shot = s.frame !== undefined && specs[s.parent].seq ? specs[s.parent].seq[s.frame] : specs[s.parent].tex;
    const shotTex = s.frame !== undefined && seqs[s.parent] ? seqs[s.parent][s.frame] : texes[s.parent];
    if (s.box) {   // lift an element out of its page by name instead of by hand-measured pixels
      const t = shot.replace(/\.png$/, ''), page = BOX[t] ? t : t.replace(/-(dark|light)$/, ''), b = BOX[page] && BOX[page][s.box];
      if (!b) throw new Error(`no box "${s.box}" in ${page}`);
      const pad = s.pad ?? [16, 8];
      s.src = [b[0] - pad[0], b[1] - pad[1], b[2] + 2 * pad[0], b[3] + 2 * pad[1]];
      if (s.key === 'auto' && b[4]) s.key = b[4];   // the measured background behind the lifted element
      if (s.wide) { const c = specs[s.parent].crop; s.src[0] = c[0] + s.wide; s.src[2] = c[2] - 2 * s.wide; }   // as wide as its pane, less a margin
    }
    const P = made[s.parent], k = P.cw / P.crop[2], src = s.src;
    const lx = (src[0] + src[2] / 2 - P.crop[0]) * k - P.cw / 2, ly = P.chh / 2 - (src[1] + src[3] / 2 - P.crop[1]) * k;
    const spec = { ...s, tex: shot, seq: undefined, crop: src, w: src[2] * k * (s.grow ?? 1), z: P.spec.z + (s.lift ?? 60), bar: false, parentRef: P, local: [lx, ly], castShadow: 0, hole: P.holes || 0 };
    made[i] = makeWindow(spec, shotTex);
    const hw = src[2] * k / 2 + 4, hh = src[3] * k / 2 + 4;
    P.holes = (P.holes || 0) + 1;
    if (P.holes > 3) throw new Error('a pane gives up three elements at most');
    P.mat.uniforms.uHole.value[P.holes - 1].set(lx - hw, ly - hh, lx + hw, ly + hh);
  });
  windows = made.filter(Boolean);
  windows.sort((a, b) => a.spec.z - b.spec.z);
  buildType(await fetch('/shots/facts.json').then(r => r.json()).catch(() => ({})));
  await document.fonts.ready;
  ENV.uniforms.tInk.value = await soundings();
  // warm-up render so shaders compile before the first captured frame
  renderAt(0);
}

function renderAt(phase) {
  // In a loop the camera and the windows may drift on every second frame only (LAYOUT.driftEvery: 2), which halves
  // what the file has to send again. The content still moves on every frame.
  const step = LAYOUT.driftEvery && LAYOUT.frames ? LAYOUT.driftEvery / LAYOUT.frames : 0;
  const th = (step ? Math.floor(phase / step + 1e-6) * step : phase) * Math.PI * 2;
  // the content motion of a loop: which two captures a sequence stands between, and how far the lifted element is out
  // A loop with several things moving gives each its own cue: play.cues[spec.cue] says the same for that one alone.
  const play = LAYOUT.play ? LAYOUT.play(phase) : { from: 0, to: 0, mix: 0, lift: 1 };
  const cue = (s) => ({ from: 0, to: 0, mix: 0, lift: 0, ...((play.cues && play.cues[s.cue]) || play) });
  for (const w of windows) {
    const u = w.mat.uniforms, c = cue(w.spec);
    if (w.seq) {
      const a = w.seq[Math.min(w.seq.length - 1, c.from)], b = w.seq[Math.min(w.seq.length - 1, c.to)];
      u.tContent.value = a; u.uTexSize.value.set(a.image.width, a.image.height);
      u.tContentB.value = b; u.uTexSizeB.value.set(b.image.width, b.image.height); u.uMix.value = c.mix;
    }
    if (w.spec.parentRef && LAYOUT.play) {
      const out = Math.min(1, Math.max(0, c.lift / 0.5)), shown = out * out * (3 - 2 * out);
      u.uOpacity.value = shown; w.spec.parentRef.mat.uniforms.uHoleAmt.value[w.spec.hole] = shown;
    }
  }
  const cam = LAYOUT.cam || [12, 5];
  camera.position.set(Math.sin(th) * cam[0], Math.sin(th * 2) * cam[1] * 0.5 + Math.cos(th) * cam[1] * 0.5, D);
  camera.lookAt(0, 0, 0);
  camera.updateMatrixWorld();
  // a `still` window (and what is lifted out of it) keeps the pose and the view of phase 0 while the rest drifts
  // (what is lifted may be `afloat`: it then rises and sinks a little on the still pane, the one thing that stirs)
  camStill.position.set(0, cam[1] * 0.5, D); camStill.lookAt(0, 0, 0); camStill.updateMatrixWorld();
  const viewOf = (w) => ((w.spec.parentRef ? w.spec.parentRef.spec : w.spec).still ? camStill : camera);
  ENV.uniforms.uPhase.value = LAYOUT.moored ? 0 : phase;
  // In a loop whose main panes lie still (LAYOUT.moored) the chart under them lies still too: its contours ring those
  // panes, and a frame then sends again only what really moved.
  const eye = LAYOUT.moored ? camStill : camera;
  ENV.uniforms.uCamOff.value.set(-eye.position.x / CW * 0.08, -eye.position.y / CH * 0.08);
  // place the panes, then tell the chart where they lie: for their shadows now, and for its contours once
  const v = new THREE.Vector3();
  const quad = (w) => { const hv = w.mat.uniforms.uHalf.value, pts = [];
    for (const [sx, sy] of [[-1, -1], [1, -1], [1, 1], [-1, 1]]) {
      v.set(sx * hv.x, sy * hv.y, 0).applyMatrix4(w.mesh.matrixWorld).project(viewOf(w));
      pts.push(v.x * 0.5 + 0.5, v.y * 0.5 + 0.5);
    }
    return pts; };
  windows.forEach((w, i) => {
    const s = w.spec, b = s.breathe || [10, 0];
    if (s.parentRef) return;
    w.mesh.position.copy(w.base);
    const MS = LAYOUT.motion ?? 1, t = s.still ? 0 : th;
    w.mesh.position.z += Math.sin(t + b[1] * Math.PI * 2) * b[0] * MS;
    w.mesh.position.y += Math.sin(t * 1 + b[1] * 5.0) * (b[0] * 0.18) * MS;
    const r = s.rot || [0, 0, 0];
    w.mesh.rotation.set(THREE.MathUtils.degToRad(r[0] + Math.sin(t + b[1] * 4) * 0.5 * MS), THREE.MathUtils.degToRad(r[1] + Math.cos(t + b[1] * 3) * 0.7 * MS), THREE.MathUtils.degToRad(r[2] || 0));
    w.mesh.updateMatrixWorld();
    if (i < MAXW) {
      const pts = quad(w);
      ENV.uniforms.uQa.value[i].set(pts[0], pts[1], pts[2], pts[3]);
      ENV.uniforms.uQb.value[i].set(pts[4], pts[5], pts[6], pts[7]);
      const depth = Math.max(0.2, (w.mesh.position.z + 900) / 900);   // nearer panes lie further above the chart
      const sd = (E.shadowDir || [0.03, -0.05]);
      ENV.uniforms.uQc.value[i].set(sd[0] * depth, sd[1] * depth, 0.012 + 0.02 * depth, Q.has('noshadow') ? 0 : (s.castShadow ?? 1));
    }
  });
  const M = new THREE.Matrix4(), R = new THREE.Matrix4();
  for (const w of windows) {
    const s = w.spec; if (!s.parentRef) continue;
    const up = LAYOUT.play ? cue(s).lift : 1;
    const lift = ((s.lift ?? 60) + Math.sin((s.parentRef.spec.still && !s.afloat ? 0 : th) + (s.breathe ? s.breathe[1] : 0.4) * 6.283) * (s.breathe ? s.breathe[0] : 8)) * up;
    const r = s.rot || [0, 0, 0];
    // a shift is where the lifted element comes to rest: it travels there as it rises, and starts over its hole
    const sx = (s.shift ? s.shift[0] : 0) * Math.min(1, up), sy = (s.shift ? s.shift[1] : 0) * Math.min(1, up);
    M.copy(s.parentRef.mesh.matrixWorld).multiply(R.makeTranslation(s.local[0] + sx, s.local[1] + sy, lift));
    M.multiply(R.makeRotationFromEuler(new THREE.Euler(THREE.MathUtils.degToRad(r[0]), THREE.MathUtils.degToRad(r[1]), THREE.MathUtils.degToRad(r[2] || 0))));
    if (s.align) {
      // slide the lifted element toward the line of sight through the place it came from (and its shift from
      // there), so it floats over its own hole instead of drifting off it in perspective (align 1 = exactly over it)
      const hole = new THREE.Vector3(s.local[0] + sx, s.local[1] + sy, 0).applyMatrix4(s.parentRef.mesh.matrixWorld);
      const at = new THREE.Vector3().setFromMatrixPosition(M), cam = viewOf(w).position;
      const onRay = hole.clone().sub(cam).multiplyScalar(at.distanceTo(cam) / hole.distanceTo(cam)).add(cam);
      M.premultiply(R.makeTranslation(...onRay.sub(at).multiplyScalar(s.align).toArray()));
    }
    w.mesh.matrix.copy(M); w.mesh.matrixWorld.copy(M);
  }
  // The contours are drawn round the panes as they stand on the first frame and then stay put: a chart does not
  // redraw itself. A lifted element is charted too when the picture is a still (`ring` on a spec says otherwise).
  if (!ringed) {
    ringed = true;
    let n = 0;
    for (const w of windows) {
      const s = w.spec, r = s.ring ?? (s.parentRef ? (LAYOUT.play ? 0 : 1) : 1);
      if (!(r > 0) || n >= MAXW) continue;
      const pts = quad(w);
      ENV.uniforms.uRa.value[n].set(pts[0], pts[1], pts[2], pts[3]); ENV.uniforms.uRb.value[n].set(pts[4], pts[5], pts[6], pts[7]); ENV.uniforms.uRn.value[n] = r; n++;
    }
  }
  pass(ENV, rtScene);
  for (const w of windows) {
    const s = w.spec;
    if (Q.has('nowin')) continue;
    const bl = blurChain(rtScene, down, up, s.frostLevels ?? TH.glass.levels, 1.0);
    w.mat.uniforms.tFrost.value = bl.frost.texture; w.mat.uniforms.tSharp.value = bl.sharp.texture;
    w.mat.uniforms.uPhase.value = phase;
    renderer.setRenderTarget(rtScene); renderer.render(w.scene, viewOf(w));
  }
  // bloom
  const bl = blurChain(rtScene, bDown, bUp, 6, 1.0, TH.bloomThresh ?? 0.8);
  COMP.uniforms.tBloom.value = bl.frost.texture;
  renderer.setRenderTarget(null); renderer.setViewport(0, 0, CW, CH);
  fsMesh.material = COMP; renderer.clear(); renderer.render(fsScene, fsCam);
  renderer.getContext().finish();
}

window.renderAt = renderAt;
window.__ready = init().then(() => true).catch(e => { console.error(e); document.title = 'ERR ' + e; throw e; });
