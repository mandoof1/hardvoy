//! The bundled lab page: everything a real login page would touch, served
//! locally so a scan never depends on a third-party endpoint.
//!
//! `page_html` renders the document; `probe_js` is the collector. The collector
//! deliberately does *not* hash anything except the byte streams it cannot move
//! (canvas PNG, WebGL pixels, audio samples): the raw values are POSTed back and
//! hardvoy hashes them in Rust, so the hashing is inspectable and unit tested.

/// The lab page. `mode` selects what the page plants:
///
/// * `leaky`  — gathers ICE host candidates with no STUN servers, the way an
///   ordinary video-call widget does. With Firefox's mDNS masking off this is
///   the classic local-IP leak.
/// * `plain`  — a normal page load, no WebRTC at all.
/// * `full`   — every probe, WebRTC included (the default).
pub fn page_html(run: &str, mode: &str) -> String {
    let mode = match mode {
        "leaky" | "plain" | "full" => mode,
        _ => "full",
    };
    let run = escape_attr(run);
    format!(
        r####"<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>hardvoy lab probe</title>
<style>
 body {{ font: 15px/1.5 system-ui, sans-serif; margin: 2rem; background: #fbfbfd; color: #1c1b22; }}
 h1 {{ font-size: 1.25rem; margin-bottom: .25rem; }}
 .muted {{ color: #5b5b66; }}
 table {{ border-collapse: collapse; margin: 1rem 0; }}
 td, th {{ border: 1px solid #c9c9d2; padding: .3rem .5rem; text-align: left; font-size: .85rem; }}
 #status {{ margin-top: 1rem; padding: .5rem .75rem; border-left: 4px solid #0a84ff; background: #eef6ff; }}
 .box {{ display: inline-block; width: 120px; height: 40px; background: linear-gradient(45deg,#f6c,#6cf); }}
</style>
</head>
<body>
<h1>hardvoy lab probe</h1>
<p class="muted">Local-only fingerprinting target. Nothing here phones a third party.
Run <code>{run}</code>, mode <code>{mode}</code>.</p>

<p>The lab page is deliberately shaped like a real application page: text, images,
inline SVG, emoji, a canvas, a form, and a media widget. Each of those gives the
browser something measurable to render.</p>

<div class="box"></div>
<svg width="120" height="40" xmlns="http://www.w3.org/2000/svg">
  <circle cx="20" cy="20" r="12" fill="#0a84ff"/>
  <text x="40" y="26" font-size="14">abc&#129505;&#7835;</text>
</svg>

<table>
  <tr><th>probe</th><th>what it measures</th></tr>
  <tr><td>canvas 2d</td><td>rasteriser, antialiasing, text shaping</td></tr>
  <tr><td>WebGL</td><td>driver-reported vendor/renderer, extension list, shader rasterisation</td></tr>
  <tr><td>WebAudio</td><td>mixer + compressor float output</td></tr>
  <tr><td>fonts</td><td>resolved families and advance widths</td></tr>
  <tr><td>geometry</td><td>sub-pixel layout, SVG, emoji fallback</td></tr>
  <tr><td>webrtc</td><td>ICE host candidates (the local-IP leak)</td></tr>
  <tr><td>clock</td><td>timer resolution, <code>performance.timeOrigin</code></td></tr>
</table>

<form><label>user <input name="u" value="operator"></label> <button type="submit">sign in</button></form>

<div id="status">probes running&hellip;</div>
<script>
 window.HARDVOY_PAGE_ERRORS = [];
 window.addEventListener("error", (e) => window.HARDVOY_PAGE_ERRORS.push(
   String((e && (e.message || e.type)) || e) + " at " + (e && e.filename ? e.filename + ":" + e.lineno + ":" + e.colno : "unknown")
 ));
 window.addEventListener("unhandledrejection", (e) => window.HARDVOY_PAGE_ERRORS.push("rejection: " + String(e && e.reason)));
 window.HARDVOY_CFG = {{
   run: "{run}",
   mode: "{mode}",
   endpoint: "/collect",
   probeTimeoutMs: Number((new URLSearchParams(location.search).get("probe")) || 6000)
 }};
</script>
<script src="/lab.js"></script>
</body>
</html>
"####
    )
}

fn escape_attr(s: &str) -> String {
    s.chars()
        .map(|c| match c {
            '"' => "'".to_string(),
            '<' => " ".to_string(),
            '>' => " ".to_string(),
            '{' => " ".to_string(),
            '}' => " ".to_string(),
            '\n' => " ".to_string(),
            c => c.to_string(),
        })
        .collect()
}

/// The collector script.
pub fn probe_js() -> String {
    r####""use strict";
// hardvoy probe collector.
//
// Every group is wrapped so that one unsupported API cannot abort the run: a
// failed probe is reported as {error: ...} and hardvoy says so in the report.

const P = {};
// published for diagnostics: `hardvoy` (and a human with devtools) can read
// what the collector has done so far without waiting for the POST
window.HARDVOY_STATE = P;
window.HARDVOY_LOG = [];
const PROBE_TIMEOUT_MS = (window.HARDVOY_CFG && window.HARDVOY_CFG.probeTimeoutMs) || 6000;

// One group at a time, with a deadline. A probe that never returns (an audio
// context a headless browser will not finish, say) must not stall the whole
// page: it is recorded as {timeout: true} and the scan carries on.
const run = async (name, fn) => {
  window.HARDVOY_LOG.push("start " + name);
  const el = document.getElementById("status");
  if (el) el.textContent = "running " + name;
  const call = Promise.resolve().then(fn);
  const guard = new Promise((res) => setTimeout(() => res({ timeout: true, timeoutMs: PROBE_TIMEOUT_MS }), PROBE_TIMEOUT_MS));
  try {
    const r = await Promise.race([call, guard]);
    P[name] = r;
    if (r && r.timeout) {
      if (el) el.textContent = "timed out on " + name;
    }
  }
  catch (e) { P[name] = { error: String(e && (e.name ? e.name + ": " + e.message : e)) }; }
  window.HARDVOY_LOG.push("end " + name);
};

function fnv1a_bytes(u8) {
  let h = 0x811c9dc3 >>> 0;
  for (let i = 0; i < u8.length; i++) { h ^= u8[i]; h = Math.imul(h, 0x01000193) >>> 0; }
  return h >>> 0;
}
function summariseFloat(ch) {
  let sum = 0, min = Infinity, max = -Infinity;
  const bytes = new Uint8Array(ch.length * 4);
  const dv = new DataView(bytes.buffer);
  for (let i = 0; i < ch.length; i++) {
    const v = ch[i];
    sum += v;
    if (v < min) min = v;
    if (v > max) max = v;
    dv.setFloat32(i * 4, v, true);
  }
  return { length: ch.length, sum, min, max, fnv1a: fnv1a_bytes(bytes) };
}

// ---------------------------------------------------------------- canvas
function P_canvas() {
  const c = document.createElement("canvas");
  c.width = 220; c.height = 120;
  const ctx = c.getContext("2d");
  ctx.textBaseline = "alphabetic";
  ctx.fillStyle = "#c0ffee";
  ctx.fillRect(0, 0, 220, 120);
  const g = ctx.createLinearGradient(0, 0, 220, 120);
  g.addColorStop(0, "rgba(255,0,128,.6)");
  g.addColorStop(1, "rgba(0,128,255,.6)");
  ctx.fillStyle = g;
  ctx.beginPath();
  ctx.arc(60, 60, 38, 0, Math.PI * 2);
  ctx.fill();
  ctx.strokeStyle = "#123456";
  ctx.lineWidth = 2.5;
  ctx.beginPath();
  ctx.moveTo(8, 110);
  ctx.bezierCurveTo(70, 10, 150, 10, 212, 110);
  ctx.stroke();
  ctx.font = "17px 'DejaVu Sans', Arial, sans-serif";
  ctx.fillStyle = "#101010";
  ctx.textBaseline = "top";
  ctx.fillText("hardvoy \u00e9\u00e8\u00fc \u4e2d\u6587 \u062e\u0628\u0631\u0629 \ud83d\ude3a", 6, 8);
  ctx.fillText("ffi W1fi \uFF21\uFF22 \u2460 \u1E9B \u0130\u0131", 6, 30);
  ctx.setTransform(1.5, 0, 0, 1.5, 0, -20);
  ctx.fillText("scaled", 4, 82);
  ctx.setTransform(1, 0, 0, 1, 0, 0);
  const m = ctx.measureText("mmmmmmmmmmlli MW\uFF25\uFF26 \u2460 \u1E9B");
  const metrics = { width: m.width };
  for (const k of ["actualBoundingBoxLeft","actualBoundingBoxRight","actualBoundingBoxAscent","actualBoundingBoxDescent","fontBoundingBoxAscent","fontBoundingBoxDescent"]) {
    if (k in m) metrics[k] = m[k];
  }
  const textMetrics = ctx.measureText("hardvoy \u00e9\u4e2d\ud83d\ude3a");
  return {
    dataUrl: c.toDataURL(),
    textMetrics: { width: textMetrics.width },
    metrics,
    willReadFrequentlySupported: "willReadFrequently" in ctx,
  };
}

// ---------------------------------------------------------------- webgl
async function probeWebgl() {
  const c = document.createElement("canvas");
  c.width = 96; c.height = 96;
  const gl = c.getContext("webgl2") || c.getContext("webgl") || c.getContext("experimental-webgl");
  if (!gl) return { supported: false };
  const params = {};
  const names = ["MAX_TEXTURE_SIZE","MAX_CUBE_MAP_TEXTURE_SIZE","MAX_RENDERBUFFER_SIZE","MAX_VERTEX_ATTRIBS","MAX_VERTEX_TEXTURE_IMAGE_UNITS","MAX_TEXTURE_IMAGE_UNITS","MAX_COMBINED_TEXTURE_IMAGE_UNITS","MAX_VERTEX_UNIFORM_VECTORS","MAX_FRAGMENT_UNIFORM_VECTORS","VENDOR","VERSION","RENDERER","SHADING_LANGUAGE_VERSION","ALIASED_LINE_WIDTH_RANGE","ALIASED_POINT_SIZE_RANGE","RED_BITS","GREEN_BITS","BLUE_BITS","ALPHA_BITS","DEPTH_BITS","STENCIL_BITS","SUBPIXEL_BITS"];
  for (const n of names) {
    try {
      const v = gl.getParameter(gl[n]);
      params[n] = (v && v.length !== undefined && typeof v !== "string") ? Array.from(v) : v;
    } catch (e) { params[n] = null; }
  }
  const dbg = gl.getExtension("WEBGL_debug_renderer_info");
  if (dbg) {
    try { params.UNMASKED_VENDOR = gl.getParameter(dbg.UNMASKED_VENDOR_WEBGL); } catch (e) {}
    try { params.UNMASKED_RENDERER = gl.getParameter(dbg.UNMASKED_RENDERER_WEBGL); } catch (e) {}
  }
  const extensions = (gl.getSupportedExtensions() || []).slice().sort();
  // deterministic shader output, then read back
  let pixels = null, shaderError = null;
  try {
    const vsSrc = "attribute vec2 p; varying vec2 q; void main(){ q = p; gl_Position = vec4(p,0.0,1.0); }";
    const fsSrc = "precision mediump float; varying vec2 q; void main(){ gl_FragColor = vec4(fract(q.x*13.37),fract(q.y*7.11),fract((q.x+q.y)*5.3),1.0); }";
    const compile = (t, s) => { const sh = gl.createShader(t); gl.shaderSource(sh, s); gl.compileShader(sh); if (!gl.getShaderParameter(sh, gl.COMPILE_STATUS)) throw new Error(gl.getShaderInfoLog(sh)); return sh; };
    const prog = gl.createProgram();
    gl.attachShader(prog, compile(gl.VERTEX_SHADER, vsSrc));
    gl.attachShader(prog, compile(gl.FRAGMENT_SHADER, fsSrc));
    gl.bindAttribLocation(prog, 0, "p");
    gl.linkProgram(prog);
    if (!gl.getProgramParameter(prog, gl.LINK_STATUS)) throw new Error(gl.getProgramInfoLog(prog));
    gl.useProgram(prog);
    gl.clearColor(0.1234, 0.5, 0.9876, 1);
    gl.clear(gl.COLOR_BUFFER_BIT);
    const buf = gl.createBuffer();
    gl.bindBuffer(gl.ARRAY_BUFFER, buf);
    gl.bufferData(gl.ARRAY_BUFFER, new Float32Array([-1,-1, 1,-1, -1,1, -1,1, 1,-1, 1,1]), gl.STATIC_DRAW);
    gl.enableVertexAttribArray(0);
    gl.vertexAttribPointer(0, 2, gl.FLOAT, false, 0, 0);
    gl.drawArrays(gl.TRIANGLES, 0, 6);
    const px = new Uint8Array(96 * 96 * 4);
    gl.readPixels(0, 0, 96, 96, gl.RGBA, gl.UNSIGNED_BYTE, px);
    let sum = 0;
    for (let i = 0; i < px.length; i++) sum += px[i];
    pixels = { sum, fnv1a: fnv1a_bytes(px), len: px.length };
  } catch (e) { shaderError = String(e); }
  const caps = {};
  for (const e of ["OES_texture_float","WEBGL_depth_texture","ANGLE_instanced_arrays","WEBGL_multisampled_render_to_texture","WEBGL_render_shared_exponent","WEBGL_power_back_filter","EXT_color_buffer_float","KHR_parallel_shader_compile"]) {
    caps[e] = !!gl.getExtension(e);
  }
  let unmaskedBlocked = null;
  try { unmaskedBlocked = params.UNMASKED_RENDERER === params.RENDERER; } catch (e) {}
  return { supported: true, version: gl.getParameter(gl.VERSION), params, extensions, pixels, shaderError, extensionProbe: caps, unmaskedEqualsMasked: unmaskedBlocked };
}

// ---------------------------------------------------------------- audio
async function probeAudio() {
  const OC = window.OfflineAudioContext || window.webkitOfflineAudioContext;
  if (!OC) return { supported: false };
  const ctx = new OC(2, 8192, 44100);
  const osc = ctx.createOscillator();
  osc.type = "square";
  osc.frequency.setValueAtTime(10000, ctx.currentTime);
  const comp = ctx.createDynamicsCompressor();
  const set = (p, v) => { try { p.setValueAtTime(v, ctx.currentTime); } catch (e) {} };
  set(comp.threshold, -50); set(comp.knee, 40); set(comp.ratio, 12); set(comp.attack, 0); set(comp.release, 0.25);
  const filt = ctx.createBiquadFilter();
  filt.type = "lowpass"; filt.frequency.setValueAtTime(13000, ctx.currentTime); filt.Q.setValueAtTime(0.7, ctx.currentTime);
  const g = ctx.createGain(); g.gain.value = 0.5;
  osc.connect(comp); comp.connect(filt); filt.connect(g); g.connect(ctx.destination);
  osc.start(0);
  const rendered = await ctx.startRendering();
  const a = summariseFloat(rendered.getChannelData(0));
  const b = summariseFloat(rendered.getChannelData(1));
  const acParams = { sampleRate: rendered.sampleRate, length: rendered.length, channels: rendered.numberOfChannels, duration: rendered.duration };
  return { supported: true, left: a, right: b, ...acParams, analyser: (() => { try { const ac2 = new (window.OfflineAudioContext || window.webkitOfflineAudioContext)(1, 4410, 44100); const an = ac2.createAnalyser(); an.fftSize = 32; return { minDecibels: an.minDecibels, maxDecibels: an.maxDecibels, defaultFft: an.fftSize }; } catch (e) { return null; } })() };
}

// ---------------------------------------------------------------- fonts
function probeFonts() {
  const families = ["monospace","serif","sans-serif","cursive","fantasy","system-ui","ui-monospace","ui-sans-serif","DejaVu Sans","DejaVu Serif","DejaVu Sans Mono","Liberation Sans","Liberation Serif","Noto Sans","Noto Serif","Noto Sans Arabic","Noto Sans CJK SC","Noto Color Emoji","FreeSans","HardvoyMissingFamily-9f3a"];
  const c = document.createElement("canvas");
  const ctx = c.getContext("2d");
  const text = "mmmmmmmmmmlli MW\uFF25\uFF26 \u2460 \u1E9B \u0130\u0131 \u4e2d\u6587 \u062e\u0628\u0631\u0629";
  const canvasWidths = families.map((f) => {
    ctx.font = "72px \"" + f + "\", monospace";
    const m = ctx.measureText(text);
    return { family: f, width: m.width };
  });
  const span = document.createElement("span");
  span.style.cssText = "font-size:74px;white-space:pre;position:absolute;left:-9999px;top:0;visibility:hidden";
  span.textContent = text;
  const domWidths = families.map((f) => {
    span.style.fontFamily = "\"" + f + "\", monospace";
    document.body.appendChild(span);
    const w = span.offsetWidth, h = span.offsetHeight;
    const r = span.getBoundingClientRect();
    span.remove();
    return { family: f, offsetWidth: w, offsetHeight: h, rectWidth: r.width };
  });
  const distinct = new Set(canvasWidths.map((x) => Math.round(x.width * 1000))).size;
  let fontsApi = null;
  try {
    fontsApi = { status: document.fonts.status, size: document.fonts.size, check: document.fonts.check("12px 'HardvoyMissingFamily-9f3a'") };
  } catch (e) { fontsApi = { error: String(e) }; }
  return { canvasWidths, domWidths, distinctWidths: distinct, fontsApi };
}

// ---------------------------------------------------------------- geometry
function probeGeometry() {
  const probes = [];
  const add = (label, html, css) => {
    const d = document.createElement("div");
    d.style.cssText = (css || "") + ";position:absolute;left:0;top:0;visibility:hidden;";
    d.innerHTML = html;
    document.body.appendChild(d);
    const r = d.getBoundingClientRect();
    const kids = Array.from(d.children).map((x) => {
      const q = x.getBoundingClientRect();
      return { x: q.x, y: q.y, w: q.width, h: q.height };
    });
    d.remove();
    probes.push({ label, x: r.x, y: r.y, w: r.width, h: r.height, kids });
  };
  add("text", "<span>a\u062e\u0628\u0631\u0629 b</span><span>\u4e2d\u6587\u5b57</span><span>\u0130\u0131i</span>", "font:13px sans-serif");
  add("emoji", "<span>\u231A\u231B</span><span>\u{1F602}</span><span>\u{1F9D1}\u200D\u{1F3A8}</span><span>\u{1F1EF}\u{1F1F5}</span>", "font:26px sans-serif");
  add("svg", '<svg width="33" height="17"><rect x="0" y="0" width="33" height="17" fill="#333"/><text x="1" y="13" font-size="11">S\u00e9gol</text></svg>', "");
  add("scaled", "<span>sub-pixel</span>", "font:13px serif;transform:scale(0.1337);transform-origin:0 0");
  add("nested", "<div style='font:11px monospace'><span>x</span><span>y</span></div>", "line-height:1.618");
  const mm = [];
  for (const q of ["(prefers-color-scheme: dark)","(prefers-color-scheme: light)","(prefers-reduced-motion: reduce)","(prefers-contrast: more)","(prefers-contrast: no-preference)","(prefers-reduced-transparency: reduce)","(dynamic-range: high)","(color-gamut: p3)","(color-gamut: srgb)","(any-pointer: coarse)","(pointer: fine)","(any-hover: hover)","(forced-colors: active)","(update: slow)","(monochrome)","(scan: interlaced)","(display-mode: standalone)","(invert: inverted)"]) {
    try { mm.push({ q, matches: window.matchMedia(q).matches }); } catch (e) { mm.push({ q, error: String(e) }); }
  }
  const c = document.createElement("canvas");
  const ctx = c.getContext("2d");
  let back = null;
  try {
    c.width = 8; c.height = 8;
    ctx.fillStyle = "#808080";
    ctx.fillRect(0, 0, 8, 8);
    ctx.fillStyle = "#010101";
    ctx.fillRect(2, 2, 1, 1);
    ctx.fillRect(2, 2, 1, 1);
    ctx.fillRect(4.5, 4.5, 1, 1);
    const d = ctx.getImageData(0, 0, 8, 8).data;
    back = { sum: Array.from(d).reduce((a, b) => a + b, 0), fnv1a: fnv1a_bytes(d) };
  } catch (e) { back = { error: String(e) }; }
  return { probes, media: mm, raster: back, dpr: window.devicePixelRatio || 1 };
}

// ---------------------------------------------------------------- env
function probeEnv() {
  const n = navigator;
  const s = window.screen || {};
  let plugins = [];
  try { plugins = Array.from(n.plugins || []).map((p) => ({ name: p.name, version: p.version, file: p.filename })); } catch (e) {}
  let mime = [];
  try { mime = Array.from(n.mimeTypes || []).map((m) => m.type); } catch (e) {}
  const features = {};
  for (const k of ["RTCPeerConnection","webkitRTCPeerConnection","AudioContext","OfflineAudioContext","WebGLRenderingContext","WebGL2RenderingContext","ServiceWorker","indexedDB","caches","showDirectoryPicker","speechSynthesis","Notification","Bluetooth","serial","gpu","serialPort","Intl","WebAssembly","WebSocket","wasmMemory"]) {
    features[k] = window[k] !== undefined;
  }
  let storage = {};
  try {
    storage.ls = typeof localStorage + "";
    storage.ss = typeof sessionStorage + "";
    storage.persistent = navigator.storage && navigator.storage.persisted ? "available" : "none";
  } catch (e) { storage = { error: String(e) }; }
  return {
    userAgent: n.userAgent,
    appVersion: n.appVersion,
    platform: n.platform,
    oscpu: n.oscpu,
    vendor: n.vendor,
    appCodeName: n.appCodeName,
    appName: n.appName,
    language: n.language,
    languages: Array.from(n.languages || []),
    hardwareConcurrency: n.hardwareConcurrency,
    maxTouchPoints: n.maxTouchPoints,
    doNotTrack: n.doNotTrack,
    globalPrivacyControl: n.globalPrivacyControl,
    webdriver: n.webdriver,
    productSub: n.productSub,
    buildID: n.buildID,
    screen: {
      width: s.width, height: s.height, availWidth: s.availWidth, availHeight: s.availHeight,
      availLeft: s.availLeft, availTop: s.availTop, colorDepth: s.colorDepth, pixelDepth: s.pixelDepth,
      orientationType: s.orientation && s.orientation.type, orientationAngle: s.orientation && s.orientation.angle,
    },
    window: {
      innerWidth: window.innerWidth, innerHeight: window.innerHeight,
      outerWidth: window.outerWidth, outerHeight: window.outerHeight,
      devicePixelRatio: window.devicePixelRatio, isSecureContext: window.isSecureContext,
      scrollX: window.scrollX, scrollY: window.scrollY,
    },
    features,
    plugins,
    mimeTypes: mime,
    storage,
    documentTitles: { title: document.title, compatMode: document.compatMode, characterSet: document.characterSet, referrer: document.referrer },
  };
}

// ---------------------------------------------------------------- locale
function probeLocale() {
  let resolved = null;
  try { resolved = new Intl.DateTimeFormat().resolvedOptions(); } catch (e) {}
  const zones = ["UTC","Etc/GMT+5","America/New_York","Europe/Berlin","Asia/Dubai","Asia/Tokyo","Pacific/Kiritimati","Antarctica/Troll"];
  const formats = zones.map((z) => {
    try {
      return { z, s: new Intl.DateTimeFormat("en-US", { timeZone: z, dateStyle: "full", timeStyle: "long", hourCycle: "h23" }).format(new Date(1700000000000)) };
    } catch (e) { return { z, error: String(e && e.name) }; }
  });
  let seg = null;
  try { seg = Array.from(new Intl.Segmenter(undefined, { granularity: "word" }).segment("\u4e2d\u6587 hardvoy")).map((x) => x.segment); } catch (e) {}
  return {
    resolved,
    tzOffsetMinutes: new Date().getTimezoneOffset(),
    dateToString: new Date(1700000000000).toString(),
    toLocaleString: (() => { try { return new Date(1700000000000).toLocaleString(); } catch (e) { return String(e); } })(),
    formats,
    number: (() => { try { return new Intl.NumberFormat(undefined, { style: "currency", currency: "USD" }).format(1234.5); } catch (e) { return String(e); } })(),
    numberDe: (() => { try { return new Intl.NumberFormat("de-DE").format(1234.567); } catch (e) { return String(e); } })(),
    collation: (() => { try { return new Intl.Collator().resolvedOptions(); } catch (e) { return null; } })(),
    plural: (() => { try { return new Intl.PluralRules().resolvedOptions().pluralCategories; } catch (e) { return null; } })(),
    list: (() => { try { return new Intl.ListFormat().format(["a", "b", "c"]); } catch (e) { return null; } })(),
    relative: (() => { try { return new Intl.RelativeTimeFormat().format(-1, "day"); } catch (e) { return String(e); } })(),
    segmenter: seg,
    timeZoneCount: Intl.supportedValuesOf ? Intl.supportedValuesOf("timeZone").length : null,
    localeCompare: "a\u00e9".localeCompare("aE"),
  };
}

// ---------------------------------------------------------------- clock
async function probeClock() {
  const samples = [];
  for (let i = 0; i < 300; i++) samples.push(performance.now());
  const deltas = [];
  for (let i = 1; i < samples.length; i++) deltas.push(samples[i] - samples[i - 1]);
  deltas.sort((a, b) => a - b);
  const dateSamples = [];
  for (let i = 0; i < 60; i++) dateSamples.push(Date.now());
  let audio = null;
  try {
    const AC = window.AudioContext || window.webkitAudioContext;
    const ac = new AC();
    audio = { currentTime: ac.currentTime, sampleRate: ac.sampleRate, baseLatency: ac.baseLatency, outputLatency: ac.outputLatency };
    try { ac.close(); } catch (e) {}
  } catch (e) { audio = { error: String(e) }; }
  let raf = null;
  try {
    raf = await new Promise((res) => {
      const t = [];
      let n = 0;
      const cb = (ts) => { t.push(ts); if (++n < 10) requestAnimationFrame(cb); else res(t); };
      requestAnimationFrame(cb);
      setTimeout(() => res(t), 700);
    });
  } catch (e) { raf = { error: String(e) }; }
  return {
    timeOrigin: performance.timeOrigin,
    epochVsTimeOrigin: Date.now() - Math.round(performance.timeOrigin),
    perfUniq: new Set(samples.map((x) => x.toFixed(9))).size,
    perfSamples: samples.length,
    perfDeltaMin: deltas[0],
    perfDeltaMed: deltas[Math.floor(deltas.length / 2)],
    perfDeltaMax: deltas[deltas.length - 1],
    dateUniq: new Set(dateSamples).size,
    audio,
    rafTimestamps: raf,
  };
}

// ---------------------------------------------------------------- storage
async function probeStorage() {
  const out = { cookie: document.cookie, cookieCount: 0, localKeys: [], sessionKeys: [], marker: null, idb: null };
  out.cookieCount = document.cookie ? document.cookie.split(";").filter((c) => c.trim()).length : 0;
  let marker = null;
  try {
    marker = localStorage.getItem("hv_marker");
    if (!marker) {
      marker = "hv-" + Math.random().toString(36).slice(2, 10) + "-" + Date.now().toString(36);
      localStorage.setItem("hv_marker", marker);
      out.markerFresh = true;
    } else {
      out.markerFresh = false;
    }
  } catch (e) { out.markerError = String(e); }
  out.marker = marker;
  try { out.localKeys = Object.keys(localStorage).sort(); } catch (e) {}
  try { out.sessionKeys = Object.keys(sessionStorage).sort(); } catch (e) {}
  try { if (indexedDB.databases) out.idb = (await indexedDB.databases()).map((d) => d.name); } catch (e) { out.idb = null; }
  return out;
}

// ---------------------------------------------------------------- webrtc
function probeWebRTC(timeoutMs) {
  return new Promise((resolve) => {
    const RTC = window.RTCPeerConnection || window.webkitRTCPeerConnection;
    if (!RTC) return resolve({ supported: false, candidates: [] });
    const fromEvent = [];
    let settled = false;
    const finish = () => {
      if (settled) return;
      settled = true;
      const sdp = pc.localDescription && pc.localDescription.sdp ? pc.localDescription.sdp : "";
      const fromSdp = (sdp.match(/a=candidate:[^\r\n]+/g) || []).map((s) => s.slice(2));
      const all = Array.from(new Set(fromSdp.concat(fromEvent.map((c) => c.replace(/^candidate:/, "candidate:").replace(/^candidate:candidate:/, "candidate:")))));
      let iceServers = [];
      try { const cfg = pc.getConfiguration ? pc.getConfiguration() : null; if (cfg && cfg.iceServers) iceServers = cfg.iceServers.map((s) => s.urls); } catch (e) {}
      resolve({
        supported: true,
        gatheringState: pc.iceGatheringState,
        connectionState: pc.connectionState,
        candidates: all,
        sdpLength: sdp.length,
        sdpHasIpv6: /IPv6|:[0-9a-fA-F]{0,4}:[0-9a-fA-F:]+/.test(sdp),
        configuredIceServers: iceServers,
        localDescriptionType: pc.localDescription ? pc.localDescription.type : null,
      });
      try { pc.close(); } catch (e) {}
    };
    let pc;
    try {
      pc = new RTC({ iceServers: [], bundlePolicy: "max-bundle" });
    } catch (e) {
      return resolve({ supported: false, error: String(e), candidates: [] });
    }
    try { pc.addTransceiver("video", { direction: "sendrecv" }); }
    catch (e) { try { pc.addTransceiver("audio"); } catch (e2) {} }
    pc.addEventListener("icecandidate", (ev) => { if (ev.candidate) fromEvent.push(ev.candidate.candidate); });
    pc.addEventListener("icegatheringstatechange", () => { if (pc.iceGatheringState === "complete") finish(); });
    setTimeout(finish, timeoutMs);
    pc.createOffer().then((o) => pc.setLocalDescription(o)).catch((e) => {
      if (!settled) { settled = true; resolve({ supported: true, error: String(e), candidates: fromEvent }); }
    });
  });
}

// ---------------------------------------------------------------- media
async function probeMedia() {
  const out = { enumerateError: null, devices: [], getUserMedia: null, codecs: [] };
  try {
    if (navigator.mediaDevices && navigator.mediaDevices.enumerateDevices) {
      out.devices = (await navigator.mediaDevices.enumerateDevices()).map((d) => ({ kind: d.kind, label: d.label, idLen: d.deviceId ? d.deviceId.length : 0 }));
    } else { out.enumerateError = "mediaDevices.enumerateDevices unavailable"; }
  } catch (e) { out.enumerateError = String(e); }
  try {
    const c = document.createElement("video");
    for (const t of ["video/webm;codecs=vp9", "video/webm;codecs=vp8", 'video/mp4;codecs="avc1.42E01E"', "video/ogg;codecs=theora", 'audio/mp4;codecs="mp4a.40.2"', "audio/webm;codecs=opus"]) {
      out.codecs.push({ t, supported: c.canPlayType(t) || "no" });
    }
  } catch (e) {}
  try {
    if (navigator.mediaDevices && navigator.mediaDevices.getUserMedia) {
      // Not requested here: getUserMedia prompts the user and, in Firefox,
      // lights the camera doorhanger. Recorded as a tradecraft note instead.
      out.getUserMedia = "available but not invoked (permission prompt + camera indicator)";
    }
  } catch (e) {}
  return out;
}

// ---------------------------------------------------------------- run
(async function main() {
  const cfg = window.HARDVOY_CFG || { run: "none", mode: "full", endpoint: "/collect" };
  const t0 = Date.now();
  await run("env", probeEnv);
  await run("locale", probeLocale);
  await run("clock", probeClock);
  await run("canvas", P_canvas);
  await run("webgl", probeWebgl);
  await run("audio", probeAudio);
  await run("fonts", probeFonts);
  await run("geometry", probeGeometry);
  await run("storage", probeStorage);
  await run("media", probeMedia);
  if (cfg.mode === "plain") {
    P.webrtc = { skipped: "mode=plain", candidates: [] };
  } else {
    await run("webrtc", () => probeWebRTC(cfg.mode === "leaky" ? 4000 : 3000));
  }
  P.hardvoyMeta = {
    pageRunId: cfg.run,
    pageMode: cfg.mode,
    ua: navigator.userAgent,
    collectedAt: new Date().toISOString(),
    collectMs: Date.now() - t0,
    probeTimeoutMs: PROBE_TIMEOUT_MS,
    groups: Object.keys(P).sort(),
    timedOut: Object.keys(P).filter((k) => P[k] && P[k].timeout),
    planted: ["webrtc-ice-host-candidates", "canvas-2d-raster", "font-advance-widths", "sub-pixel-layout", "sub-millisecond-timers"],
  };
  let ok = false, status = 0, err = null;
  for (let attempt = 0; attempt < 3 && !ok; attempt++) {
    try {
      const r = await fetch(cfg.endpoint + "?run=" + encodeURIComponent(cfg.run) + "&attempt=" + attempt, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(P),
      });
      status = r.status;
      ok = r.ok;
    } catch (e) { err = String(e); }
  }
  const el = document.getElementById("status");
  if (el) {
    el.textContent = (ok ? "posted" : "post failed") + " run=" + cfg.run + " status=" + status + (err ? " error=" + err : "") + " ms=" + (Date.now() - t0);
  }
})();
"####.to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Walk the collector's JavaScript the way a parser would: skip strings and
    /// comments, track brace depth, and report every line where a token appears
    /// at top level inside no function. A `return` at depth 0 is what turned
    /// the canvas probe into a labelled block and silently killed the collector.
    fn js_top_level_returns(src: &str) -> Vec<usize> {
        let cs: Vec<char> = src.chars().collect();
        let mut depth: i32 = 0;
        let mut line = 1usize;
        let mut out = Vec::new();
        let mut i = 0usize;
        let mut string_delim: Option<char> = None;
        while i < cs.len() {
            let c = cs[i];
            if c == '\n' {
                line += 1;
                i += 1;
                continue;
            }
            if let Some(d) = string_delim {
                if c == '\\' {
                    i += 2;
                    if cs.get(i - 1) == Some(&'\n') {
                        line += 1;
                    }
                    continue;
                }
                if c == d {
                    string_delim = None;
                }
                i += 1;
                continue;
            }
            if c == '/' && cs.get(i + 1) == Some(&'/') {
                while i < cs.len() && cs[i] != '\n' {
                    i += 1;
                }
                continue;
            }
            if c == '/' && cs.get(i + 1) == Some(&'*') {
                i += 2;
                while i + 1 < cs.len() && !(cs[i] == '*' && cs[i + 1] == '/') {
                    if cs[i] == '\n' {
                        line += 1;
                    }
                    i += 1;
                }
                i += 2;
                continue;
            }
            if c == '\'' || c == '"' || c == '`' {
                string_delim = Some(c);
                i += 1;
                continue;
            }
            if c == '{' {
                depth += 1;
                i += 1;
                continue;
            }
            if c == '}' {
                depth -= 1;
                i += 1;
                continue;
            }
            if depth == 0
                && src[i..].starts_with("return")
                && (i == 0 || !cs[i - 1].is_alphanumeric())
                && cs.get(i + 6).is_none_or(|n| !n.is_alphanumeric())
            {
                out.push(line);
            }
            i += 1;
        }
        out
    }

    #[test]
    fn collector_javascript_has_no_top_level_return() {
        let js = probe_js();
        let bad = js_top_level_returns(&js);
        assert!(bad.is_empty(), "return outside a function at lines {bad:?}");
    }

    /// The real check: parse the collector the way a browser would, as a
    /// classic script (where a top-level `return` is a syntax error). A brace
    /// balance test is not enough — the canvas probe once became a labelled
    /// block, which balances perfectly and still kills the whole script.
    #[test]
    fn collector_javascript_parses_as_a_classic_script() {
        let js = probe_js();
        let dir = std::env::temp_dir().join(format!("hardvoy-js-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let file = dir.join("lab.js");
        std::fs::write(&file, &js).unwrap();
        let probe = std::process::Command::new("node").arg("--version").output();
        if probe.is_err() {
            panic!(
                "node is required to check the lab page's JavaScript: {js} bytes written to {}",
                file.display()
            );
        }
        let out = std::process::Command::new("node")
            .arg("-e")
            .arg("const fs=require('fs'),vm=require('vm');new vm.Script(fs.readFileSync(process.argv[1],'utf8'));console.log('ok')")
            .arg(&file)
            .output()
            .unwrap();
        assert!(
            out.status.success(),
            "the collector does not parse as a script: {}",
            String::from_utf8_lossy(&out.stderr)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn every_probe_the_page_calls_is_defined() {
        let js = probe_js();
        // `await run("canvas", P_canvas)` must have a matching definition
        let mut called: Vec<(String, String)> = Vec::new();
        let mut rest = js.as_str();
        while let Some(i) = rest.find("run(\"") {
            let after = &rest[i + 5..];
            let name: String = after.chars().take_while(|c| *c != '"').collect();
            let tail = &after[name.len() + 2..];
            let fn_name: String = tail
                .trim_start_matches([' ', ',', '\n'])
                .chars()
                .take_while(|c| c.is_alphanumeric() || *c == '_' || *c == '$')
                .collect();
            if !name.is_empty() {
                called.push((name, fn_name));
            }
            rest = tail;
        }
        assert!(
            called.len() >= 10,
            "found only {} run() calls",
            called.len()
        );
        for (group, f) in &called {
            if f.is_empty() {
                continue; // an inline arrow function
            }
            let defined = js.contains(&format!("function {f}("))
                || js.contains(&format!("const {f} ="))
                || js.contains(&format!("const {f}="));
            assert!(defined, "group {group} calls {f}, which is never defined");
        }
    }

    #[test]
    fn the_scanner_itself_catches_the_bug_it_would_find() {
        // regression guard for the scanner: this is exactly the shape that
        // turned the canvas probe into a labelled block
        let js = "const a = () => { return 1; };\nreturn 2;";
        assert_eq!(js_top_level_returns(js), vec![2]);
        // a `return` inside a string or comment is not a top-level return
        let js2 = "// return 1\nconst s = \"return 2\";\n";
        assert!(js_top_level_returns(js2).is_empty());
    }

    #[test]
    fn page_carries_run_id_and_mode() {
        let h = page_html("run-42", "leaky");
        assert!(h.contains("run: \"run-42\""));
        assert!(h.contains("mode: \"leaky\""));
        assert!(h.contains("/lab.js"));
        assert!(h.contains("hardvoy lab probe"));
    }

    #[test]
    fn unknown_mode_falls_back_to_full() {
        assert!(page_html("x", "wat").contains("mode: \"full\""));
    }

    #[test]
    fn run_id_cannot_break_the_script() {
        let h = page_html("a\"<>{}}\n", "full");
        assert!(
            !h.contains("run: \"a\""),
            "unescaped quote reached the script"
        );
        assert!(h.contains("run: \"a"));
    }

    #[test]
    fn probe_js_declares_every_group_the_model_reads() {
        let js = probe_js();
        for group in [
            "\"env\"",
            "\"locale\"",
            "\"clock\"",
            "\"canvas\"",
            "\"webgl\"",
            "\"audio\"",
            "\"fonts\"",
            "\"geometry\"",
            "\"storage\"",
            "\"webrtc\"",
            "\"media\"",
        ] {
            assert!(
                js.contains(&format!("run({group},")),
                "collector never fills {group}"
            );
        }
        assert!(js.contains("hv_marker"));
        assert!(js.contains("iceServers: []"));
        assert!(js.contains("/collect") || js.contains("cfg.endpoint"));
    }

    #[test]
    fn probe_js_is_balanced_enough_to_parse() {
        // cheap sanity check: balanced braces/brackets, no stray Rust format
        // specifiers leaking through
        let js = probe_js();
        let (mut braces, mut brackets, mut parens) = (0i64, 0i64, 0i64);
        for c in js.chars() {
            match c {
                '{' => braces += 1,
                '}' => braces -= 1,
                '[' => brackets += 1,
                ']' => brackets -= 1,
                '(' => parens += 1,
                ')' => parens -= 1,
                _ => {}
            }
            assert!(
                braces >= 0 && brackets >= 0 && parens >= 0,
                "unbalanced near: {c}"
            );
        }
        assert_eq!(braces, 0);
        assert_eq!(brackets, 0);
        assert_eq!(parens, 0);
    }
}
