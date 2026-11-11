// Sets day or night before the first paint, so the page never flashes the wrong one. A file of
// its own because the page's content policy allows no inline script. Keep in step with src/theme.ts.
(function () {
  var mode = 'system'
  try {
    mode = localStorage.getItem('seaward:theme') || 'system'
  } catch (e) {
    /* storage is blocked: follow the system */
  }
  var dark = mode === 'dark' || (mode !== 'light' && window.matchMedia('(prefers-color-scheme: dark)').matches)
  document.documentElement.dataset.theme = dark ? 'dark' : 'light'
  var meta = document.querySelector('meta[name="theme-color"]')
  if (meta) meta.setAttribute('content', dark ? '#0a141f' : '#f8f6ef')
})()
