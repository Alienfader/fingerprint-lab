// In-page fingerprint probe. Mirrors SIGNAL_JS in browser_fp.py so the two agree.
// Expects window.PROBE_NONCE; POSTs the collected object to /collect/<nonce>.
(async () => {
  const out = {};
  const safe = (f, d = null) => { try { return f(); } catch (e) { return d; } };

  out.webdriver       = safe(() => navigator.webdriver);
  out.userAgent       = safe(() => navigator.userAgent);
  out.pluginsLen      = safe(() => navigator.plugins.length);
  out.pluginNames     = safe(() => Array.from(navigator.plugins).map(p => p.name));
  out.languages       = safe(() => JSON.stringify(navigator.languages));
  out.hasWindowChrome = safe(() => typeof window.chrome !== 'undefined');
  out.hardwareConc    = safe(() => navigator.hardwareConcurrency);
  out.platform        = safe(() => navigator.platform);

  const glParam = (which) => safe(() => {
    const c = document.createElement('canvas');
    const gl = c.getContext('webgl') || c.getContext('experimental-webgl');
    const dbg = gl.getExtension('WEBGL_debug_renderer_info');
    return gl.getParameter(dbg[which]);
  });
  out.webglVendor   = glParam('UNMASKED_VENDOR_WEBGL');
  out.webglRenderer = glParam('UNMASKED_RENDERER_WEBGL');

  // Headless inconsistency: Notification.permission 'denied' vs permissions.query 'prompt'.
  out.permMismatch = await (async () => {
    try {
      const q = await navigator.permissions.query({ name: 'notifications' });
      return (Notification.permission === 'denied' && q.state === 'prompt');
    } catch (e) { return null; }
  })();

  // Canvas fingerprint, hashed in-page (SHA-256 hex prefix) so the payload stays small.
  out.canvas = await (async () => {
    try {
      const c = document.createElement('canvas');
      const ctx = c.getContext('2d');
      ctx.textBaseline = 'top'; ctx.font = '14px Arial';
      ctx.fillStyle = '#f60'; ctx.fillRect(10, 1, 62, 20);
      ctx.fillStyle = '#069'; ctx.fillText('fp-lab \u{1F512}', 2, 15);
      const bytes = new TextEncoder().encode(c.toDataURL());
      const h = await crypto.subtle.digest('SHA-256', bytes);
      return Array.from(new Uint8Array(h)).map(b => b.toString(16).padStart(2, '0')).join('').slice(0, 16);
    } catch (e) { return null; }
  })();

  try {
    await fetch('/collect/' + window.PROBE_NONCE, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(out),
    });
  } catch (e) { /* server simply keeps js=None */ }
})();
