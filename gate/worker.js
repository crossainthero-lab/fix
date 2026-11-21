// rescue-gate: one-time provisioning for Rescue Support.
//  - The helper stores a Tailscale auth key ENCRYPTED with a random 16-char code (AES-GCM, key derived from the code).
//    Only the SHA-256 of the code is used as the KV key, so neither the code nor the auth key is readable from KV.
//  - The friend's PC sends the code to POST /redeem and receives the auth key. It stays redeemable only until the
//    PC confirms a successful enrolment (POST /report with ok=true), after which the encrypted key is deleted.
//  - POST /report lets the PC tell the helper its computer name, Windows user, Tailscale address and result.
//  - GET /report/<code> returns that report to whoever holds the code (the helper).
const CODE_RE = /^[a-z2-7]{16}$/;
const te = new TextEncoder(), td = new TextDecoder();
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const b64 = (b) => btoa(String.fromCharCode(...new Uint8Array(b)));
const unb64 = (s) => Uint8Array.from(atob(s), (c) => c.charCodeAt(0));
const sha = async (s) => hex(await crypto.subtle.digest('SHA-256', te.encode(s)));

async function deriveKey(code, salt) {
  const base = await crypto.subtle.importKey('raw', te.encode(code), 'PBKDF2', false, ['deriveKey']);
  return crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, base,
    { name: 'AES-GCM', length: 256 }, false, ['decrypt']);
}
const json = (o, s = 200) => new Response(JSON.stringify(o), { status: s, headers: { 'content-type': 'application/json', 'cache-control': 'no-store' } });

export default {
  async fetch(req, env) {
    const url = new URL(req.url);
    if (req.method === 'GET' && url.pathname === '/') return new Response('rescue-gate ok\n');

    if (req.method === 'POST' && (url.pathname === '/redeem' || url.pathname === '/report')) {
      const raw = await req.text();
      if (raw.length > 4096) return json({ error: 'too large' }, 413);
      let body; try { body = JSON.parse(raw); } catch { return json({ error: 'bad json' }, 400); }
      const code = body && body.code;
      if (typeof code !== 'string' || !CODE_RE.test(code)) return json({ error: 'bad code' }, 400);
      const h = await sha(code);
      const rec = await env.RESCUE.get('c:' + h, 'json');
      if (!rec) return json({ error: 'unknown or expired code' }, 404);

      if (url.pathname === '/redeem') {
        if (rec.state !== 'ready') return json({ error: 'code already used' }, 410);
        try {
          const k = await deriveKey(code, unb64(rec.salt));
          const plain = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: unb64(rec.iv) }, k, unb64(rec.ct));
          return json({ key: td.decode(plain) });
        } catch { return json({ error: 'could not decrypt' }, 500); }
      }
      // /report
      const r = body.report && typeof body.report === 'object' ? body.report : {};
      const clean = {};
      for (const f of ['ok', 'message', 'computer', 'user', 'ip', 'dnsName', 'hostKey', 'version', 'code']) {
        if (r[f] !== undefined) clean[f] = typeof r[f] === 'string' ? r[f].slice(0, 300) : r[f];
      }
      clean.at = new Date().toISOString();
      await env.RESCUE.put('r:' + h, JSON.stringify(clean), { expirationTtl: 7 * 86400 });
      if (clean.ok === true) {
        await env.RESCUE.put('c:' + h, JSON.stringify({ state: 'done', at: clean.at }), { expirationTtl: 7 * 86400 });
      }
      return json({ stored: true });
    }

    if (req.method === 'GET' && url.pathname.startsWith('/report/')) {
      const code = url.pathname.slice(8);
      if (!CODE_RE.test(code)) return json({ error: 'bad code' }, 400);
      const rep = await env.RESCUE.get('r:' + await sha(code), 'json');
      return rep ? json(rep) : json({ error: 'no report yet' }, 404);
    }
    return json({ error: 'not found' }, 404);
  },
};
