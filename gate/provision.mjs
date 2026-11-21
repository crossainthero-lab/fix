#!/usr/bin/env node
// Helper-side: encrypt a Tailscale auth key (read from STDIN, never from argv) with a fresh random code and store it in
// the rescue-gate KV namespace. Prints ONLY the code. Usage:
//   <command that prints the key> | CLOUDFLARE_ACCOUNT_ID=... node provision.mjs <kv-namespace-id> [ttl-seconds]
import { webcrypto as crypto, randomInt } from 'node:crypto';
import { execFileSync } from 'node:child_process';
import { writeFileSync, rmSync, mkdtempSync, readFileSync } from 'node:fs';
import { join } from 'node:path';
import { tmpdir } from 'node:os';

const [nsId, ttlArg] = process.argv.slice(2);
if (!nsId) { console.error('usage: provision.mjs <kv-namespace-id> [ttl-seconds]'); process.exit(2); }
const ttl = Math.max(60, parseInt(ttlArg || '86400', 10));
const key = readFileSync(0, 'utf8').trim();
if (!/^tskey-[A-Za-z0-9_-]{10,}$/.test(key)) { console.error('stdin does not look like a Tailscale key (value not shown)'); process.exit(3); }

const alphabet = 'abcdefghijklmnopqrstuvwxyz234567';
let code = ''; for (let i = 0; i < 16; i++) code += alphabet[randomInt(32)];
const te = new TextEncoder();
const hex = (b) => [...new Uint8Array(b)].map((x) => x.toString(16).padStart(2, '0')).join('');
const b64 = (b) => Buffer.from(b).toString('base64');
const salt = crypto.getRandomValues(new Uint8Array(16)), iv = crypto.getRandomValues(new Uint8Array(12));
const base = await crypto.subtle.importKey('raw', te.encode(code), 'PBKDF2', false, ['deriveKey']);
const k = await crypto.subtle.deriveKey({ name: 'PBKDF2', salt, iterations: 100000, hash: 'SHA-256' }, base, { name: 'AES-GCM', length: 256 }, false, ['encrypt']);
const ct = await crypto.subtle.encrypt({ name: 'AES-GCM', iv }, k, te.encode(key));
const h = hex(await crypto.subtle.digest('SHA-256', te.encode(code)));
const rec = JSON.stringify({ state: 'ready', salt: b64(salt), iv: b64(iv), ct: b64(ct), created: new Date().toISOString() });

const dir = mkdtempSync(join('/dev/shm', 'rg-'));
const f = join(dir, 'rec.json');
try {
  writeFileSync(f, rec, { mode: 0o600 });
  execFileSync('npx', ['--no-install', 'wrangler', 'kv', 'key', 'put', 'c:' + h, '--path', f, '--namespace-id', nsId, '--ttl', String(ttl), '--remote'], { stdio: ['ignore', 'ignore', 'inherit'] });
} finally { rmSync(dir, { recursive: true, force: true }); }
console.log(code);
