#!/usr/bin/env node
/**
 * ============================================================================
 *  KEY SYSTEM — Node.js (zero dependency, Railway-ready)  |  API + Admin Panel
 * ----------------------------------------------------------------------------
 *  Port dari Cloudflare Worker versi KV — protokol mod menu SAMA PERSIS:
 *    POST /            body: user_key=<KEY>&serial=<SERIAL>  (form-urlencoded)
 *    UA      : AbsoluteX/2.0 (opsional diverifikasi via REQUIRE_UA)
 *    Response: {"status":"OK","data":{"rng","expired","member_key"},"reason":""}
 *
 *  Panel admin : https://<domain>/admin   (login password)
 *  Storage     : file JSON (data/keys.json) — persist penuh bila dipasang Volume
 *  Variabel    : lihat README.md (ADMIN_PASSWORD wajib di-set)
 * ============================================================================
 */
'use strict';

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

/* ==========================================================================
 *  KONFIGURASI (variabel env dengan default)
 * ========================================================================== */
const cfg = {
  ADMIN_PASSWORD: process.env.ADMIN_PASSWORD || '',
  SESSION_SECRET: process.env.SESSION_SECRET || (process.env.ADMIN_PASSWORD || '') + '::ks-default-salt',
  KEY_PREFIX: (process.env.KEY_PREFIX || 'BMX').toUpperCase().replace(/[^A-Z0-9]/g, '') || 'BMX',
  STATUS_OK: process.env.STATUS_OK || 'OK',
  REQUIRE_UA: process.env.REQUIRE_UA || '',           // kosong = mati; contoh: "AbsoluteX/2.0"
  BIND_DEVICE: (process.env.BIND_DEVICE || '1') !== '0',
  MAX_DEVICES: parseInt(process.env.MAX_DEVICES || '1', 10) || 1,
  EXPIRED_FMT: process.env.EXPIRED_FMT || 'dd-mm-yyyy', // dd-mm-yyyy | iso | epoch
  LIFETIME_TEXT: process.env.LIFETIME_TEXT || 'Lifetime',
  REASON_OK: process.env.REASON_OK || '',
  REASON_NOTFOUND: process.env.REASON_NOTFOUND || 'Key tidak ditemukan',
  REASON_BANNED: process.env.REASON_BANNED || 'Key diblokir',
  REASON_EXPIRED: process.env.REASON_EXPIRED || 'Key expired',
  REASON_DEVICE: process.env.REASON_DEVICE || 'Device sudah terdaftar di key lain',
};

const PORT = parseInt(process.env.PORT || '3000', 10) || 3000;
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'keys.json');

/* ==========================================================================
 *  STORAGE — file JSON (atomic write). Railway: pasang Volume -> DATA_DIR=/data
 * ========================================================================== */
let db = {}; // { "key:BMX-XXXX-XXXX-XXXX": rec, ... }

function loadDb() {
  try {
    db = JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
    if (typeof db !== 'object' || !db) db = {};
  } catch (e) {
    db = {};
  }
}

function saveDb() {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    const tmp = DB_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(db));
    fs.renameSync(tmp, DB_FILE);
  } catch (e) {
    console.error('[keypanel] gagal simpan db:', e.message);
  }
}

loadDb();

/* ==========================================================================
 *  UTIL
 * ========================================================================== */
function json(res, obj, status = 200, cors = false) {
  const h = {
    'content-type': 'application/json; charset=utf-8',
    'cache-control': 'no-store',
  };
  if (cors) h['access-control-allow-origin'] = '*';
  res.writeHead(status, h);
  res.end(JSON.stringify(obj));
}

function html(res, body, status = 200) {
  res.writeHead(status, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' });
  res.end(body);
}

function readBody(req) {
  return new Promise((resolve) => {
    let d = '';
    req.on('data', (c) => {
      d += c;
      if (d.length > 1e6) req.destroy();
    });
    req.on('end', () => resolve(d));
    req.on('error', () => resolve(''));
  });
}

async function parseBody(req) {
  const raw = await readBody(req);
  const ct = (req.headers['content-type'] || '').toLowerCase();
  if (ct.includes('application/json')) {
    try { return JSON.parse(raw || '{}'); } catch (e) { return {}; }
  }
  // form-urlencoded & query-string style
  return Object.fromEntries(new URLSearchParams(raw));
}

function hmacHex(secret, msg) {
  return crypto.createHmac('sha256', String(secret)).update(msg).digest('hex');
}

function timingEq(a, b) {
  const ba = crypto.createHash('sha256').update(String(a || '')).digest();
  const bb = crypto.createHash('sha256').update(String(b || '')).digest();
  return crypto.timingSafeEqual(ba, bb);
}

function getCookie(req, name) {
  const cookie = req.headers.cookie || '';
  for (const part of cookie.split(';')) {
    const i = part.indexOf('=');
    if (i > 0 && part.slice(0, i).trim() === name) return part.slice(i + 1).trim();
  }
  return '';
}

function clientIp(req) {
  const xff = req.headers['x-forwarded-for'];
  if (xff) return String(xff).split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || 'unknown';
}

/* ==========================================================================
 *  API VERIFY — dipanggil payload / tool (protokol AbsoluteX)
 * ========================================================================== */
async function handleVerify(req, res, url) {
  const c = cfg;

  if (c.REQUIRE_UA) {
    const ua = req.headers['user-agent'] || '';
    if (!ua.includes(c.REQUIRE_UA)) {
      return payloadJson(res, c, false, c.REASON_NOTFOUND, null, 403);
    }
  }

  let user_key = url.searchParams.get('user_key') || url.searchParams.get('key') || '';
  let serial = url.searchParams.get('serial') || '';
  if (req.method === 'POST') {
    const body = await parseBody(req);
    user_key = user_key || body.user_key || body.key || '';
    serial = serial || body.serial || '';
  }

  user_key = String(user_key).trim().toUpperCase();
  serial = String(serial).trim();

  if (!user_key) {
    return payloadJson(res, c, false, 'user_key kosong', null, 400);
  }

  const rec = db['key:' + user_key] || null;
  const now = Date.now();

  if (!rec) return payloadJson(res, c, false, c.REASON_NOTFOUND, null, 200);
  if (rec.status === 'banned') return payloadJson(res, c, false, c.REASON_BANNED, rec, 200);
  if (rec.expires && now > rec.expires) return payloadJson(res, c, false, c.REASON_EXPIRED, rec, 200);

  let changed = false;
  if (c.BIND_DEVICE && serial) {
    rec.serials = rec.serials || [];
    if (!rec.serials.includes(serial)) {
      if (rec.serials.length >= (rec.max_devices || c.MAX_DEVICES)) {
        return payloadJson(res, c, false, c.REASON_DEVICE, rec, 200);
      }
      rec.serials.push(serial);
      changed = true;
    }
  }

  rec.uses = (rec.uses || 0) + 1;
  rec.last_used = now;
  // throttle penulisan last_used: maks 1x / 5 menit kecuali ada perubahan binding
  if (changed || !rec.last_write || now - rec.last_write > 5 * 60 * 1000) {
    rec.last_write = now;
    saveDb();
  }

  return payloadJson(res, c, true, c.REASON_OK, rec, 200);
}

/* Format respons yang dibaca mod menu (status/data{rng,expired,member_key}/reason) */
function payloadJson(res, c, ok, reason, rec, httpStatus) {
  const expiredStr = rec ? fmtExpired(c, rec.expires) : '';
  const rng = crypto.randomBytes(12).toString('base64url');
  const body = {
    status: ok ? c.STATUS_OK : '',
    reason: reason || '',
    expired: expiredStr,
    member_key: rec ? rec.key : '',
    data: {
      rng: rng,
      expired: expiredStr,
      member_key: rec ? rec.key : '',
      status: ok ? c.STATUS_OK : '',
    },
  };
  return json(res, body, httpStatus, true);
}

function fmtExpired(c, ms) {
  if (!ms) return c.LIFETIME_TEXT;
  if (c.EXPIRED_FMT === 'iso') return new Date(ms).toISOString();
  if (c.EXPIRED_FMT === 'epoch') return String(Math.floor(ms / 1000));
  const p = (n) => String(n).padStart(2, '0');
  // default: dd-mm-yyyy (zona WIB)
  const wib = new Date(ms + 7 * 3600 * 1000);
  return `${p(wib.getUTCDate())}-${p(wib.getUTCMonth() + 1)}-${wib.getUTCFullYear()}`;
}

/* ==========================================================================
 *  ADMIN — AUTH (cookie HMAC, 12 jam)
 * ========================================================================== */
function isAuthed(req) {
  const c = cfg;
  if (!c.ADMIN_PASSWORD) return false; // password wajib di-set
  const tok = getCookie(req, 'ks_sess');
  if (!tok) return false;
  const dot = tok.indexOf('.');
  if (dot < 1) return false;
  const expStr = tok.slice(0, dot);
  const sig = tok.slice(dot + 1);
  const exp = parseInt(expStr, 10);
  if (!exp || Date.now() > exp) return false;
  const expect = hmacHex(c.SESSION_SECRET, 'admin:' + expStr);
  if (!timingEq(sig, expect)) return false;
  return true;
}

// rate limit login sederhana (per proses)
const loginFails = new Map();

async function adminLogin(req, res) {
  const c = cfg;
  const ip = clientIp(req);
  const now = Date.now();
  const st = loginFails.get(ip) || { n: 0, until: 0 };
  if (st.until > now) {
    return json(res, { ok: false, error: `Terlalu banyak percobaan. Coba lagi ${Math.ceil((st.until - now) / 1000)}s` }, 429);
  }

  const body = await parseBody(req);
  const pass = String(body.password || '');
  if (!c.ADMIN_PASSWORD) {
    return json(res, { ok: false, error: 'ADMIN_PASSWORD belum di-set di Variables' }, 500);
  }
  if (!pass || !timingEq(pass, c.ADMIN_PASSWORD)) {
    st.n += 1;
    if (st.n >= 8) { st.n = 0; st.until = now + 10 * 60 * 1000; }
    loginFails.set(ip, st);
    return json(res, { ok: false, error: 'Password salah' }, 401);
  }
  loginFails.delete(ip);

  const exp = Date.now() + 12 * 3600 * 1000;
  const sig = hmacHex(c.SESSION_SECRET, 'admin:' + exp);
  res.writeHead(302, {
    'set-cookie': `ks_sess=${exp}.${sig}; Path=/; HttpOnly; SameSite=Lax; Max-Age=${12 * 3600}`,
    location: '/admin',
  });
  res.end();
}

/* ==========================================================================
 *  ADMIN — API (list / stats / create / ban / unban / delete / reset / extend / setexpiry)
 * ========================================================================== */
const DURATIONS = { '1': 1, '3': 3, '7': 7, '14': 14, '30': 30, '60': 60, '90': 90, 'lifetime': 0 };

function genKey(prefix) {
  const abc = '23456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // tanpa 0,O,1,I
  const seg = () => {
    const a = crypto.randomBytes(4);
    return [...a].map((b) => abc[b % abc.length]).join('');
  };
  return `${prefix}-${seg()}-${seg()}-${seg()}`;
}

function listAllKeys() {
  const keys = [];
  for (const k of Object.keys(db)) {
    if (k.startsWith('key:') && db[k]) keys.push(db[k]);
  }
  keys.sort((a, b) => (b.created || 0) - (a.created || 0));
  return keys;
}

async function adminApi(req, res, pathname) {
  const c = cfg;

  if (pathname === '/admin/api/list' && req.method === 'GET') {
    return json(res, { ok: true, keys: listAllKeys().slice(0, 1000) });
  }

  if (pathname === '/admin/api/stats' && req.method === 'GET') {
    const keys = listAllKeys();
    const now = Date.now();
    const stats = {
      total: keys.length,
      active: keys.filter((k) => k.status === 'active' && (!k.expires || k.expires > now)).length,
      expired: keys.filter((k) => k.expires && k.expires <= now && k.status !== 'banned').length,
      banned: keys.filter((k) => k.status === 'banned').length,
    };
    return json(res, { ok: true, stats });
  }

  if (req.method !== 'POST') return json(res, { ok: false, error: 'method' }, 405);
  const body = await parseBody(req);

  if (pathname === '/admin/api/create') {
    const durKey = String(body.duration ?? '30');
    let days;
    if (durKey in DURATIONS) days = DURATIONS[durKey];
    else days = parseInt(body.custom_days ?? durKey, 10);
    if (isNaN(days) || days < 0) days = 30;

    const qty = Math.min(Math.max(parseInt(body.qty || '1', 10) || 1, 1), 50);
    const note = String(body.note || '').slice(0, 100);
    const max_devices = Math.min(Math.max(parseInt(body.max_devices || c.MAX_DEVICES, 10) || 1, 1), 10);

    const made = [];
    for (let i = 0; i < qty; i++) {
      let key, tries = 0;
      do { key = genKey(c.KEY_PREFIX); tries++; } while (tries < 5 && db['key:' + key]);
      const rec = {
        key,
        note,
        max_devices,
        status: 'active',
        serials: [],
        created: Date.now(),
        expires: days > 0 ? Date.now() + days * 86400000 : null,
        uses: 0,
        last_used: 0,
      };
      db['key:' + key] = rec;
      made.push(rec);
    }
    saveDb();
    return json(res, { ok: true, keys: made });
  }

  const key = String(body.key || '').trim().toUpperCase();
  if (!key) return json(res, { ok: false, error: 'key required' }, 400);
  const rec = db['key:' + key];
  if (!rec) return json(res, { ok: false, error: 'key tidak ditemukan' }, 404);

  if (pathname === '/admin/api/ban') {
    rec.status = 'banned';
  } else if (pathname === '/admin/api/unban') {
    rec.status = 'active';
  } else if (pathname === '/admin/api/delete') {
    delete db['key:' + key];
    saveDb();
    return json(res, { ok: true, deleted: key });
  } else if (pathname === '/admin/api/reset') {
    rec.serials = [];
  } else if (pathname === '/admin/api/extend') {
    const days = parseInt(body.days || '0', 10) || 0;
    if (days === 0) return json(res, { ok: false, error: 'days required' }, 400);
    const base = rec.expires && rec.expires > Date.now() ? rec.expires : Date.now();
    rec.expires = base + days * 86400000;
    rec.status = 'active';
  } else if (pathname === '/admin/api/setexpiry') {
    const ms = parseInt(body.expires, 10);
    rec.expires = isNaN(ms) ? null : ms;
  } else {
    return json(res, { ok: false, error: 'unknown endpoint' }, 404);
  }

  saveDb();
  return json(res, { ok: true, key: rec });
}

/* ==========================================================================
 *  HALAMAN (landing, login, panel)
 * ========================================================================== */
function pageLanding(res) {
  const c = cfg;
  const page = `<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Key System API</title><style>
body{background:#0b0f17;color:#e5e9f0;font-family:ui-monospace,monospace;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#121826;border:1px solid #1f2937;border-radius:14px;padding:32px;max-width:640px;width:92%}
h1{margin:0 0 6px;font-size:20px;color:#7dd3fc}code{background:#0b0f17;padding:2px 6px;border-radius:6px;color:#a5b4fc}
pre{background:#0b0f17;padding:12px;border-radius:8px;overflow:auto;font-size:12px}
.tag{display:inline-block;background:#1e293b;color:#94a3b8;border-radius:6px;padding:2px 8px;font-size:11px;margin-right:6px}
a{color:#7dd3fc}
</style></head><body><div class="card">
<h1>&#9919; Key System API</h1>
<p><span class="tag">online</span> Server key aktif. Panel admin: <a href="/admin">/admin</a></p>
<h3>Endpoint</h3>
<pre>POST /
Content-Type: application/x-www-form-urlencoded
User-Agent: ${c.REQUIRE_UA || '(bebas)'}

user_key=XXXX-XXXX-XXXX-XXXX&serial=DEVICE_SERIAL</pre>
<h3>Response</h3>
<pre>{ "status": "${c.STATUS_OK}", "reason": "",
  "expired": "${c.LIFETIME_TEXT}",
  "member_key": "XXXX-XXXX-XXXX-XXXX",
  "data": { "rng": "...", "expired": "...", "member_key": "...", "status": "${c.STATUS_OK}" } }</pre>
<p style="color:#64748b;font-size:12px">Gagal: status kosong + reason berisi alasan (key tidak ditemukan / expired / diblokir / device).</p>
</div></body></html>`;
  return html(res, page);
}

function pageLogin(res) {
  const page = `<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Admin Login</title><style>
body{background:#0b0f17;color:#e5e9f0;font-family:system-ui,sans-serif;display:flex;align-items:center;justify-content:center;min-height:100vh;margin:0}
.card{background:#121826;border:1px solid #1f2937;border-radius:14px;padding:32px;width:340px}
h1{margin:0 0 18px;font-size:18px;text-align:center;color:#7dd3fc}
input{width:100%;box-sizing:border-box;background:#0b0f17;border:1px solid #334155;color:#e5e9f0;border-radius:8px;padding:11px 12px;font-size:14px;margin-bottom:12px}
button{width:100%;background:#0ea5e9;border:0;color:#04121f;font-weight:700;border-radius:8px;padding:11px;font-size:14px;cursor:pointer}
button:hover{background:#38bdf8}#err{color:#f87171;font-size:12px;min-height:16px;text-align:center}
</style></head><body><div class="card">
<h1>&#128274; Admin Panel</h1>
<form id="f"><input type="password" id="p" placeholder="Password admin" autofocus>
<button type="submit">Masuk</button><div id="err"></div></form>
<script>
f.onsubmit = async (e) => {
  e.preventDefault();
  const r = await fetch('/admin/login', {
    method: 'POST',
    headers: {'content-type': 'application/x-www-form-urlencoded'},
    body: 'password=' + encodeURIComponent(document.getElementById('p').value)
  });
  if (r.ok) location.reload();
  else { const j = await r.json().catch(()=>({})); document.getElementById('err').textContent = j.error || 'Gagal'; }
};
</script></div></body></html>`;
  return html(res, page);
}

/* Panel admin: satu halaman HTML + JS fetch ke /admin/api/* */
function pagePanel(res) {
  const page = `<!doctype html><html lang="id"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Key Panel</title><style>
:root{--bg:#0b0f17;--card:#121826;--line:#1f2937;--txt:#e5e9f0;--dim:#64748b;--acc:#0ea5e9;--ok:#34d399;--warn:#fbbf24;--bad:#f87171}
*{box-sizing:border-box}
body{background:var(--bg);color:var(--txt);font-family:system-ui,sans-serif;margin:0;padding:20px}
.wrap{max-width:1100px;margin:0 auto}
header{display:flex;justify-content:space-between;align-items:center;margin-bottom:16px}
h1{font-size:18px;margin:0;color:var(--acc)}
.stats{display:flex;gap:10px;flex-wrap:wrap;margin-bottom:16px}
.chip{background:var(--card);border:1px solid var(--line);border-radius:10px;padding:10px 16px;min-width:110px}
.chip b{display:block;font-size:20px}.chip span{font-size:11px;color:var(--dim)}
.card{background:var(--card);border:1px solid var(--line);border-radius:12px;padding:16px;margin-bottom:16px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:end}
label{display:block;font-size:11px;color:var(--dim);margin-bottom:4px}
select,input{background:var(--bg);border:1px solid #334155;color:var(--txt);border-radius:8px;padding:9px 10px;font-size:13px}
input[type=text],input[type=number]{width:160px}
button{background:var(--acc);border:0;color:#04121f;font-weight:700;border-radius:8px;padding:9px 14px;font-size:13px;cursor:pointer}
button:hover{filter:brightness(1.15)}
button.ghost{background:#1e293b;color:var(--txt);font-weight:500}
button.mini{padding:4px 8px;font-size:11px;border-radius:6px}
button.red{background:#7f1d1d;color:#fecaca}button.green{background:#064e3b;color:#a7f3d0}
table{width:100%;border-collapse:collapse;font-size:12px}
th{color:var(--dim);text-align:left;padding:8px 6px;border-bottom:1px solid var(--line);font-weight:600}
td{padding:8px 6px;border-bottom:1px solid #172033;vertical-align:top}
.key{font-family:ui-monospace,monospace;color:#a5b4fc;cursor:pointer}
.badge{display:inline-block;padding:2px 8px;border-radius:6px;font-size:10px;font-weight:700}
.b-act{background:#064e3b;color:var(--ok)}.b-exp{background:#78350f;color:var(--warn)}.b-ban{background:#7f1d1d;color:var(--bad)}
.sisa{color:var(--dim);font-size:11px}
.search{width:220px}
.empty{color:var(--dim);text-align:center;padding:24px}
#toast{position:fixed;bottom:18px;right:18px;background:#052e16;color:var(--ok);border:1px solid #14532d;padding:10px 16px;border-radius:10px;font-size:13px;display:none}
</style></head><body><div class="wrap">
<header><h1>&#9919; Key Panel</h1><div>
<button class="ghost" onclick="loadAll()">Refresh</button>
<button class="ghost" onclick="fetch('/admin/logout',{method:'POST'}).then(()=>location.reload())">Logout</button>
</div></header>

<div class="stats">
<div class="chip"><b id="s-total">-</b><span>Total</span></div>
<div class="chip"><b id="s-act">-</b><span>Aktif</span></div>
<div class="chip"><b id="s-exp">-</b><span>Expired</span></div>
<div class="chip"><b id="s-ban">-</b><span>Banned</span></div>
</div>

<div class="card">
<b style="font-size:13px">+ Buat Key Baru</b><br><br>
<div class="row">
<div><label>Durasi</label>
<select id="dur">
<option value="1">1 Hari</option><option value="3">3 Hari</option>
<option value="7" selected>7 Hari</option><option value="14">14 Hari</option>
<option value="30">30 Hari</option><option value="60">60 Hari</option>
<option value="90">90 Hari</option><option value="lifetime">Lifetime</option>
<option value="custom">Custom...</option>
</select></div>
<div id="cwrap" style="display:none"><label>Jumlah hari</label><input type="number" id="cdays" value="15" min="1"></div>
<div><label>Jumlah key</label><input type="number" id="qty" value="1" min="1" max="50"></div>
<div><label>Maks device</label><input type="number" id="mdev" value="1" min="1" max="10"></div>
<div style="flex:1;min-width:180px"><label>Catatan (opsional)</label><input type="text" id="note" style="width:100%" placeholder="untuk siapa / order #"></div>
<button onclick="createKey()">Generate</button>
</div></div>

<div class="card">
<div class="row" style="margin-bottom:10px">
<input type="text" class="search" id="q" placeholder="Cari key / catatan / serial..." oninput="render()">
<span style="color:var(--dim);font-size:11px">Klik key untuk copy &bull; Waktu: WIB (Asia/Jakarta)</span>
</div>
<div style="overflow:auto"><table>
<thead><tr><th>Key</th><th>Status</th><th>Dibuat</th><th>Expired</th><th>Device (serial)</th><th>Pakai</th><th>Catatan</th><th>Aksi</th></tr></thead>
<tbody id="tb"><tr><td colspan="8" class="empty">memuat...</td></tr></tbody>
</table></div></div>
</div>
<div id="toast"></div>
<script>
let KEYS = [];
const WIB = new Intl.DateTimeFormat('id-ID',{timeZone:'Asia/Jakarta',dateStyle:'medium',timeStyle:'short'});
const fmt = ms => ms ? WIB.format(new Date(ms)) : 'Lifetime';
const sisa = ms => {
  if (!ms) return 'tanpa batas';
  const d = ms - Date.now();
  if (d <= 0) return 'expired';
  const h = Math.floor(d/3600000), m = Math.floor(d%3600000/60000);
  return h >= 48 ? Math.floor(h/24) + ' hari lagi' : h + 'j ' + m + 'm lagi';
};
const esc = s => String(s??'').replace(/[&<>"]/g, c => ({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]));
function toast(m){ const t=document.getElementById('toast'); t.textContent=m; t.style.display='block'; setTimeout(()=>t.style.display='none',2200); }

async function loadAll(){
  const [lr, sr] = await Promise.all([fetch('/admin/api/list'), fetch('/admin/api/stats')]);
  const lj = await lr.json(), sj = await sr.json();
  KEYS = lj.keys || [];
  document.getElementById('s-total').textContent = sj.stats.total;
  document.getElementById('s-act').textContent = sj.stats.active;
  document.getElementById('s-exp').textContent = sj.stats.expired;
  document.getElementById('s-ban').textContent = sj.stats.banned;
  render();
}
function statusOf(k){
  if (k.status === 'banned') return '<span class="badge b-ban">BANNED</span>';
  if (k.expires && k.expires <= Date.now()) return '<span class="badge b-exp">EXPIRED</span>';
  return '<span class="badge b-act">AKTIF</span>';
}
function render(){
  const q = document.getElementById('q').value.toLowerCase();
  const rows = KEYS.filter(k => !q || (k.key+k.note+(k.serials||[]).join(' ')).toLowerCase().includes(q))
    .map(k => '<tr>' +
      '<td><span class="key" onclick="copyKey(\\'' + k.key + '\\')">' + k.key + '</span></td>' +
      '<td>' + statusOf(k) + '</td>' +
      '<td>' + fmt(k.created) + '</td>' +
      '<td>' + fmt(k.expires) + '<div class="sisa">' + sisa(k.expires) + '</div></td>' +
      '<td>' + ((k.serials||[]).map(esc).join('<br>') || '<span style="color:var(--dim)">-</span>') + '</td>' +
      '<td>' + (k.uses||0) + 'x</td>' +
      '<td>' + esc(k.note) + '</td>' +
      '<td style="white-space:nowrap">' +
        '<button class="mini ghost" onclick="act(\\'extend\\',\\'' + k.key + '\\')">+</button> ' +
        ((k.serials||[]).length ? '<button class="mini ghost" onclick="act(\\'reset\\',\\'' + k.key + '\\')">reset</button> ' : '') +
        (k.status==='banned'
          ? '<button class="mini green" onclick="act(\\'unban\\',\\'' + k.key + '\\')">unban</button> '
          : '<button class="mini ghost" onclick="act(\\'ban\\',\\'' + k.key + '\\')">ban</button> ') +
        '<button class="mini red" onclick="del(\\'' + k.key + '\\')">hapus</button>' +
      '</td></tr>';
  document.getElementById('tb').innerHTML = rows.join('') || '<tr><td colspan="8" class="empty">Belum ada key</td></tr>';
}
document.getElementById('dur').onchange = e => document.getElementById('cwrap').style.display = e.target.value==='custom'?'':'none';
async function createKey(){
  const dur = document.getElementById('dur').value;
  const body = { duration: dur, qty: document.getElementById('qty').value,
    max_devices: document.getElementById('mdev').value, note: document.getElementById('note').value };
  if (dur === 'custom') body.custom_days = document.getElementById('cdays').value;
  const r = await fetch('/admin/api/create', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify(body) });
  const j = await r.json();
  if (j.ok){ toast(j.keys.length + ' key dibuat'); loadAll(); } else toast('Gagal: ' + (j.error||''));
}
async function act(a, k){
  let days = 0;
  if (a === 'extend'){ days = prompt('Perpanjang berapa hari?', '7'); if (!days) return; }
  const r = await fetch('/admin/api/' + a, { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({key:k, days}) });
  const j = await r.json();
  if (j.ok){ toast('OK'); loadAll(); } else toast('Gagal: ' + (j.error||''));
}
async function del(k){
  if (!confirm('Hapus key ' + k + '?')) return;
  const r = await fetch('/admin/api/delete', { method:'POST', headers:{'content-type':'application/json'}, body: JSON.stringify({key:k}) });
  const j = await r.json();
  if (j.ok){ toast('Terhapus'); loadAll(); }
}
function copyKey(k){ navigator.clipboard.writeText(k).then(()=>toast('Copied: ' + k)); }
loadAll();
</script></body></html>`;
  return html(res, page);
}

/* ==========================================================================
 *  ROUTER
 * ========================================================================== */
const server = http.createServer(async (req, res) => {
  const url = new URL(req.url, 'http://localhost');
  const pathname = url.pathname.replace(/\/+$/, '') || '/';

  try {
    // ---------- CORS preflight ----------
    if (req.method === 'OPTIONS') {
      res.writeHead(204, {
        'access-control-allow-origin': '*',
        'access-control-allow-methods': 'GET, POST, OPTIONS',
        'access-control-allow-headers': 'content-type',
      });
      return res.end();
    }

    // ---------- healthcheck (Railway) ----------
    if (pathname === '/health') {
      return json(res, { ok: true, uptime: process.uptime(), keys: Object.keys(db).length });
    }

    // ---------- API utama (kompatibel payload) ----------
    if (pathname === '/' || pathname === '/api/verify' || pathname === '/api/validate') {
      const isVerify =
        pathname !== '/' ||
        req.method === 'POST' ||
        url.searchParams.has('user_key') ||
        url.searchParams.has('key') ||
        url.searchParams.has('serial');
      if (isVerify && (req.method === 'POST' || req.method === 'GET')) {
        return await handleVerify(req, res, url);
      }
      return pageLanding(res);
    }

    // ---------- Admin panel ----------
    if (pathname === '/admin') {
      if (isAuthed(req)) return pagePanel(res);
      return pageLogin(res);
    }
    if (pathname === '/admin/login' && req.method === 'POST') {
      return await adminLogin(req, res);
    }
    if (pathname === '/admin/logout' && req.method === 'POST') {
      res.writeHead(302, {
        'set-cookie': 'ks_sess=; Path=/; HttpOnly; Max-Age=0',
        location: '/admin',
      });
      return res.end();
    }

    if (pathname.startsWith('/admin/api/')) {
      if (!isAuthed(req)) {
        return json(res, { ok: false, error: 'unauthorized' }, 401);
      }
      return await adminApi(req, res, pathname);
    }

    if (pathname === '/favicon.ico') {
      res.writeHead(204);
      return res.end();
    }

    return json(res, { ok: false, error: 'not_found' }, 404);
  } catch (err) {
    console.error('[keypanel] error:', err);
    if (!res.headersSent) return json(res, { ok: false, error: 'server_error', detail: String(err) }, 500);
  }
});

server.listen(PORT, () => {
  console.log(`[keypanel] listening on :${PORT} | prefix=${cfg.KEY_PREFIX} | ADMIN_PASSWORD ${cfg.ADMIN_PASSWORD ? 'DISET' : 'BELUM DISET (panel terkunci!)'}`);
});
