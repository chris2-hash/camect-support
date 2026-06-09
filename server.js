// Camect Support Ticketing
// node server.js [port]

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');
const net    = require('net');
const tls    = require('tls');
const https  = require('https');

const PORT           = parseInt(process.argv[2]) || 3000;
const TICKETS_FILE   = path.join(__dirname, 'tickets.json');
const USERS_FILE     = path.join(__dirname, 'users.json');
const CUSTOMERS_FILE = path.join(__dirname, 'customers.json');
const CANNED_FILE    = path.join(__dirname, 'canned.json');
const TEMPLATES_FILE = path.join(__dirname, 'templates.json');
const SETTINGS_FILE  = path.join(__dirname, 'settings.json');
const ATTACH_DIR     = path.join(__dirname, 'attachments');
const MAX_ATTACH     = 10 * 1024 * 1024;

const DEFAULT_SETTINGS = {
  smtp:   { enabled: false, host: '', port: 587, secure: false, user: '', password: '', from: '' },
  sla:    { urgent: 4, high: 8, normal: 24, low: 72 },
  notify: { onCreate: true, onAssign: true, onComment: true, onStatus: true },
  ai:     { apiKey: '', model: 'claude-haiku-4-5-20251001' },
  google: { clientId: '', clientSecret: '', redirectUri: `http://localhost:${parseInt(process.argv[2])||3000}/auth/google/callback`, refreshToken: '', accessToken: '', tokenExpiry: 0 },
};

// ── Helpers ───────────────────────────────────────────────────────────────

function load(file, def = []) {
  try { return JSON.parse(fs.readFileSync(file, 'utf8')); } catch { return def; }
}
function save(file, data) {
  try { fs.writeFileSync(file, JSON.stringify(data, null, 2)); }
  catch (e) { console.error('[save]', e.message); }
}
function uid()  { return crypto.randomBytes(6).toString('hex'); }
function json(res, code, obj) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'Content-Type': 'application/json', 'Content-Length': Buffer.byteLength(body) });
  res.end(body);
}
function hashPassword(pw) {
  const salt = crypto.randomBytes(16).toString('hex');
  return salt + ':' + crypto.createHmac('sha256', salt).update(pw).digest('hex');
}
function verifyPassword(pw, stored) {
  const [salt, hash] = stored.split(':');
  return crypto.createHmac('sha256', salt).update(pw).digest('hex') === hash;
}
async function readBody(req) {
  return new Promise(resolve => {
    const c = []; req.on('data', d => c.push(d)); req.on('end', () => resolve(Buffer.concat(c)));
  });
}
function parseMultipart(body, boundary) {
  const parts = [], sep = Buffer.from('--' + boundary);
  let pos = body.indexOf(sep) + sep.length + 2;
  while (pos < body.length) {
    const end = body.indexOf(sep, pos);
    if (end === -1) break;
    const part = body.slice(pos, end - 2);
    const hEnd = part.indexOf('\r\n\r\n');
    if (hEnd !== -1) parts.push({
      name:     (part.slice(0, hEnd).toString().match(/name="([^"]+)"/)     || [])[1] || '',
      filename: (part.slice(0, hEnd).toString().match(/filename="([^"]+)"/) || [])[1] || '',
      data: part.slice(hEnd + 4),
    });
    pos = end + sep.length + 2;
  }
  return parts;
}

// ── State ─────────────────────────────────────────────────────────────────

let tickets   = load(TICKETS_FILE);
let users     = load(USERS_FILE);
let customers = load(CUSTOMERS_FILE);
let canned    = load(CANNED_FILE);
let templates = load(TEMPLATES_FILE);
const rawSettings = load(SETTINGS_FILE, {});
let settings = {
  smtp:   { ...DEFAULT_SETTINGS.smtp,   ...(rawSettings.smtp   || {}) },
  sla:    { ...DEFAULT_SETTINGS.sla,    ...(rawSettings.sla    || {}) },
  notify: { ...DEFAULT_SETTINGS.notify, ...(rawSettings.notify || {}) },
  ai:     { ...DEFAULT_SETTINGS.ai,     ...(rawSettings.ai     || {}) },
  google: { ...DEFAULT_SETTINGS.google, ...(rawSettings.google || {}) },
};

let nextSeq    = tickets.reduce((m, t) => Math.max(m, t.seq || 0), 0) + 1;
const sessions = {};
let sseClients = [];

if (!fs.existsSync(ATTACH_DIR)) fs.mkdirSync(ATTACH_DIR, { recursive: true });

if (users.length === 0) {
  users.push({ id: uid(), username: 'admin', passwordHash: hashPassword('admin'),
    role: 'admin', displayName: 'Administrator', email: '', ts: Date.now() });
  save(USERS_FILE, users);
  console.log('[Setup] Default admin created — login: admin / admin');
}

// ── Session ───────────────────────────────────────────────────────────────

function createSession(user) {
  const token = crypto.randomBytes(32).toString('hex');
  sessions[token] = { id: user.id, username: user.username, role: user.role, displayName: user.displayName };
  return token;
}
function getSession(req) {
  const m = (req.headers.cookie || '').match(/session=([a-f0-9]+)/);
  return m ? (sessions[m[1]] || null) : null;
}

// ── SSE ───────────────────────────────────────────────────────────────────

function ssePublish(type, data) {
  const msg = `data: ${JSON.stringify({ type, ...data })}\n\n`;
  sseClients = sseClients.filter(res => {
    try { res.write(msg); return true; } catch { return false; }
  });
}

// ── Email ─────────────────────────────────────────────────────────────────

async function sendMail(cfg, to, subject, bodyHtml) {
  if (!cfg?.enabled || !cfg.host || !to) return;
  const b64 = s => Buffer.from(s).toString('base64');
  const recipients = [].concat(to).filter(Boolean);
  if (!recipients.length) return;

  return new Promise((resolve, reject) => {
    let buf = '', settled = false;
    const incoming = [], pending = [];
    const timer = setTimeout(() => settle(new Error('SMTP timeout')), 15000);

    function settle(err) {
      if (settled) return; settled = true;
      clearTimeout(timer);
      err ? reject(err) : resolve();
    }

    const useSSL = cfg.port === 465 || cfg.secure;
    const sock = useSSL
      ? tls.connect({ host: cfg.host, port: cfg.port || 465, servername: cfg.host })
      : net.connect({ host: cfg.host, port: cfg.port || 587 });

    sock.on('error', settle);
    sock.on('data', chunk => {
      buf += chunk.toString();
      let i;
      while ((i = buf.indexOf('\r\n')) !== -1) {
        const line = buf.slice(0, i); buf = buf.slice(i + 2);
        pending.length ? pending.shift()(line) : incoming.push(line);
      }
    });

    function readline() {
      if (incoming.length) return Promise.resolve(incoming.shift());
      return new Promise(res => pending.push(res));
    }
    async function readResp() {
      let line; do { line = await readline(); } while (line[3] === '-');
      return line;
    }
    async function expect(code) {
      const line = await readResp();
      if (parseInt(line) !== code) throw new Error(`SMTP ${parseInt(line)}: ${line.slice(4)}`);
    }
    function write(s) { sock.write(s + '\r\n'); }

    async function run() {
      await expect(220);
      write('EHLO mail.support');
      await expect(250);
      if (cfg.user && cfg.password) {
        write('AUTH LOGIN');
        await expect(334);
        write(b64(cfg.user));
        await expect(334);
        write(b64(cfg.password));
        await expect(235);
      }
      write(`MAIL FROM:<${cfg.from}>`);
      await expect(250);
      for (const r of recipients) { write(`RCPT TO:<${r}>`); await expect(250); }
      write('DATA');
      await expect(354);
      sock.write([
        `From: Camect Support <${cfg.from}>`,
        `To: ${recipients.join(', ')}`,
        `Subject: ${subject}`,
        `MIME-Version: 1.0`,
        `Content-Type: text/html; charset=UTF-8`,
        `Date: ${new Date().toUTCString()}`,
        '', bodyHtml, '.',
      ].join('\r\n') + '\r\n');
      await expect(250);
      write('QUIT');
      sock.end();
      settle();
    }
    run().catch(settle);
  });
}

async function notifyTicket(event, ticket, extra = {}) {
  if (!settings.smtp?.enabled) return;
  if (event === 'created'  && !settings.notify?.onCreate)  return;
  if (event === 'assigned' && !settings.notify?.onAssign)  return;
  if (event === 'comment'  && !settings.notify?.onComment) return;
  if (event === 'status'   && !settings.notify?.onStatus)  return;
  const recipientName = extra.newAssignee || ticket.assignedTo;
  if (!recipientName) return;
  const user = users.find(u => u.username === recipientName);
  if (!user?.email) return;
  const subjects = {
    created:  `[${ticket.ticketId}] New ticket: ${ticket.title}`,
    assigned: `[${ticket.ticketId}] Assigned to you: ${ticket.title}`,
    comment:  `[${ticket.ticketId}] New comment: ${ticket.title}`,
    status:   `[${ticket.ticketId}] Status changed: ${ticket.title}`,
  };
  const row = (k, v) => `<tr><td style="padding:4px 10px;color:#888;white-space:nowrap">${k}</td><td style="padding:4px 10px">${v}</td></tr>`;
  const html = `<div style="font-family:sans-serif;max-width:580px;margin:0 auto;padding:24px">
    <h2 style="color:#4f8ef7;margin-bottom:16px">${subjects[event] || ticket.title}</h2>
    <table style="border-collapse:collapse;width:100%;background:#f5f5f5;border-radius:6px;margin-bottom:20px">
      ${row('Status', ticket.status)} ${row('Priority', ticket.priority)}
      ${row('Customer', ticket.customerName || '—')} ${row('Assigned to', ticket.assignedTo || '—')}
      ${extra.comment ? row('Comment', extra.comment.replace(/\n/g, '<br>')) : ''}
    </table>
    <a href="http://localhost:${PORT}/" style="background:#4f8ef7;color:#fff;padding:9px 18px;border-radius:5px;text-decoration:none;font-size:13px">View Ticket</a>
  </div>`;
  try {
    await sendMail(settings.smtp, user.email, subjects[event] || ticket.title, html);
    console.log(`[Email] Notified ${user.email} (${event})`);
  } catch (e) {
    console.error('[Email] Failed:', e.message);
  }
}

// ── AI Diagnosis ──────────────────────────────────────────────────────────

async function callClaude(apiKey, model, report, ticket) {
  const system = `You are a Camect hub support engineer. Diagnose hub bug reports and logs.
Ticket: ${ticket.title} | Priority: ${ticket.priority} | Category: ${ticket.category}${ticket.description ? '\nDescription: ' + ticket.description : ''}

Respond with three sections:
**Root Cause** — what is causing the issue
**Affected Components** — which parts of the system are involved
**Resolution Steps** — numbered, actionable steps to fix the issue

Be concise and specific to Camect hub hardware and software.`;

  const payload = JSON.stringify({
    model: model || 'claude-haiku-4-5-20251001',
    max_tokens: 1024,
    system,
    messages: [{ role: 'user', content: 'Hub bug report / log:\n\n' + report }],
  });

  return new Promise((resolve, reject) => {
    const req = https.request({
      hostname: 'api.anthropic.com',
      path: '/v1/messages',
      method: 'POST',
      headers: {
        'x-api-key': apiKey,
        'anthropic-version': '2023-06-01',
        'content-type': 'application/json',
        'content-length': Buffer.byteLength(payload),
      },
    }, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try {
          const parsed = JSON.parse(data);
          if (parsed.error) return reject(new Error(parsed.error.message || 'API error'));
          const text = parsed.content?.[0]?.text;
          if (!text) return reject(new Error('Empty response from Claude API'));
          resolve(text);
        } catch (e) { reject(new Error('Failed to parse Claude API response')); }
      });
    });
    req.on('error', reject);
    req.write(payload);
    req.end();
  });
}

// ── Google / Gmail ────────────────────────────────────────────────────────

function httpsReq(hostname, path, method, headers, bodyStr) {
  return new Promise((resolve, reject) => {
    const opts = { hostname, path, method, headers: { ...headers } };
    if (bodyStr) opts.headers['content-length'] = Buffer.byteLength(bodyStr);
    const req = https.request(opts, res => {
      let data = '';
      res.on('data', c => data += c);
      res.on('end', () => {
        try { resolve({ status: res.statusCode, body: JSON.parse(data) }); }
        catch { resolve({ status: res.statusCode, body: data }); }
      });
    });
    req.on('error', reject);
    if (bodyStr) req.write(bodyStr);
    req.end();
  });
}

async function refreshGoogleToken() {
  if (!settings.google.refreshToken) throw new Error('Gmail not connected');
  const body = new URLSearchParams({
    client_id:     settings.google.clientId,
    client_secret: settings.google.clientSecret,
    refresh_token: settings.google.refreshToken,
    grant_type:    'refresh_token',
  }).toString();
  const r = await httpsReq('oauth2.googleapis.com', '/token', 'POST',
    { 'content-type': 'application/x-www-form-urlencoded' }, body);
  if (r.body.error) throw new Error(r.body.error_description || r.body.error);
  settings.google.accessToken = r.body.access_token;
  settings.google.tokenExpiry = Date.now() + (r.body.expires_in * 1000);
  save(SETTINGS_FILE, settings);
}

async function callGmailAPI(gmailPath) {
  if (!settings.google.refreshToken) throw new Error('Gmail not connected. Go to Settings → Gmail.');
  if (Date.now() >= settings.google.tokenExpiry - 60000) await refreshGoogleToken();
  const r = await httpsReq('gmail.googleapis.com', gmailPath, 'GET',
    { 'Authorization': 'Bearer ' + settings.google.accessToken }, null);
  if (r.status === 401) { await refreshGoogleToken(); return callGmailAPI(gmailPath); }
  return r.body;
}

// ── Timeline helper ───────────────────────────────────────────────────────

function tl(sess, type, text, extra = {}) {
  return { ts: Date.now(), user: sess.username, type, text, ...extra };
}

// ── Route handler ─────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  const parsed   = new URL(req.url, 'http://localhost');
  const pathname = parsed.pathname;
  const method   = req.method;

  if (pathname === '/' || pathname === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return fs.createReadStream(path.join(__dirname, 'ui.html')).pipe(res);
  }

  if (pathname === '/auth/login' && method === 'POST') {
    const b = JSON.parse((await readBody(req)).toString() || '{}');
    const u = users.find(u => u.username === b.username);
    if (!u || !verifyPassword(b.password || '', u.passwordHash))
      return json(res, 401, { error: 'Invalid username or password' });
    const token = createSession(u);
    res.setHeader('Set-Cookie', `session=${token}; Path=/; HttpOnly; SameSite=Strict`);
    return json(res, 200, { ok: true, user: { id: u.id, username: u.username, role: u.role, displayName: u.displayName } });
  }

  if (pathname === '/auth/logout' && method === 'POST') {
    const m = (req.headers.cookie || '').match(/session=([a-f0-9]+)/);
    if (m) delete sessions[m[1]];
    res.setHeader('Set-Cookie', 'session=; Path=/; Max-Age=0');
    return json(res, 200, { ok: true });
  }

  if (pathname === '/stream') {
    const sess = getSession(req);
    if (!sess) return json(res, 401, { error: 'Not authenticated' });
    res.writeHead(200, { 'Content-Type': 'text/event-stream', 'Cache-Control': 'no-cache', 'Connection': 'keep-alive' });
    res.write(`data: ${JSON.stringify({ type: 'connected' })}\n\n`);
    sseClients.push(res);
    req.on('close', () => { sseClients = sseClients.filter(c => c !== res); });
    return;
  }

  // Google OAuth redirects — no session required
  if (pathname === '/auth/google' && method === 'GET') {
    if (!settings.google.clientId) { res.writeHead(302,{'Location':'/?google=no-config'}); return res.end(); }
    const params = new URLSearchParams({
      client_id:     settings.google.clientId,
      redirect_uri:  settings.google.redirectUri,
      response_type: 'code',
      scope:         'https://www.googleapis.com/auth/gmail.readonly',
      access_type:   'offline',
      prompt:        'consent',
    });
    res.writeHead(302, { 'Location': 'https://accounts.google.com/o/oauth2/v2/auth?' + params });
    return res.end();
  }

  if (pathname === '/auth/google/callback' && method === 'GET') {
    const code = parsed.searchParams.get('code');
    if (!code) { res.writeHead(302,{'Location':'/?google=error'}); return res.end(); }
    try {
      const body = new URLSearchParams({
        code, grant_type: 'authorization_code',
        client_id:     settings.google.clientId,
        client_secret: settings.google.clientSecret,
        redirect_uri:  settings.google.redirectUri,
      }).toString();
      const r = await httpsReq('oauth2.googleapis.com', '/token', 'POST',
        { 'content-type': 'application/x-www-form-urlencoded' }, body);
      if (r.body.error) throw new Error(r.body.error_description || r.body.error);
      settings.google.accessToken  = r.body.access_token;
      settings.google.refreshToken = r.body.refresh_token || settings.google.refreshToken;
      settings.google.tokenExpiry  = Date.now() + (r.body.expires_in * 1000);
      save(SETTINGS_FILE, settings);
      res.writeHead(302, { 'Location': '/?google=connected' });
    } catch (e) {
      console.error('[Google OAuth]', e.message);
      res.writeHead(302, { 'Location': '/?google=error&msg=' + encodeURIComponent(e.message) });
    }
    return res.end();
  }

  const sess = getSession(req);
  if (!sess) return json(res, 401, { error: 'Not authenticated' });
  if (pathname === '/auth/me') return json(res, 200, sess);

  // ── Stats ──────────────────────────────────────────────────────────────

  if (pathname === '/stats' && method === 'GET') {
    const s = { byStatus: {}, byPriority: {}, unassigned: 0, myOpen: 0 };
    for (const t of tickets) {
      s.byStatus[t.status]     = (s.byStatus[t.status]     || 0) + 1;
      s.byPriority[t.priority] = (s.byPriority[t.priority] || 0) + 1;
      const active = t.status !== 'closed' && t.status !== 'resolved';
      if (active && !t.assignedTo)                  s.unassigned++;
      if (active && t.assignedTo === sess.username) s.myOpen++;
    }
    return json(res, 200, s);
  }

  // ── Tickets list / create ──────────────────────────────────────────────

  if (pathname === '/tickets' && method === 'GET') {
    let r = [...tickets];
    const q = parsed.searchParams;
    const status = q.get('status'), priority = q.get('priority');
    const category = q.get('category'), assigned = q.get('assignedTo');
    const search = (q.get('search') || '').toLowerCase();
    if (status   && status   !== 'all') r = r.filter(t => t.status   === status);
    if (priority && priority !== 'all') r = r.filter(t => t.priority === priority);
    if (category && category !== 'all') r = r.filter(t => t.category === category);
    if (assigned === 'me')                   r = r.filter(t => t.assignedTo === sess.username);
    else if (assigned === 'unassigned')      r = r.filter(t => !t.assignedTo);
    else if (assigned && assigned !== 'all') r = r.filter(t => t.assignedTo === assigned);
    if (search) r = r.filter(t =>
      t.title.toLowerCase().includes(search) ||
      t.description.toLowerCase().includes(search) ||
      (t.customerName || '').toLowerCase().includes(search) ||
      t.ticketId.toLowerCase().includes(search));
    const ord = { open: 0, in_progress: 1, pending: 2, resolved: 3, closed: 4 };
    r.sort((a, b) => { const d = (ord[a.status]||0)-(ord[b.status]||0); return d || b.updatedTs - a.updatedTs; });
    const total = r.length;
    const limit = Math.max(1, parseInt(q.get('limit')) || 50);
    const page  = Math.max(1, parseInt(q.get('page'))  || 1);
    return json(res, 200, { tickets: r.slice((page-1)*limit, page*limit), total, page, pages: Math.ceil(total/limit) || 1, limit });
  }

  if (pathname === '/tickets' && method === 'POST') {
    const b    = JSON.parse((await readBody(req)).toString() || '{}');
    const cust = customers.find(c => c.id === b.customerId);
    const seq  = nextSeq++;
    const t = {
      id: uid(), ticketId: 'TKT-' + String(seq).padStart(4, '0'), seq,
      ts: Date.now(), updatedTs: Date.now(),
      title: (b.title || '').trim() || 'Untitled',
      description: b.description || '',
      status: 'open', priority: b.priority || 'normal', category: b.category || 'other',
      customerId:   cust?.id   || '',
      customerName: cust?.name || b.customerName || '',
      hubId:        cust?.hubId || b.hubId || '',
      assignedTo: b.assignedTo || '', createdBy: sess.username,
      dueDate: b.dueDate || null,
      attachments: [],
      timeline: [tl(sess, 'created', `Ticket created by ${sess.username}`)],
    };
    if (b.assignedTo) t.timeline.push(tl(sess, 'assigned', `Assigned to ${b.assignedTo}`));
    tickets.unshift(t);
    save(TICKETS_FILE, tickets);
    ssePublish('ticket.created', { ticket: t });
    notifyTicket('created', t).catch(() => {});
    if (b.assignedTo) notifyTicket('assigned', t, { newAssignee: b.assignedTo }).catch(() => {});
    return json(res, 201, t);
  }

  // ── Bulk actions ───────────────────────────────────────────────────────

  if (pathname === '/tickets/bulk' && method === 'POST') {
    const b = JSON.parse((await readBody(req)).toString() || '{}');
    const { ids = [], action, value } = b;
    if (!ids.length) return json(res, 400, { error: 'No IDs provided' });
    let count = 0;
    for (const id of ids) {
      const t = tickets.find(t => t.id === id);
      if (!t) continue;
      if (action === 'delete') {
        if (sess.role !== 'admin') continue;
        tickets = tickets.filter(x => x.id !== id);
        ssePublish('ticket.deleted', { id });
        count++; continue;
      }
      if (action === 'status'   && t.status   !== value) { const p = t.status;    t.status   = value; t.timeline.push(tl(sess, 'status_change',   `Status: ${p} → ${value}`)); }
      if (action === 'priority' && t.priority !== value) { const p = t.priority;  t.priority = value; t.timeline.push(tl(sess, 'priority_change', `Priority: ${p} → ${value}`)); }
      if (action === 'assignee') { t.assignedTo = value; t.timeline.push(tl(sess, 'assigned', value ? `Assigned to ${value}` : 'Unassigned')); }
      t.updatedTs = Date.now();
      ssePublish('ticket.updated', { ticket: t });
      count++;
    }
    save(TICKETS_FILE, tickets);
    return json(res, 200, { ok: true, count });
  }

  // ── CSV export ─────────────────────────────────────────────────────────

  if (pathname === '/tickets/export' && method === 'GET') {
    let r = [...tickets];
    const q = parsed.searchParams;
    const status = q.get('status'), priority = q.get('priority'), category = q.get('category'), assigned = q.get('assignedTo');
    const search = (q.get('search') || '').toLowerCase();
    if (status   && status   !== 'all') r = r.filter(t => t.status   === status);
    if (priority && priority !== 'all') r = r.filter(t => t.priority === priority);
    if (category && category !== 'all') r = r.filter(t => t.category === category);
    if (assigned === 'me')                   r = r.filter(t => t.assignedTo === sess.username);
    else if (assigned === 'unassigned')      r = r.filter(t => !t.assignedTo);
    else if (assigned && assigned !== 'all') r = r.filter(t => t.assignedTo === assigned);
    if (search) r = r.filter(t => t.title.toLowerCase().includes(search) || (t.customerName||'').toLowerCase().includes(search));
    const ord = { open: 0, in_progress: 1, pending: 2, resolved: 3, closed: 4 };
    r.sort((a, b) => { const d = (ord[a.status]||0)-(ord[b.status]||0); return d || b.updatedTs - a.updatedTs; });
    const q2 = s => `"${(s||'').toString().replace(/"/g,'""')}"`;
    const header = 'Ticket ID,Title,Status,Priority,Category,Customer,Hub ID,Assigned To,Created By,Due Date,Created,Updated,Description';
    const rows = r.map(t => [
      t.ticketId, t.title, t.status, t.priority, t.category,
      t.customerName||'', t.hubId||'', t.assignedTo||'', t.createdBy,
      t.dueDate ? new Date(t.dueDate).toISOString().slice(0,10) : '',
      new Date(t.ts).toISOString(), new Date(t.updatedTs).toISOString(),
      t.description,
    ].map(q2).join(','));
    const csv = [header, ...rows].join('\r\n');
    res.writeHead(200, { 'Content-Type': 'text/csv', 'Content-Disposition': `attachment; filename="tickets-${Date.now()}.csv"`, 'Content-Length': Buffer.byteLength(csv) });
    return res.end(csv);
  }

  // ── Single ticket ──────────────────────────────────────────────────────

  const mTicket = pathname.match(/^\/tickets\/([^/]+)$/);
  if (mTicket) {
    const idx = tickets.findIndex(t => t.id === mTicket[1] || t.ticketId === mTicket[1]);
    if (idx === -1) return json(res, 404, { error: 'Not found' });
    const t = tickets[idx];
    if (method === 'GET') return json(res, 200, t);
    if (method === 'PUT') {
      const b    = JSON.parse((await readBody(req)).toString() || '{}');
      const cust = b.customerId ? customers.find(c => c.id === b.customerId) : null;
      if (b.title       !== undefined) t.title       = b.title;
      if (b.description !== undefined) t.description = b.description;
      if (b.category    !== undefined) t.category    = b.category;
      if (b.dueDate     !== undefined) t.dueDate     = b.dueDate || null;
      if (b.status   !== undefined && b.status   !== t.status)   { const p = t.status;    t.status   = b.status;    t.timeline.push(tl(sess, 'status_change',   `Status: ${p} → ${b.status}`));    notifyTicket('status', t).catch(()=>{}); }
      if (b.priority !== undefined && b.priority !== t.priority) { const p = t.priority;  t.priority = b.priority;  t.timeline.push(tl(sess, 'priority_change', `Priority: ${p} → ${b.priority}`)); }
      if (b.assignedTo !== undefined && b.assignedTo !== t.assignedTo) {
        t.assignedTo = b.assignedTo;
        t.timeline.push(tl(sess, 'assigned', b.assignedTo ? `Assigned to ${b.assignedTo}` : 'Unassigned'));
        if (b.assignedTo) notifyTicket('assigned', t, { newAssignee: b.assignedTo }).catch(()=>{});
      }
      if (b.customerId !== undefined) {
        t.customerId   = cust?.id   || b.customerId;
        t.customerName = cust?.name || b.customerName || t.customerName;
        t.hubId        = cust?.hubId || b.hubId || t.hubId;
      }
      t.updatedTs = Date.now();
      save(TICKETS_FILE, tickets);
      ssePublish('ticket.updated', { ticket: t });
      return json(res, 200, t);
    }
    if (method === 'DELETE') {
      if (sess.role !== 'admin') return json(res, 403, { error: 'Admin only' });
      tickets.splice(idx, 1);
      save(TICKETS_FILE, tickets);
      ssePublish('ticket.deleted', { id: mTicket[1] });
      return json(res, 200, { ok: true });
    }
  }

  // ── Comments ───────────────────────────────────────────────────────────

  const mComment = pathname.match(/^\/tickets\/([^/]+)\/comments$/);
  if (mComment && method === 'POST') {
    const t = tickets.find(t => t.id === mComment[1]);
    if (!t) return json(res, 404, { error: 'Not found' });
    const b = JSON.parse((await readBody(req)).toString() || '{}');
    if (!b.text?.trim()) return json(res, 400, { error: 'Text required' });
    const entry = tl(sess, b.isNote ? 'note' : 'comment', b.text.trim(), { isNote: !!b.isNote });
    t.timeline.push(entry);
    t.updatedTs = Date.now();
    save(TICKETS_FILE, tickets);
    ssePublish('ticket.updated', { ticket: t });
    if (!b.isNote) notifyTicket('comment', t, { comment: b.text.trim() }).catch(() => {});
    return json(res, 201, entry);
  }

  // ── Merge ──────────────────────────────────────────────────────────────

  const mMerge = pathname.match(/^\/tickets\/([^/]+)\/merge$/);
  if (mMerge && method === 'POST') {
    const src = tickets.find(t => t.id === mMerge[1]);
    if (!src) return json(res, 404, { error: 'Source ticket not found' });
    const b   = JSON.parse((await readBody(req)).toString() || '{}');
    const dst = tickets.find(t => t.id === b.targetId || t.ticketId === b.targetId);
    if (!dst) return json(res, 404, { error: 'Target ticket not found' });
    if (src.id === dst.id) return json(res, 400, { error: 'Cannot merge into itself' });
    dst.timeline.push(tl(sess, 'merge', `Merged from ${src.ticketId}: ${src.title}`));
    src.timeline.filter(e => e.type !== 'created').forEach(e => dst.timeline.push({ ...e }));
    dst.attachments.push(...src.attachments);
    dst.updatedTs = Date.now();
    src.status = 'closed';
    src.timeline.push(tl(sess, 'status_change', `Merged into ${dst.ticketId} and closed`));
    src.updatedTs = Date.now();
    save(TICKETS_FILE, tickets);
    ssePublish('ticket.updated', { ticket: dst });
    ssePublish('ticket.updated', { ticket: src });
    return json(res, 200, { ok: true, target: dst });
  }

  // ── AI Diagnose ────────────────────────────────────────────────────────

  const mDiagnose = pathname.match(/^\/tickets\/([^/]+)\/diagnose$/);
  if (mDiagnose && method === 'POST') {
    const t = tickets.find(t => t.id === mDiagnose[1]);
    if (!t) return json(res, 404, { error: 'Not found' });
    const b = JSON.parse((await readBody(req)).toString() || '{}');
    if (!b.report?.trim()) return json(res, 400, { error: 'Report text required' });
    if (!settings.ai?.apiKey) return json(res, 400, { error: 'Claude API key not configured. Add it in Settings → AI Diagnosis.' });
    try {
      const reportText = b.report.trim();
      // Save report as txt attachment
      const attId = uid();
      const dateStr = new Date().toISOString().slice(0, 10);
      const stored = attId + '.txt';
      const dir = path.join(ATTACH_DIR, t.id);
      fs.mkdirSync(dir, { recursive: true });
      const reportBuf = Buffer.from(reportText, 'utf8');
      fs.writeFileSync(path.join(dir, stored), reportBuf);
      const att = { id: attId, filename: `hub-report-${dateStr}.txt`, stored, size: reportBuf.length, ts: Date.now(), uploadedBy: sess.username };
      t.attachments.push(att);
      t.timeline.push(tl(sess, 'attachment', `Report saved: hub-report-${dateStr}.txt`));
      // Run diagnosis
      const diagnosis = await callClaude(settings.ai.apiKey, settings.ai.model, reportText, t);
      const entry = tl(sess, 'note', '🤖 AI Diagnosis:\n\n' + diagnosis, { isNote: true });
      t.timeline.push(entry);
      t.updatedTs = Date.now();
      save(TICKETS_FILE, tickets);
      ssePublish('ticket.updated', { ticket: t });
      return json(res, 200, { diagnosis, entry, attachment: att });
    } catch (e) {
      return json(res, 500, { error: e.message });
    }
  }

  // ── Gmail search ──────────────────────────────────────────────────────

  const mGmail = pathname.match(/^\/tickets\/([^/]+)\/gmail-search$/);
  if (mGmail && method === 'POST') {
    const t = tickets.find(t => t.id === mGmail[1]);
    if (!t) return json(res, 404, { error: 'Not found' });
    if (!settings.google.refreshToken) return json(res, 400, { error: 'Gmail not connected. Go to Settings → Gmail.' });
    const b = JSON.parse((await readBody(req)).toString() || '{}');
    const STOP = new Set('the a an is are was were be been have has had do does did will would could should may might to of in on at for with about from by and or but if not no so i you he she it we they'.split(' '));
    // Prefer explicit parsed fields from the report; fall back to ticket metadata
    let terms = [];
    if (b.hubId)      terms.push(b.hubId.trim());
    if (b.macAddress) terms.push(b.macAddress.trim());
    if (!terms.length) {
      terms = [
        ...t.title.toLowerCase().split(/\W+/).filter(w => w.length > 3 && !STOP.has(w)),
        ...(t.customerName ? t.customerName.toLowerCase().split(/\W+/).filter(w => w.length > 2) : []),
        ...(t.hubId ? [t.hubId] : []),
      ];
    }
    const keywords = [...new Set(terms)].slice(0, 6);
    if (!keywords.length) return json(res, 400, { error: 'Not enough keywords to search' });
    const q = keywords.map(k => `"${k}"`).join(' OR ');
    try {
      const list = await callGmailAPI('/gmail/v1/users/me/messages?' + new URLSearchParams({ q, maxResults: 8 }));
      if (!list.messages?.length) return json(res, 200, { results: [], query: q });
      const results = await Promise.all(list.messages.slice(0, 6).map(async m => {
        const msg = await callGmailAPI(`/gmail/v1/users/me/messages/${m.id}?format=metadata&metadataHeaders=Subject&metadataHeaders=From&metadataHeaders=Date`);
        const hdrs = {};
        (msg.payload?.headers || []).forEach(h => { hdrs[h.name] = h.value; });
        return { id: m.id, threadId: m.threadId, subject: hdrs.Subject || '(no subject)', from: hdrs.From || '', date: hdrs.Date || '', snippet: msg.snippet || '' };
      }));
      return json(res, 200, { results, query: q });
    } catch (e) { return json(res, 500, { error: e.message }); }
  }

  // ── Google status / disconnect (authenticated) ─────────────────────────

  if (pathname === '/auth/google/status' && method === 'GET') {
    if (sess.role !== 'admin') return json(res, 403, { error: 'Admin only' });
    return json(res, 200, { connected: !!settings.google.refreshToken, clientConfigured: !!settings.google.clientId });
  }
  if (pathname === '/auth/google/disconnect' && method === 'POST') {
    if (sess.role !== 'admin') return json(res, 403, { error: 'Admin only' });
    settings.google.refreshToken = ''; settings.google.accessToken = ''; settings.google.tokenExpiry = 0;
    save(SETTINGS_FILE, settings);
    return json(res, 200, { ok: true });
  }

  // ── Attachments ────────────────────────────────────────────────────────

  const mAttach = pathname.match(/^\/tickets\/([^/]+)\/attachments$/);
  if (mAttach && method === 'POST') {
    const t  = tickets.find(t => t.id === mAttach[1]);
    if (!t) return json(res, 404, { error: 'Not found' });
    const bm = (req.headers['content-type'] || '').match(/boundary=(.+)/);
    if (!bm) return json(res, 400, { error: 'Expected multipart' });
    const body  = await readBody(req);
    const parts = parseMultipart(body, bm[1].trim());
    const file  = parts.find(p => p.filename);
    if (!file) return json(res, 400, { error: 'No file' });
    if (file.data.length > MAX_ATTACH) return json(res, 413, { error: 'Max 10 MB' });
    const attId = uid(), ext = path.extname(file.filename), stored = attId + ext;
    const dir   = path.join(ATTACH_DIR, t.id);
    fs.mkdirSync(dir, { recursive: true });
    fs.writeFileSync(path.join(dir, stored), file.data);
    const att = { id: attId, filename: file.filename, stored, size: file.data.length, ts: Date.now(), uploadedBy: sess.username };
    t.attachments.push(att);
    t.timeline.push(tl(sess, 'attachment', `Attached: ${file.filename}`));
    t.updatedTs = Date.now();
    save(TICKETS_FILE, tickets);
    ssePublish('ticket.updated', { ticket: t });
    return json(res, 201, att);
  }

  const mGetAtt = pathname.match(/^\/attachments\/([^/]+)\/([^/]+)$/);
  if (mGetAtt && method === 'GET') {
    const [, tid, stored] = mGetAtt;
    const t = tickets.find(t => t.id === tid);
    const att = t?.attachments.find(a => a.stored === stored);
    if (!att) return json(res, 404, { error: 'Not found' });
    const fp = path.join(ATTACH_DIR, tid, stored);
    if (!fs.existsSync(fp)) return json(res, 404, { error: 'File missing' });
    res.writeHead(200, { 'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${att.filename}"`,
      'Content-Length': fs.statSync(fp).size });
    return fs.createReadStream(fp).pipe(res);
  }

  // ── Canned Responses ──────────────────────────────────────────────────

  if (pathname === '/canned') {
    if (method === 'GET') return json(res, 200, canned);
    if (method === 'POST') {
      if (sess.role !== 'admin') return json(res, 403, { error: 'Admin only' });
      const b = JSON.parse((await readBody(req)).toString() || '{}');
      if (!b.title?.trim()) return json(res, 400, { error: 'Title required' });
      const c = { id: uid(), title: b.title.trim(), body: b.body || '' };
      canned.push(c); save(CANNED_FILE, canned);
      return json(res, 201, c);
    }
  }
  const mCanned = pathname.match(/^\/canned\/([^/]+)$/);
  if (mCanned) {
    if (sess.role !== 'admin') return json(res, 403, { error: 'Admin only' });
    const idx = canned.findIndex(c => c.id === mCanned[1]);
    if (idx === -1) return json(res, 404, { error: 'Not found' });
    if (method === 'PUT') {
      const b = JSON.parse((await readBody(req)).toString() || '{}');
      if (b.title !== undefined) canned[idx].title = b.title;
      if (b.body  !== undefined) canned[idx].body  = b.body;
      save(CANNED_FILE, canned); return json(res, 200, canned[idx]);
    }
    if (method === 'DELETE') { canned.splice(idx, 1); save(CANNED_FILE, canned); return json(res, 200, { ok: true }); }
  }

  // ── Templates ─────────────────────────────────────────────────────────

  if (pathname === '/templates') {
    if (method === 'GET') return json(res, 200, templates);
    if (method === 'POST') {
      if (sess.role !== 'admin') return json(res, 403, { error: 'Admin only' });
      const b = JSON.parse((await readBody(req)).toString() || '{}');
      if (!b.name?.trim()) return json(res, 400, { error: 'Name required' });
      const t = { id: uid(), name: b.name.trim(), title: b.title||'', description: b.description||'', priority: b.priority||'normal', category: b.category||'other' };
      templates.push(t); save(TEMPLATES_FILE, templates);
      return json(res, 201, t);
    }
  }
  const mTpl = pathname.match(/^\/templates\/([^/]+)$/);
  if (mTpl) {
    if (sess.role !== 'admin') return json(res, 403, { error: 'Admin only' });
    const idx = templates.findIndex(t => t.id === mTpl[1]);
    if (idx === -1) return json(res, 404, { error: 'Not found' });
    if (method === 'PUT') {
      const b = JSON.parse((await readBody(req)).toString() || '{}');
      Object.assign(templates[idx], { name: b.name||templates[idx].name, title: b.title??templates[idx].title, description: b.description??templates[idx].description, priority: b.priority||templates[idx].priority, category: b.category||templates[idx].category });
      save(TEMPLATES_FILE, templates); return json(res, 200, templates[idx]);
    }
    if (method === 'DELETE') { templates.splice(idx, 1); save(TEMPLATES_FILE, templates); return json(res, 200, { ok: true }); }
  }

  // ── Customers ──────────────────────────────────────────────────────────

  if (pathname === '/customers') {
    if (method === 'GET') return json(res, 200, customers);
    if (method === 'POST') {
      const b = JSON.parse((await readBody(req)).toString() || '{}');
      if (!b.name?.trim()) return json(res, 400, { error: 'Name required' });
      const c = { id: uid(), name: b.name.trim(), hubId: b.hubId||'', email: b.email||'', phone: b.phone||'', notes: b.notes||'', ts: Date.now() };
      customers.push(c); save(CUSTOMERS_FILE, customers);
      return json(res, 201, c);
    }
  }
  const mCust = pathname.match(/^\/customers\/([^/]+)$/);
  if (mCust) {
    const idx = customers.findIndex(c => c.id === mCust[1]);
    if (idx === -1) return json(res, 404, { error: 'Not found' });
    if (method === 'PUT') {
      const b = JSON.parse((await readBody(req)).toString() || '{}');
      ['name','hubId','email','phone','notes'].forEach(k => { if (b[k] !== undefined) customers[idx][k] = b[k]; });
      save(CUSTOMERS_FILE, customers); return json(res, 200, customers[idx]);
    }
    if (method === 'DELETE') { customers.splice(idx, 1); save(CUSTOMERS_FILE, customers); return json(res, 200, { ok: true }); }
  }

  // ── Users ──────────────────────────────────────────────────────────────

  if (pathname === '/users') {
    if (method === 'GET') return json(res, 200, users.map(u => ({ id: u.id, username: u.username, role: u.role, displayName: u.displayName, email: u.email||'', ts: u.ts })));
    if (method === 'POST') {
      if (sess.role !== 'admin') return json(res, 403, { error: 'Admin only' });
      const b = JSON.parse((await readBody(req)).toString() || '{}');
      if (!b.username?.trim() || !b.password) return json(res, 400, { error: 'Username and password required' });
      if (users.find(u => u.username === b.username.trim())) return json(res, 409, { error: 'Username already exists' });
      const u = { id: uid(), username: b.username.trim(), passwordHash: hashPassword(b.password), role: b.role||'agent', displayName: (b.displayName||b.username).trim(), email: b.email||'', ts: Date.now() };
      users.push(u); save(USERS_FILE, users);
      return json(res, 201, { id: u.id, username: u.username, role: u.role, displayName: u.displayName, email: u.email });
    }
  }
  const mUser = pathname.match(/^\/users\/([^/]+)$/);
  if (mUser) {
    const idx = users.findIndex(u => u.id === mUser[1]);
    if (idx === -1) return json(res, 404, { error: 'Not found' });
    if (method === 'PUT') {
      if (sess.role !== 'admin') return json(res, 403, { error: 'Admin only' });
      const b = JSON.parse((await readBody(req)).toString() || '{}');
      const u = users[idx];
      if (b.displayName !== undefined) u.displayName  = b.displayName;
      if (b.role        !== undefined) u.role         = b.role;
      if (b.email       !== undefined) u.email        = b.email;
      if (b.password)                  u.passwordHash = hashPassword(b.password);
      save(USERS_FILE, users);
      return json(res, 200, { id: u.id, username: u.username, role: u.role, displayName: u.displayName, email: u.email });
    }
    if (method === 'DELETE') {
      if (sess.role !== 'admin') return json(res, 403, { error: 'Admin only' });
      if (users[idx].id === sess.id) return json(res, 400, { error: 'Cannot delete yourself' });
      users.splice(idx, 1); save(USERS_FILE, users);
      return json(res, 200, { ok: true });
    }
  }

  // ── Settings ──────────────────────────────────────────────────────────

  if (pathname === '/settings') {
    if (sess.role !== 'admin') return json(res, 403, { error: 'Admin only' });
    if (method === 'GET') {
      const safe = JSON.parse(JSON.stringify(settings));
      if (safe.smtp?.password)         safe.smtp.password         = '••••••••';
      if (safe.ai?.apiKey)             safe.ai.apiKey             = '••••••••';
      if (safe.google?.clientSecret)   safe.google.clientSecret   = '••••••••';
      if (safe.google?.refreshToken)   safe.google.refreshToken   = '••••••••';
      if (safe.google?.accessToken)    delete safe.google.accessToken;
      if (safe.google?.tokenExpiry)    delete safe.google.tokenExpiry;
      return json(res, 200, safe);
    }
    if (method === 'PUT') {
      const b = JSON.parse((await readBody(req)).toString() || '{}');
      if (b.smtp) {
        const { password, ...rest } = b.smtp;
        Object.assign(settings.smtp, rest);
        if (password && password !== '••••••••') settings.smtp.password = password;
      }
      if (b.sla)    Object.assign(settings.sla,    b.sla);
      if (b.notify) Object.assign(settings.notify, b.notify);
      if (b.ai) {
        const { apiKey, ...rest } = b.ai;
        Object.assign(settings.ai, rest);
        if (apiKey && apiKey !== '••••••••') settings.ai.apiKey = apiKey;
      }
      if (b.google) {
        const { clientSecret, refreshToken, ...rest } = b.google;
        Object.assign(settings.google, rest);
        if (clientSecret && clientSecret !== '••••••••') settings.google.clientSecret = clientSecret;
      }
      save(SETTINGS_FILE, settings);
      return json(res, 200, { ok: true });
    }
  }

  if (pathname === '/settings/test-email' && method === 'POST') {
    if (sess.role !== 'admin') return json(res, 403, { error: 'Admin only' });
    const me = users.find(u => u.id === sess.id);
    if (!me?.email) return json(res, 400, { error: 'Set your email address in Users first.' });
    try {
      await sendMail(settings.smtp, me.email, 'Camect Support — Test Email',
        '<div style="font-family:sans-serif;padding:20px"><p>Email notifications are working correctly.</p></div>');
      return json(res, 200, { ok: true });
    } catch (e) {
      return json(res, 500, { error: e.message });
    }
  }

  json(res, 404, { error: 'Not found' });
});

server.listen(PORT, () => {
  const l = '─'.repeat(48);
  console.log(`\n┌${l}┐`);
  console.log(`│  Camect Support Ticketing                        │`);
  console.log(`├${l}┤`);
  console.log(`│  http://localhost:${PORT}                             │`);
  console.log(`│  Default login:  admin / admin                   │`);
  console.log(`└${l}┘\n`);
});
