// Camect Support Ticketing
// node server.js [port]   (default 3000)

const http   = require('http');
const fs     = require('fs');
const path   = require('path');
const crypto = require('crypto');

const PORT           = parseInt(process.argv[2]) || 3000;
const TICKETS_FILE   = path.join(__dirname, 'tickets.json');
const USERS_FILE     = path.join(__dirname, 'users.json');
const CUSTOMERS_FILE = path.join(__dirname, 'customers.json');
const ATTACH_DIR     = path.join(__dirname, 'attachments');
const MAX_ATTACH     = 10 * 1024 * 1024;

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
let nextSeq   = tickets.reduce((m, t) => Math.max(m, t.seq || 0), 0) + 1;
const sessions = {};

if (!fs.existsSync(ATTACH_DIR)) fs.mkdirSync(ATTACH_DIR, { recursive: true });

if (users.length === 0) {
  users.push({ id: uid(), username: 'admin', passwordHash: hashPassword('admin'),
    role: 'admin', displayName: 'Administrator', ts: Date.now() });
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

// ── Timeline helper ───────────────────────────────────────────────────────

function tl(sess, type, text, extra = {}) {
  return { ts: Date.now(), user: sess.username, type, text, ...extra };
}

// ── Server ────────────────────────────────────────────────────────────────

const server = http.createServer(async (req, res) => {
  const parsed   = new URL(req.url, 'http://localhost');
  const pathname = parsed.pathname;
  const method   = req.method;

  if (pathname === '/' || pathname === '/index.html') {
    res.writeHead(200, { 'Content-Type': 'text/html' });
    return fs.createReadStream(path.join(__dirname, 'ui.html')).pipe(res);
  }

  // ── Auth (no session required) ─────────────────────────────────────────

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
      if (active && !t.assignedTo)                    s.unassigned++;
      if (active && t.assignedTo === sess.username)   s.myOpen++;
    }
    return json(res, 200, s);
  }

  // ── Tickets ────────────────────────────────────────────────────────────

  if (pathname === '/tickets' && method === 'GET') {
    let r = [...tickets];
    const q = parsed.searchParams;
    const status   = q.get('status'),   priority = q.get('priority');
    const category = q.get('category'), assigned = q.get('assignedTo');
    const search   = (q.get('search') || '').toLowerCase();
    if (status   && status   !== 'all') r = r.filter(t => t.status   === status);
    if (priority && priority !== 'all') r = r.filter(t => t.priority === priority);
    if (category && category !== 'all') r = r.filter(t => t.category === category);
    if (assigned === 'me')              r = r.filter(t => t.assignedTo === sess.username);
    else if (assigned === 'unassigned') r = r.filter(t => !t.assignedTo);
    else if (assigned && assigned !== 'all') r = r.filter(t => t.assignedTo === assigned);
    if (search) r = r.filter(t =>
      t.title.toLowerCase().includes(search) ||
      t.description.toLowerCase().includes(search) ||
      (t.customerName || '').toLowerCase().includes(search) ||
      t.ticketId.toLowerCase().includes(search));
    const ord = { open: 0, in_progress: 1, pending: 2, resolved: 3, closed: 4 };
    r.sort((a, b) => { const d = (ord[a.status]||0)-(ord[b.status]||0); return d||b.updatedTs-a.updatedTs; });
    return json(res, 200, r);
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
      attachments: [],
      timeline: [tl(sess, 'created', `Ticket created by ${sess.username}`)],
    };
    if (b.assignedTo) t.timeline.push(tl(sess, 'assigned', `Assigned to ${b.assignedTo}`));
    tickets.unshift(t);
    save(TICKETS_FILE, tickets);
    return json(res, 201, t);
  }

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
      if (b.status   !== undefined && b.status   !== t.status)   { const p=t.status;   t.status=b.status;     t.timeline.push(tl(sess,'status_change',   `Status: ${p} → ${b.status}`)); }
      if (b.priority !== undefined && b.priority !== t.priority) { const p=t.priority; t.priority=b.priority; t.timeline.push(tl(sess,'priority_change', `Priority: ${p} → ${b.priority}`)); }
      if (b.assignedTo !== undefined && b.assignedTo !== t.assignedTo) {
        t.assignedTo = b.assignedTo;
        t.timeline.push(tl(sess, 'assigned', b.assignedTo ? `Assigned to ${b.assignedTo}` : 'Unassigned'));
      }
      if (b.customerId !== undefined) {
        t.customerId   = cust?.id   || b.customerId;
        t.customerName = cust?.name || b.customerName || t.customerName;
        t.hubId        = cust?.hubId || b.hubId || t.hubId;
      }
      t.updatedTs = Date.now();
      save(TICKETS_FILE, tickets);
      return json(res, 200, t);
    }
    if (method === 'DELETE') {
      if (sess.role !== 'admin') return json(res, 403, { error: 'Admin only' });
      tickets.splice(idx, 1);
      save(TICKETS_FILE, tickets);
      return json(res, 200, { ok: true });
    }
  }

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
    return json(res, 201, entry);
  }

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
    return json(res, 201, att);
  }

  const mGetAtt = pathname.match(/^\/attachments\/([^/]+)\/([^/]+)$/);
  if (mGetAtt && method === 'GET') {
    const [, tid, stored] = mGetAtt;
    const t   = tickets.find(t => t.id === tid);
    const att = t?.attachments.find(a => a.stored === stored);
    if (!att) return json(res, 404, { error: 'Not found' });
    const fp = path.join(ATTACH_DIR, tid, stored);
    if (!fs.existsSync(fp)) return json(res, 404, { error: 'File missing' });
    res.writeHead(200, { 'Content-Type': 'application/octet-stream',
      'Content-Disposition': `attachment; filename="${att.filename}"`,
      'Content-Length': fs.statSync(fp).size });
    return fs.createReadStream(fp).pipe(res);
  }

  // ── Customers ──────────────────────────────────────────────────────────

  if (pathname === '/customers') {
    if (method === 'GET') return json(res, 200, customers);
    if (method === 'POST') {
      const b = JSON.parse((await readBody(req)).toString() || '{}');
      if (!b.name?.trim()) return json(res, 400, { error: 'Name required' });
      const c = { id: uid(), name: b.name.trim(), hubId: b.hubId||'', email: b.email||'', phone: b.phone||'', notes: b.notes||'', ts: Date.now() };
      customers.push(c);
      save(CUSTOMERS_FILE, customers);
      return json(res, 201, c);
    }
  }

  const mCust = pathname.match(/^\/customers\/([^/]+)$/);
  if (mCust) {
    const idx = customers.findIndex(c => c.id === mCust[1]);
    if (idx === -1) return json(res, 404, { error: 'Not found' });
    if (method === 'PUT') {
      const b = JSON.parse((await readBody(req)).toString() || '{}');
      const c = customers[idx];
      if (b.name  !== undefined) c.name  = b.name;
      if (b.hubId !== undefined) c.hubId = b.hubId;
      if (b.email !== undefined) c.email = b.email;
      if (b.phone !== undefined) c.phone = b.phone;
      if (b.notes !== undefined) c.notes = b.notes;
      save(CUSTOMERS_FILE, customers);
      return json(res, 200, c);
    }
    if (method === 'DELETE') {
      customers.splice(idx, 1);
      save(CUSTOMERS_FILE, customers);
      return json(res, 200, { ok: true });
    }
  }

  // ── Users ──────────────────────────────────────────────────────────────

  if (pathname === '/users') {
    if (method === 'GET') return json(res, 200, users.map(u => ({ id: u.id, username: u.username, role: u.role, displayName: u.displayName, ts: u.ts })));
    if (method === 'POST') {
      if (sess.role !== 'admin') return json(res, 403, { error: 'Admin only' });
      const b = JSON.parse((await readBody(req)).toString() || '{}');
      if (!b.username?.trim() || !b.password) return json(res, 400, { error: 'Username and password required' });
      if (users.find(u => u.username === b.username.trim())) return json(res, 409, { error: 'Username already exists' });
      const u = { id: uid(), username: b.username.trim(), passwordHash: hashPassword(b.password),
        role: b.role || 'agent', displayName: (b.displayName || b.username).trim(), ts: Date.now() };
      users.push(u);
      save(USERS_FILE, users);
      return json(res, 201, { id: u.id, username: u.username, role: u.role, displayName: u.displayName });
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
      if (b.displayName) u.displayName  = b.displayName;
      if (b.role)        u.role         = b.role;
      if (b.password)    u.passwordHash = hashPassword(b.password);
      save(USERS_FILE, users);
      return json(res, 200, { id: u.id, username: u.username, role: u.role, displayName: u.displayName });
    }
    if (method === 'DELETE') {
      if (sess.role !== 'admin') return json(res, 403, { error: 'Admin only' });
      if (users[idx].id === sess.id) return json(res, 400, { error: 'Cannot delete yourself' });
      users.splice(idx, 1);
      save(USERS_FILE, users);
      return json(res, 200, { ok: true });
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
