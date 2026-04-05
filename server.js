const express     = require('express');
const compression = require('compression');
const multer      = require('multer');
const path        = require('path');
const fs          = require('fs');

const app  = express();
const PORT = process.env.PORT || 3000;
const DATA_DIR      = process.env.DATA_DIR || __dirname;
const ACCOUNTS_FILE    = path.join(DATA_DIR, 'accounts.json');
const SUBMISSIONS_FILE = path.join(DATA_DIR, 'submissions.json');
const MAINTENANCE_FILE = path.join(DATA_DIR, 'maintenance.json');
const IMG_COUNTER_FILE = path.join(DATA_DIR, 'imgCounter.json');
const BUG_REPORTS_FILE = path.join(DATA_DIR, 'bug_reports.json');
const ANALYTICS_FILE   = path.join(DATA_DIR, 'analytics.json');
const ANALYTICS_MAX    = 20000; // keep at most this many events
const IMG_DIR          = path.join(DATA_DIR, 'acc_img');

/* ── Security Headers ── */
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('X-XSS-Protection', '1; mode=block');
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  next();
});

/* ── Admin Basic Auth with brute-force protection ── */
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'changeme';

// Track failed login attempts per IP
const authFailures = new Map(); // ip -> { count, resetAt }
const AUTH_MAX_FAILURES = 10;
const AUTH_LOCKOUT_MS   = 15 * 60 * 1000; // 15 minutes

function requireAuth(req, res, next) {
  const ip  = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip;
  const now = Date.now();

  // Check if IP is locked out
  const record = authFailures.get(ip);
  if (record) {
    if (record.count >= AUTH_MAX_FAILURES && record.resetAt > now) {
      const waitMin = Math.ceil((record.resetAt - now) / 60000);
      return res.status(429).send(`登入嘗試次數過多，請 ${waitMin} 分鐘後再試`);
    }
    if (record.resetAt <= now) authFailures.delete(ip);
  }

  const auth = req.headers['authorization'];
  if (auth && auth.startsWith('Basic ')) {
    const decoded = Buffer.from(auth.slice(6), 'base64').toString('utf8');
    const colonIdx = decoded.indexOf(':');
    if (colonIdx !== -1) {
      const user = decoded.slice(0, colonIdx);
      const pass = decoded.slice(colonIdx + 1);
      if (user === ADMIN_USER && pass === ADMIN_PASS) {
        authFailures.delete(ip); // reset on success
        return next();
      }
    }
  }

  // Record failure
  const cur = authFailures.get(ip) || { count: 0, resetAt: now + AUTH_LOCKOUT_MS };
  if (cur.count === 0) cur.resetAt = now + AUTH_LOCKOUT_MS;
  cur.count++;
  authFailures.set(ip, cur);

  res.set('WWW-Authenticate', 'Basic realm="Admin"');
  res.status(401).send('需要登入');
}

// Ensure acc_img directory exists
if (!fs.existsSync(IMG_DIR)) fs.mkdirSync(IMG_DIR, { recursive: true });

app.use(compression());
app.use(express.json({ limit: '50kb' })); // prevent oversized JSON payloads

/* Block direct static access to admin.html and daily.html (any path) */
app.use((req, res, next) => {
  if (req.path === '/admin.html' || req.path.endsWith('/admin.html') || req.path === '/daily.html') return requireAuth(req, res, next);
  next();
});

app.use(express.static(__dirname));

/* ── Helper: read / write accounts.json ── */
function readAccounts() {
  try { return JSON.parse(fs.readFileSync(ACCOUNTS_FILE, 'utf8')); }
  catch(e) { return []; }
}
function writeAccounts(data) {
  fs.writeFileSync(ACCOUNTS_FILE, JSON.stringify(data, null, 2), 'utf8');
}

/* ── Helper: generate next 8-digit image ID (persistent, never resets) ── */
function nextImgId() {
  let counter = 0;
  try { counter = JSON.parse(fs.readFileSync(IMG_COUNTER_FILE, 'utf8')).imgId || 0; } catch {}
  // Also scan accounts as a safety floor (in case counter file is missing)
  try {
    const accounts = readAccounts();
    for (const acc of accounts) {
      const names = Array.isArray(acc.imgNAMEs) && acc.imgNAMEs.length
        ? acc.imgNAMEs : (acc.imgNAME ? [acc.imgNAME] : []);
      for (const name of names) {
        const base = path.parse(name).name;
        const n = parseInt(base, 10);
        if (!isNaN(n) && n > counter) counter = n;
      }
    }
  } catch {}
  counter++;
  fs.writeFileSync(IMG_COUNTER_FILE, JSON.stringify({ imgId: counter }), 'utf8');
  return String(counter).padStart(8, '0');
}

/* ── MIME magic-byte validation (prevents extension spoofing) ── */
function isAllowedImageMime(filePath) {
  try {
    const buf = Buffer.alloc(12);
    const fd  = fs.openSync(filePath, 'r');
    const bytesRead = fs.readSync(fd, buf, 0, 12, 0);
    fs.closeSync(fd);
    if (bytesRead < 3) return false;
    // JPEG: FF D8 FF
    if (buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return true;
    // PNG: 89 50 4E 47 0D 0A 1A 0A
    if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47) return true;
    // GIF: 47 49 46 38 (GIF8)
    if (buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x38) return true;
    // WebP: 52 49 46 46 ?? ?? ?? ?? 57 45 42 50
    if (bytesRead >= 12 &&
        buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x46 &&
        buf[8] === 0x57 && buf[9] === 0x45 && buf[10] === 0x42 && buf[11] === 0x50) return true;
    return false;
  } catch (e) { return false; }
}

/* ── Multer: save to temp, rename after we know the ID ── */
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, IMG_DIR),
    filename:    (req, file, cb) => cb(null, 'tmp_' + Date.now() + path.extname(file.originalname)),
  }),
  fileFilter: (req, file, cb) => {
    const ok = /\.(jpe?g|png|gif|webp)$/i.test(file.originalname);
    cb(null, ok);
  },
  limits: { fileSize: 10 * 1024 * 1024 }, // 10 MB
});

/* ── Helper: read / write maintenance.json ── */
function readMaintenance() {
  try {
    const m = JSON.parse(fs.readFileSync(MAINTENANCE_FILE, 'utf8'));
    // Migrate old { on: bool } format → new per-service format
    if ('on' in m && !('sellAccount' in m)) {
      return { sellAccount: m.on, design: m.on, spotAccount: m.on };
    }
    return m;
  }
  catch(e) { return { sellAccount: false, design: false, spotAccount: false }; }
}
function writeMaintenance(data) {
  fs.writeFileSync(MAINTENANCE_FILE, JSON.stringify(data), 'utf8');
}

/* ══════════════════════════════════════════════════════════
   API ROUTES
══════════════════════════════════════════════════════════ */

/* Protect admin.html */
app.get('/admin.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

/* GET /api/maintenance — public */
app.get('/api/maintenance', (req, res) => {
  res.json(readMaintenance());
});

/* POST /api/maintenance — auth required; body: { key: 'sellAccount'|'design'|'spotAccount' } */
app.post('/api/maintenance', requireAuth, (req, res) => {
  const { key } = req.body;
  const validKeys = ['sellAccount', 'design', 'spotAccount'];
  if (!key || !validKeys.includes(key)) {
    return res.status(400).json({ error: '無效的維護項目' });
  }
  const current = readMaintenance();
  current[key] = !current[key];
  writeMaintenance(current);
  res.json(current);
});

/* GET /api/accounts */
app.get('/api/accounts', (req, res) => {
  res.json(readAccounts());
});

/* POST /api/accounts  — add new account (with optional images) */
app.post('/api/accounts', requireAuth, upload.array('images', 10), (req, res) => {
  const accounts = readAccounts();
  const { price } = req.body;
  const files = req.files || [];

  if (!price) {
    files.forEach(f => { try { fs.unlinkSync(f.path); } catch {} });
    return res.status(400).json({ error: '價格為必填' });
  }

  // Validate actual file content (magic bytes), not just extension
  for (const f of files) {
    if (!isAllowedImageMime(f.path)) {
      files.forEach(ff => { try { fs.unlinkSync(ff.path); } catch {} });
      return res.status(400).json({ error: '不允許的圖片格式' });
    }
  }

  const newId = accounts.length ? Math.max(...accounts.map(a => a.id)) + 1 : 1;
  const imgNAMEs = [];

  for (const f of files) {
    const imgId = nextImgId();
    const ext   = path.extname(f.originalname).toLowerCase();
    const name  = imgId + ext;
    fs.renameSync(f.path, path.join(IMG_DIR, name));
    imgNAMEs.push(name);
  }

  const newAccount = {
    id:       newId,
    price:    Number(price),
    imgNAME:  imgNAMEs[0] || '',
    imgNAMEs,
    views:    0,
  };

  accounts.push(newAccount);
  writeAccounts(accounts);
  res.status(201).json(newAccount);
});

/* PUT /api/accounts/:id  — edit existing account */
app.put('/api/accounts/:id', requireAuth, upload.array('images', 10), (req, res) => {
  const accounts = readAccounts();
  const id = parseInt(req.params.id, 10);
  const idx = accounts.findIndex(a => a.id === id);
  const files = req.files || [];

  if (idx === -1) {
    files.forEach(f => { try { fs.unlinkSync(f.path); } catch {} });
    return res.status(404).json({ error: '帳號不存在' });
  }

  const { price } = req.body;
  if (!price) {
    files.forEach(f => { try { fs.unlinkSync(f.path); } catch {} });
    return res.status(400).json({ error: '價格為必填' });
  }

  // Validate actual file content (magic bytes), not just extension
  for (const f of files) {
    if (!isAllowedImageMime(f.path)) {
      files.forEach(ff => { try { fs.unlinkSync(ff.path); } catch {} });
      return res.status(400).json({ error: '不允許的圖片格式' });
    }
  }

  let imgNAMEs = Array.isArray(accounts[idx].imgNAMEs) && accounts[idx].imgNAMEs.length
    ? accounts[idx].imgNAMEs
    : (accounts[idx].imgNAME ? [accounts[idx].imgNAME] : []);

  if (files.length > 0) {
    // Delete old images
    for (const oldName of imgNAMEs) {
      const base = path.parse(oldName).name;
      if (/^\d{8}$/.test(base)) {
        const oldPath = path.join(IMG_DIR, oldName);
        try { if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath); } catch {}
      }
    }
    imgNAMEs = [];
    for (const f of files) {
      const imgId = nextImgId();
      const ext   = path.extname(f.originalname).toLowerCase();
      const name  = imgId + ext;
      fs.renameSync(f.path, path.join(IMG_DIR, name));
      imgNAMEs.push(name);
    }
  }

  accounts[idx] = { ...accounts[idx], price: Number(price), imgNAME: imgNAMEs[0] || '', imgNAMEs };
  writeAccounts(accounts);
  res.json(accounts[idx]);
});

/* DELETE /api/accounts  — delete all accounts at once */
app.delete('/api/accounts', requireAuth, (req, res) => {
  const accounts = readAccounts();
  for (const acc of accounts) {
    const names = Array.isArray(acc.imgNAMEs) && acc.imgNAMEs.length
      ? acc.imgNAMEs : (acc.imgNAME ? [acc.imgNAME] : []);
    for (const name of names) {
      const base = path.parse(name).name;
      if (/^\d{8}$/.test(base)) {
        try { if (fs.existsSync(path.join(IMG_DIR, name))) fs.unlinkSync(path.join(IMG_DIR, name)); } catch {}
      }
    }
  }
  writeAccounts([]);
  res.json({ ok: true, deleted: accounts.length });
});

/* DELETE /api/accounts/:id */
app.delete('/api/accounts/:id', requireAuth, (req, res) => {
  const accounts = readAccounts();
  const id  = parseInt(req.params.id, 10);
  const idx = accounts.findIndex(a => a.id === id);

  if (idx === -1) return res.status(404).json({ error: '帳號不存在' });

  const names = Array.isArray(accounts[idx].imgNAMEs) && accounts[idx].imgNAMEs.length
    ? accounts[idx].imgNAMEs : (accounts[idx].imgNAME ? [accounts[idx].imgNAME] : []);
  for (const name of names) {
    const base = path.parse(name).name;
    if (/^\d{8}$/.test(base)) {
      try { if (fs.existsSync(path.join(IMG_DIR, name))) fs.unlinkSync(path.join(IMG_DIR, name)); } catch {}
    }
  }

  accounts.splice(idx, 1);
  writeAccounts(accounts);
  res.json({ ok: true });
});

/* POST /api/accounts/:id/view — public, increment view counter */
app.post('/api/accounts/:id/view', (req, res) => {
  const accounts = readAccounts();
  const id  = parseInt(req.params.id, 10);
  const idx = accounts.findIndex(a => a.id === id);
  if (idx === -1) return res.status(404).json({ error: '帳號不存在' });
  accounts[idx].views = (accounts[idx].views || 0) + 1;
  writeAccounts(accounts);
  res.json({ views: accounts[idx].views });
});

/* ── Serve acc_img directory (long cache: images are content-addressed by ID) ── */
app.use('/acc_img', express.static(IMG_DIR, {
  maxAge: '1y',
  immutable: true,
}));

/* ══════════════════════════════════════════════════════════
   SUBMISSIONS API  (收帳號 / 製圖訂單)
══════════════════════════════════════════════════════════ */

function readSubmissions() {
  try { return JSON.parse(fs.readFileSync(SUBMISSIONS_FILE, 'utf8')); }
  catch(e) { return []; }
}
function writeSubmissions(data) {
  fs.writeFileSync(SUBMISSIONS_FILE, JSON.stringify(data, null, 2), 'utf8');
}


/* POST /api/submissions  — public, customer submits */
app.post('/api/submissions', upload.single('bindImg'), (req, res) => {
  const { type, gameAccount, gamePassword, bindType, contact, note } = req.body;
  if (!type || !contact) return res.status(400).json({ error: '缺少必填欄位' });

  // Input length limits to prevent oversized payloads
  const LIMITS = { type: 20, gameAccount: 100, gamePassword: 100, bindType: 30, contact: 200, note: 1000 };
  if (String(type).length     > LIMITS.type)        return res.status(400).json({ error: '欄位超過長度限制' });
  if (String(contact).length  > LIMITS.contact)     return res.status(400).json({ error: '欄位超過長度限制' });
  if (note   && String(note).length  > LIMITS.note) return res.status(400).json({ error: '備註超過 1000 字' });

  if (type === 'design' && (!gameAccount || !gamePassword)) {
    return res.status(400).json({ error: '製圖服務需填寫遊戲帳號與密碼' });
  }
  if (type === 'design' && !bindType) {
    return res.status(400).json({ error: '請選擇綁定方式' });
  }
  if (gameAccount && String(gameAccount).length > LIMITS.gameAccount) return res.status(400).json({ error: '欄位超過長度限制' });
  if (gamePassword && String(gamePassword).length > LIMITS.gamePassword) return res.status(400).json({ error: '欄位超過長度限制' });

  const subs = readSubmissions();
  const newId = subs.length ? Math.max(...subs.map(s => s.id)) + 1 : 1;
  const orderNo = 'DS' + String(newId).padStart(6, '0');
  const entry = {
    id:           newId,
    orderNo,
    type:         String(type).slice(0, LIMITS.type),
    gameAccount:  String(gameAccount || '').slice(0, LIMITS.gameAccount),
    gamePassword: String(gamePassword || '').slice(0, LIMITS.gamePassword),
    bindType:     String(bindType || '').slice(0, LIMITS.bindType),
    contact:      String(contact).slice(0, LIMITS.contact),
    note:         String(note || '').slice(0, LIMITS.note),
    bindImg:      req.file ? req.file.filename : null,
    createdAt:    new Date().toISOString(),
    done:         false,
  };
  subs.push(entry);
  writeSubmissions(subs);
  res.status(201).json({ ok: true, id: newId, orderNo });
});

/* GET /api/submissions  — auth required */
app.get('/api/submissions', requireAuth, (req, res) => {
  res.json(readSubmissions());
});

/* PATCH /api/submissions/:id  — toggle done, auth required */
app.patch('/api/submissions/:id', requireAuth, (req, res) => {
  const subs = readSubmissions();
  const id  = parseInt(req.params.id, 10);
  const idx = subs.findIndex(s => s.id === id);
  if (idx === -1) return res.status(404).json({ error: '訂單不存在' });
  subs[idx].done = !subs[idx].done;
  writeSubmissions(subs);
  res.json(subs[idx]);
});

/* DELETE /api/submissions/:id  — auth required */
app.delete('/api/submissions/:id', requireAuth, (req, res) => {
  const subs = readSubmissions();
  const id  = parseInt(req.params.id, 10);
  const idx = subs.findIndex(s => s.id === id);
  if (idx === -1) return res.status(404).json({ error: '訂單不存在' });
  subs.splice(idx, 1);
  writeSubmissions(subs);
  res.json({ ok: true });
});

/* ══════════════════════════════════════════════════════════
   ANALYTICS API
══════════════════════════════════════════════════════════ */

function readAnalytics() {
  try { return JSON.parse(fs.readFileSync(ANALYTICS_FILE, 'utf8')); }
  catch(e) { return []; }
}
function writeAnalytics(data) {
  fs.writeFileSync(ANALYTICS_FILE, JSON.stringify(data), 'utf8');
}

/* POST /api/analytics/event  — public; body: { type, extra? } */
app.post('/api/analytics/event', (req, res) => {
  const VALID_TYPES = ['account_view', 'design_click', 'sell_click', 'contact_click'];
  const { type, extra } = req.body;
  if (!type || !VALID_TYPES.includes(type)) return res.status(400).json({ error: 'invalid type' });

  const events = readAnalytics();
  events.push({
    type,
    extra: extra && typeof extra === 'object' ? extra : {},
    ts: new Date().toISOString(),
  });
  // Prune oldest events if over limit
  if (events.length > ANALYTICS_MAX) events.splice(0, events.length - ANALYTICS_MAX);
  writeAnalytics(events);
  res.json({ ok: true });
});

/* GET /api/analytics  — auth required */
app.get('/api/analytics', requireAuth, (req, res) => {
  res.json(readAnalytics());
});

/* ══════════════════════════════════════════════════════════
   BUG REPORTS API
══════════════════════════════════════════════════════════ */

function readBugReports() {
  try { return JSON.parse(fs.readFileSync(BUG_REPORTS_FILE, 'utf8')); }
  catch(e) { return []; }
}
function writeBugReports(data) {
  fs.writeFileSync(BUG_REPORTS_FILE, JSON.stringify(data, null, 2), 'utf8');
}

/* POST /api/bug-reports  — public */
app.post('/api/bug-reports', (req, res) => {
  const { description, contact, page } = req.body;
  if (!description) return res.status(400).json({ error: '請填寫問題描述' });

  const LIMITS = { description: 2000, contact: 200, page: 100 };
  if (String(description).length > LIMITS.description) return res.status(400).json({ error: '描述超過長度限制' });
  if (contact && String(contact).length > LIMITS.contact) return res.status(400).json({ error: '聯繫方式超過長度限制' });
  if (page    && String(page).length    > LIMITS.page)    return res.status(400).json({ error: '頁面欄位超過長度限制' });

  const reports = readBugReports();
  const newId = reports.length ? Math.max(...reports.map(r => r.id)) + 1 : 1;
  const entry = {
    id:          newId,
    description: String(description).slice(0, LIMITS.description),
    contact:     String(contact || '').slice(0, LIMITS.contact),
    page:        String(page    || '').slice(0, LIMITS.page),
    createdAt:   new Date().toISOString(),
    resolved:    false,
  };
  reports.push(entry);
  writeBugReports(reports);
  res.status(201).json({ ok: true, id: newId });
});

/* GET /api/bug-reports  — auth required */
app.get('/api/bug-reports', requireAuth, (req, res) => {
  res.json(readBugReports());
});

/* PATCH /api/bug-reports/:id  — toggle resolved, auth required */
app.patch('/api/bug-reports/:id', requireAuth, (req, res) => {
  const reports = readBugReports();
  const id  = parseInt(req.params.id, 10);
  const idx = reports.findIndex(r => r.id === id);
  if (idx === -1) return res.status(404).json({ error: '回報不存在' });
  reports[idx].resolved = !reports[idx].resolved;
  writeBugReports(reports);
  res.json(reports[idx]);
});

/* DELETE /api/bug-reports/:id  — auth required */
app.delete('/api/bug-reports/:id', requireAuth, (req, res) => {
  const reports = readBugReports();
  const id  = parseInt(req.params.id, 10);
  const idx = reports.findIndex(r => r.id === id);
  if (idx === -1) return res.status(404).json({ error: '回報不存在' });
  reports.splice(idx, 1);
  writeBugReports(reports);
  res.json({ ok: true });
});

app.listen(PORT, () => {
  console.log(`伺服器啟動於 http://localhost:${PORT}`);
  console.log(`後台管理頁面: http://localhost:${PORT}/admin.html`);
});
