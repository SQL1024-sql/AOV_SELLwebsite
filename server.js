const express     = require('express');
const compression = require('compression');
const multer      = require('multer');
const path        = require('path');
const fs          = require('fs');
const crypto      = require('crypto');

const app  = express();
app.disable('x-powered-by');
const PORT = process.env.PORT || 3000;
const DATA_DIR      = process.env.DATA_DIR || __dirname;
const ACCOUNTS_FILE    = path.join(DATA_DIR, 'accounts.json');
const SUBMISSIONS_FILE = path.join(DATA_DIR, 'submissions.json');
const MAINTENANCE_FILE = path.join(DATA_DIR, 'maintenance.json');
const IMG_COUNTER_FILE = path.join(DATA_DIR, 'imgCounter.json');
const BUG_REPORTS_FILE = path.join(DATA_DIR, 'bug_reports.json');
const ANALYTICS_FILE   = path.join(DATA_DIR, 'analytics.json');
const SETTINGS_FILE    = path.join(DATA_DIR, 'settings.json');
const ANALYTICS_MAX    = 20000;
const IMG_DIR          = path.join(DATA_DIR, 'acc_img');

/* ── Default site settings ── */
const DEFAULT_SETTINGS = {
  discountEnabled: true,
  discountPerPage: 3,
  discountMinPct: 10,
  discountMaxPct: 30,
  categories: [
    { label: '小資族', min: 0, max: 500, color: '#4ade80', emoji: '🌱' },
    { label: '進階玩家', min: 501, max: 1500, color: '#63B3ED', emoji: '⚔️' },
    { label: '收藏家', min: 1501, max: 3000, color: '#B47FFF', emoji: '👑' },
    { label: '土豪專區', min: 3001, max: 9999999, color: '#FFD700', emoji: '💎' },
  ],
  messengerLink: 'https://m.me/hsieh1010',
  instagramLink: '',
  viewerBase: 20,
  viewerRange: 15,
  totalViewsMultiplier: 3.2,
};

function readSettings() {
  try {
    const s = JSON.parse(fs.readFileSync(SETTINGS_FILE, 'utf8'));
    return { ...DEFAULT_SETTINGS, ...s };
  } catch { return { ...DEFAULT_SETTINGS }; }
}
function writeSettings(data) {
  fs.writeFileSync(SETTINGS_FILE, JSON.stringify(data, null, 2), 'utf8');
}

/* ── Password encryption for submissions ──
   Key precedence: ENCRYPTION_KEY env var → persisted file → newly-generated (then persisted).
   Persisting prevents previously-encrypted submissions from becoming undecryptable after restart. */
const ENC_KEY_FILE = path.join(DATA_DIR, '.encryption_key');
function loadOrCreateEncKey() {
  if (process.env.ENCRYPTION_KEY) return process.env.ENCRYPTION_KEY;
  try {
    const k = fs.readFileSync(ENC_KEY_FILE, 'utf8').trim();
    if (k && /^[0-9a-fA-F]{64}$/.test(k)) return k;
  } catch {}
  const k = crypto.randomBytes(32).toString('hex');
  try { fs.writeFileSync(ENC_KEY_FILE, k, { mode: 0o600 }); } catch (e) {
    console.warn('⚠️  無法寫入加密金鑰檔案，重啟後將無法解密現有提交：', e.message);
  }
  return k;
}
const ENCRYPTION_KEY = loadOrCreateEncKey();
const ENC_KEY_BUF = Buffer.from(ENCRYPTION_KEY.slice(0, 64).padEnd(64, '0'), 'hex'); // 32 bytes

/* ── Admin session secret (for persistent "remember this device" cookie) ── */
const SESSION_SECRET_FILE = path.join(DATA_DIR, '.session_secret');
function loadOrCreateSessionSecret() {
  if (process.env.SESSION_SECRET) return process.env.SESSION_SECRET;
  try {
    const k = fs.readFileSync(SESSION_SECRET_FILE, 'utf8').trim();
    if (k && k.length >= 32) return k;
  } catch {}
  const k = crypto.randomBytes(32).toString('hex');
  try { fs.writeFileSync(SESSION_SECRET_FILE, k, { mode: 0o600 }); } catch (e) {
    console.warn('⚠️  無法寫入 session secret 檔案，重啟後將需重新登入：', e.message);
  }
  return k;
}
const SESSION_SECRET = loadOrCreateSessionSecret();
const SESSION_MAX_AGE_MS = 30 * 24 * 60 * 60 * 1000; // 30 days
const SESSION_COOKIE_NAME = 'admin_session';

function signSessionExp(exp) {
  return crypto.createHmac('sha256', SESSION_SECRET).update(String(exp)).digest('hex');
}
function makeSessionToken() {
  const exp = Date.now() + SESSION_MAX_AGE_MS;
  return `${exp}.${signSessionExp(exp)}`;
}
function verifySessionToken(token) {
  if (!token || typeof token !== 'string') return false;
  const dot = token.indexOf('.');
  if (dot === -1) return false;
  const expStr = token.slice(0, dot);
  const sig    = token.slice(dot + 1);
  const exp = Number(expStr);
  if (!Number.isFinite(exp) || exp < Date.now()) return false;
  const expected = signSessionExp(exp);
  if (expected.length !== sig.length) return false;
  try {
    return crypto.timingSafeEqual(Buffer.from(expected, 'hex'), Buffer.from(sig, 'hex'));
  } catch { return false; }
}
function parseCookies(header) {
  const out = {};
  if (!header) return out;
  for (const part of header.split(';')) {
    const i = part.indexOf('=');
    if (i === -1) continue;
    const k = part.slice(0, i).trim();
    const v = part.slice(i + 1).trim();
    if (k) {
      try { out[k] = decodeURIComponent(v); } catch { out[k] = v; }
    }
  }
  return out;
}
function setSessionCookie(req, res) {
  const token = makeSessionToken();
  const isHttps = req.headers['x-forwarded-proto'] === 'https' || req.secure;
  const parts = [
    `${SESSION_COOKIE_NAME}=${token}`,
    'HttpOnly',
    'SameSite=Lax',
    'Path=/',
    `Max-Age=${Math.floor(SESSION_MAX_AGE_MS / 1000)}`,
  ];
  if (isHttps) parts.push('Secure');
  res.append('Set-Cookie', parts.join('; '));
}

function encryptText(text) {
  if (!text) return '';
  const iv = crypto.randomBytes(16);
  const cipher = crypto.createCipheriv('aes-256-cbc', ENC_KEY_BUF, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  return iv.toString('hex') + ':' + encrypted;
}

function decryptText(data) {
  if (!data || !data.includes(':')) return data || '';
  try {
    const [ivHex, encrypted] = data.split(':');
    const iv = Buffer.from(ivHex, 'hex');
    const decipher = crypto.createDecipheriv('aes-256-cbc', ENC_KEY_BUF, iv);
    let decrypted = decipher.update(encrypted, 'hex', 'utf8');
    decrypted += decipher.final('utf8');
    return decrypted;
  } catch { return '[解密失敗]'; }
}

/* ── Security Headers (with CSP) ── */
app.use((req, res, next) => {
  res.set('X-Content-Type-Options', 'nosniff');
  res.set('X-Frame-Options', 'DENY');
  res.set('X-XSS-Protection', '1; mode=block');
  res.set('Referrer-Policy', 'strict-origin-when-cross-origin');
  res.set('Strict-Transport-Security', 'max-age=31536000; includeSubDomains');
  res.set('Permissions-Policy', 'camera=(), microphone=(), geolocation=()');
  res.set('Content-Security-Policy', "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src 'self' https://fonts.gstatic.com; img-src 'self' data: blob: https://placehold.co https://image2url.com https://picsum.photos; connect-src 'self'");
  next();
});

/* ── Simple request logging ── */
app.use((req, res, next) => {
  const start = Date.now();
  res.on('finish', () => {
    const ms = Date.now() - start;
    console.log(`${new Date().toISOString()} ${req.method} ${req.path} ${res.statusCode} ${ms}ms`);
  });
  next();
});

/* ── Admin Basic Auth with brute-force protection ── */
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS;

if (!ADMIN_PASS) {
  console.warn('⚠️  警告: ADMIN_PASS 環境變數未設定！請設定安全密碼。預設密碼已停用。');
}

const authFailures = new Map();
const AUTH_MAX_FAILURES = 10;
const AUTH_LOCKOUT_MS   = 15 * 60 * 1000;

function requireAuth(req, res, next) {
  if (!ADMIN_PASS) {
    return res.status(503).send('管理員密碼未設定，請聯繫系統管理員設定 ADMIN_PASS 環境變數');
  }

  // Persistent session: if device has a valid signed cookie, skip Basic Auth
  const cookies = parseCookies(req.headers['cookie']);
  if (cookies[SESSION_COOKIE_NAME] && verifySessionToken(cookies[SESSION_COOKIE_NAME])) {
    return next();
  }

  const ip  = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip;
  const now = Date.now();

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
      // Timing-safe comparison
      const userBuf  = Buffer.from(user);
      const passBuf  = Buffer.from(pass);
      const adminBuf = Buffer.from(ADMIN_USER);
      const adminPBuf = Buffer.from(ADMIN_PASS);
      const userOk = userBuf.length === adminBuf.length && crypto.timingSafeEqual(userBuf, adminBuf);
      const passOk = passBuf.length === adminPBuf.length && crypto.timingSafeEqual(passBuf, adminPBuf);
      if (userOk && passOk) {
        authFailures.delete(ip);
        // Issue a long-lived signed cookie so this device can skip Basic Auth in future visits
        setSessionCookie(req, res);
        return next();
      }
    }
  }

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
app.use(express.json({ limit: '50kb' }));

/* ── Rate limiting for public endpoints ── */
const rateLimits = new Map(); // ip -> { count, resetAt }
const RATE_LIMIT_MAX = 60;    // max requests per window
const RATE_LIMIT_WINDOW = 60 * 1000; // 1 minute

function rateLimit(req, res, next) {
  const ip  = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip;
  const now = Date.now();
  let rec = rateLimits.get(ip);
  if (!rec || rec.resetAt <= now) {
    rec = { count: 0, resetAt: now + RATE_LIMIT_WINDOW };
    rateLimits.set(ip, rec);
  }
  rec.count++;
  if (rec.count > RATE_LIMIT_MAX) {
    return res.status(429).json({ error: '請求過於頻繁，請稍後再試' });
  }
  next();
}

// Clean up rate limit map periodically
setInterval(() => {
  const now = Date.now();
  for (const [ip, rec] of rateLimits) {
    if (rec.resetAt <= now) rateLimits.delete(ip);
  }
}, 5 * 60 * 1000);

/* Block direct static access to sensitive files and auth-protected pages */
app.use((req, res, next) => {
  // Block sensitive files (normalize path to prevent double-slash or trailing-slash bypass)
  const blocked = ['/accounts.json', '/submissions.json', '/maintenance.json',
    '/imgCounter.json', '/bug_reports.json', '/analytics.json',
    '/addACC.py', '/daily_upload.py', '/package.json', '/package-lock.json',
    '/.gitignore', '/.wranglerignore', '/.env', '/server.js'];
  const cleanPath = decodeURIComponent(req.path).replace(/\/+/g, '/').replace(/\/+$/, '') || '/';
  if (blocked.includes(cleanPath) || cleanPath.startsWith('/.')) {
    return res.status(403).send('Forbidden');
  }
  // Protect admin and daily pages (normalize to prevent trailing-slash bypass)
  const normalizedPath = req.path.replace(/\/+$/, '') || '/';
  if (normalizedPath === '/admin.html' || normalizedPath.endsWith('/admin.html') || normalizedPath === '/daily.html') {
    return requireAuth(req, res, next);
  }
  next();
});

/* Serve images with long cache */
app.use('/acc_img', express.static(IMG_DIR, { maxAge: '1y', immutable: true }));

/* Serve specific allowed root files (before public fallback) */
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'index.html'));
});
const ALLOWED_ROOT_FILES = ['index.html', 'admin.html', 'daily.html'];
app.get('/:file', (req, res, next) => {
  if (ALLOWED_ROOT_FILES.includes(req.params.file)) {
    return res.sendFile(path.join(__dirname, req.params.file));
  }
  next();
});

/* Public directory for other static assets (CSS, JS, images) */
app.use(express.static(path.join(__dirname, 'public')));

/* ── Helper: read / write with simple file lock ── */
const fileLocks = new Map();

async function withFileLock(filePath, fn) {
  while (fileLocks.get(filePath)) {
    await new Promise(r => setTimeout(r, 10));
  }
  fileLocks.set(filePath, true);
  try {
    return fn();
  } finally {
    fileLocks.delete(filePath);
  }
}

function readJSON(filePath) {
  try { return JSON.parse(fs.readFileSync(filePath, 'utf8')); }
  catch { return []; }
}

function writeJSON(filePath, data, pretty = true) {
  fs.writeFileSync(filePath, JSON.stringify(data, pretty ? null : undefined, pretty ? 2 : undefined), 'utf8');
}

function readAccounts() { return readJSON(ACCOUNTS_FILE); }
function writeAccounts(data) { writeJSON(ACCOUNTS_FILE, data); }

/* ── Helper: generate next 8-digit image ID ── */
function nextImgId() {
  let counter = 0;
  try { counter = JSON.parse(fs.readFileSync(IMG_COUNTER_FILE, 'utf8')).imgId || 0; } catch {}
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

/* ── MIME magic-byte validation ── */
function isAllowedImageMime(filePath) {
  try {
    const buf = Buffer.alloc(12);
    const fd  = fs.openSync(filePath, 'r');
    const bytesRead = fs.readSync(fd, buf, 0, 12, 0);
    fs.closeSync(fd);
    if (bytesRead < 3) return false;
    if (buf[0] === 0xFF && buf[1] === 0xD8 && buf[2] === 0xFF) return true;
    if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4E && buf[3] === 0x47) return true;
    if (buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x38) return true;
    if (bytesRead >= 12 &&
        buf[0] === 0x52 && buf[1] === 0x49 && buf[2] === 0x46 && buf[3] === 0x46 &&
        buf[8] === 0x57 && buf[9] === 0x45 && buf[10] === 0x42 && buf[11] === 0x50) return true;
    return false;
  } catch { return false; }
}

/* ── Multer ── */
const upload = multer({
  storage: multer.diskStorage({
    destination: (req, file, cb) => cb(null, IMG_DIR),
    filename:    (req, file, cb) => cb(null, 'tmp_' + Date.now() + path.extname(file.originalname)),
  }),
  fileFilter: (req, file, cb) => {
    const ok = /\.(jpe?g|png|gif|webp)$/i.test(file.originalname);
    cb(null, ok);
  },
  limits: { fileSize: 10 * 1024 * 1024 },
});

/* ── Helper: read / write maintenance.json ── */
function readMaintenance() {
  try {
    const m = JSON.parse(fs.readFileSync(MAINTENANCE_FILE, 'utf8'));
    if ('on' in m && !('sellAccount' in m)) {
      return { sellAccount: m.on, design: m.on, spotAccount: m.on };
    }
    return m;
  }
  catch { return { sellAccount: false, design: false, spotAccount: false }; }
}
function writeMaintenance(data) {
  fs.writeFileSync(MAINTENANCE_FILE, JSON.stringify(data), 'utf8');
}

/* ══════════════════════════════════════════════════════════
   API ROUTES
══════════════════════════════════════════════════════════ */

/* Health check endpoint */
app.get('/api/health', (req, res) => {
  res.json({ status: 'ok', uptime: process.uptime() });
});

/* Protect admin.html */
app.get('/admin.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

/* GET /api/maintenance — public */
app.get('/api/maintenance', (req, res) => {
  res.json(readMaintenance());
});

/* POST /api/maintenance — auth required */
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

/* POST /api/accounts — add new account (with optional images) */
app.post('/api/accounts', requireAuth, upload.array('images', 200), (req, res) => {
  return withFileLock(ACCOUNTS_FILE, () => {
    const accounts = readAccounts();
    const { price, game } = req.body;
    const files = req.files || [];

    const priceNum = Number(price);
    if (!price || !Number.isFinite(priceNum) || priceNum <= 0 || priceNum > 9999999 || !Number.isInteger(priceNum)) {
      files.forEach(f => { try { fs.unlinkSync(f.path); } catch {} });
      return res.status(400).json({ error: '價格必須為正整數（最大 9999999）' });
    }

    const VALID_GAMES = ['AOV','PUBG','COD','BrawlStars','SpeedDrift','FreeFire'];
    const gameName = VALID_GAMES.includes(game) ? game : 'AOV';

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
      game:     gameName,
      imgNAME:  imgNAMEs[0] || '',
      imgNAMEs,
      views:    0,
    };

    accounts.push(newAccount);
    writeAccounts(accounts);
    res.status(201).json(newAccount);
  });
});

/* PUT /api/accounts/:id — edit existing account */
app.put('/api/accounts/:id', requireAuth, upload.array('images', 200), (req, res) => {
  return withFileLock(ACCOUNTS_FILE, () => {
    const accounts = readAccounts();
    const id = parseInt(req.params.id, 10);
    const idx = accounts.findIndex(a => a.id === id);
    const files = req.files || [];

    if (idx === -1) {
      files.forEach(f => { try { fs.unlinkSync(f.path); } catch {} });
      return res.status(404).json({ error: '帳號不存在' });
    }

    const { price, game } = req.body;
    const priceNum = Number(price);
    if (!price || !Number.isFinite(priceNum) || priceNum <= 0 || priceNum > 9999999 || !Number.isInteger(priceNum)) {
      files.forEach(f => { try { fs.unlinkSync(f.path); } catch {} });
      return res.status(400).json({ error: '價格必須為正整數（最大 9999999）' });
    }

    const VALID_GAMES = ['AOV','PUBG','COD','BrawlStars','SpeedDrift','FreeFire'];
    const gameName = VALID_GAMES.includes(game) ? game : (accounts[idx].game || 'AOV');

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

    accounts[idx] = { ...accounts[idx], price: Number(price), game: gameName, imgNAME: imgNAMEs[0] || '', imgNAMEs };
    writeAccounts(accounts);
    res.json(accounts[idx]);
  });
});

/* PATCH /api/accounts/batch — batch update prices */
app.patch('/api/accounts/batch', requireAuth, (req, res) => {
  return withFileLock(ACCOUNTS_FILE, () => {
    const { updates } = req.body;
    if (!Array.isArray(updates) || updates.length === 0) {
      return res.status(400).json({ error: '請提供要更新的帳號資料' });
    }
    const accounts = readAccounts();
    const results = [];
    for (const { id, price } of updates) {
      const idx = accounts.findIndex(a => a.id === id);
      if (idx === -1) continue;
      const pNum = Number(price);
      if (!price || !Number.isFinite(pNum) || pNum <= 0 || pNum > 9999999 || !Number.isInteger(pNum)) continue;
      accounts[idx].price = Number(price);
      results.push(accounts[idx]);
    }
    writeAccounts(accounts);
    res.json({ ok: true, updated: results.length, accounts: results });
  });
});

/* DELETE /api/accounts — delete all accounts at once */
app.delete('/api/accounts', requireAuth, (req, res) => {
  return withFileLock(ACCOUNTS_FILE, () => {
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
});

/* DELETE /api/accounts/:id */
app.delete('/api/accounts/:id', requireAuth, (req, res) => {
  return withFileLock(ACCOUNTS_FILE, () => {
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
});

/* POST /api/accounts/:id/view — public, increment view counter (per-IP per-account dedup) */
const viewDedup = new Map(); // key: "ip:accountId" -> timestamp
const VIEW_DEDUP_WINDOW = 5 * 60 * 1000; // 5 minutes

app.post('/api/accounts/:id/view', rateLimit, (req, res) => {
  const ip = req.headers['x-forwarded-for']?.split(',')[0].trim() || req.ip;
  const accountId = req.params.id;
  const dedupKey = `${ip}:${accountId}`;
  const now = Date.now();

  if (viewDedup.has(dedupKey) && viewDedup.get(dedupKey) > now - VIEW_DEDUP_WINDOW) {
    // Already counted recently — return current views without incrementing
    const accounts = readAccounts();
    const id = parseInt(accountId, 10);
    const acc = accounts.find(a => a.id === id);
    return res.json({ views: acc ? (acc.views || 0) : 0 });
  }
  viewDedup.set(dedupKey, now);

  return withFileLock(ACCOUNTS_FILE, () => {
    const accounts = readAccounts();
    const id  = parseInt(accountId, 10);
    const idx = accounts.findIndex(a => a.id === id);
    if (idx === -1) return res.status(404).json({ error: '帳號不存在' });
    accounts[idx].views = (accounts[idx].views || 0) + 1;
    writeAccounts(accounts);
    res.json({ views: accounts[idx].views });
  });
});

// Clean up view dedup map periodically
setInterval(() => {
  const cutoff = Date.now() - VIEW_DEDUP_WINDOW;
  for (const [key, ts] of viewDedup) {
    if (ts < cutoff) viewDedup.delete(key);
  }
}, 10 * 60 * 1000);

/* ══════════════════════════════════════════════════════════
   SUBMISSIONS API
══════════════════════════════════════════════════════════ */

function readSubmissions() { return readJSON(SUBMISSIONS_FILE); }
function writeSubmissions(data) { writeJSON(SUBMISSIONS_FILE, data); }

/* POST /api/submissions — public, customer submits */
app.post('/api/submissions', rateLimit, upload.single('bindImg'), (req, res) => {
  const { type, gameAccount, gamePassword, bindType, contact, note } = req.body;
  if (!type || !contact) return res.status(400).json({ error: '缺少必填欄位' });

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

  return withFileLock(SUBMISSIONS_FILE, () => {
    const subs = readSubmissions();
    const newId = subs.length ? Math.max(...subs.map(s => s.id)) + 1 : 1;
    const orderNo = 'DS' + String(newId).padStart(6, '0');
    const entry = {
      id:           newId,
      orderNo,
      type:         String(type).slice(0, LIMITS.type),
      gameAccount:  encryptText(String(gameAccount || '').slice(0, LIMITS.gameAccount)),
      gamePassword: encryptText(String(gamePassword || '').slice(0, LIMITS.gamePassword)),
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
});

/* GET /api/submissions — auth required, returns decrypted data */
app.get('/api/submissions', requireAuth, (req, res) => {
  const subs = readSubmissions();
  const decrypted = subs.map(s => ({
    ...s,
    gameAccount:  decryptText(s.gameAccount),
    gamePassword: decryptText(s.gamePassword),
  }));
  res.json(decrypted);
});

/* PATCH /api/submissions/:id — toggle done, auth required */
app.patch('/api/submissions/:id', requireAuth, (req, res) => {
  return withFileLock(SUBMISSIONS_FILE, () => {
    const subs = readSubmissions();
    const id  = parseInt(req.params.id, 10);
    const idx = subs.findIndex(s => s.id === id);
    if (idx === -1) return res.status(404).json({ error: '訂單不存在' });
    subs[idx].done = !subs[idx].done;
    writeSubmissions(subs);
    const result = { ...subs[idx], gameAccount: decryptText(subs[idx].gameAccount), gamePassword: decryptText(subs[idx].gamePassword) };
    res.json(result);
  });
});

/* DELETE /api/submissions/:id — auth required */
app.delete('/api/submissions/:id', requireAuth, (req, res) => {
  return withFileLock(SUBMISSIONS_FILE, () => {
    const subs = readSubmissions();
    const id  = parseInt(req.params.id, 10);
    const idx = subs.findIndex(s => s.id === id);
    if (idx === -1) return res.status(404).json({ error: '訂單不存在' });
    subs.splice(idx, 1);
    writeSubmissions(subs);
    res.json({ ok: true });
  });
});

/* ══════════════════════════════════════════════════════════
   ANALYTICS API
══════════════════════════════════════════════════════════ */

function readAnalytics() { return readJSON(ANALYTICS_FILE); }
function writeAnalytics(data) { writeJSON(ANALYTICS_FILE, data, false); }

/* POST /api/analytics/event — public */
app.post('/api/analytics/event', rateLimit, (req, res) => {
  const VALID_TYPES = ['account_view', 'design_click', 'sell_click', 'contact_click'];
  const { type, extra } = req.body;
  if (!type || !VALID_TYPES.includes(type)) return res.status(400).json({ error: 'invalid type' });

  return withFileLock(ANALYTICS_FILE, () => {
    const events = readAnalytics();
    events.push({
      type,
      extra: extra && typeof extra === 'object' ? extra : {},
      ts: new Date().toISOString(),
    });
    if (events.length > ANALYTICS_MAX) events.splice(0, events.length - ANALYTICS_MAX);
    writeAnalytics(events);
    res.json({ ok: true });
  });
});

/* GET /api/analytics — auth required */
app.get('/api/analytics', requireAuth, (req, res) => {
  res.json(readAnalytics());
});

/* ══════════════════════════════════════════════════════════
   BUG REPORTS API
══════════════════════════════════════════════════════════ */

function readBugReports() { return readJSON(BUG_REPORTS_FILE); }
function writeBugReports(data) { writeJSON(BUG_REPORTS_FILE, data); }

/* POST /api/bug-reports — public */
app.post('/api/bug-reports', rateLimit, (req, res) => {
  const { description, contact, page } = req.body;
  if (!description) return res.status(400).json({ error: '請填寫問題描述' });

  const LIMITS = { description: 2000, contact: 200, page: 100 };
  if (String(description).length > LIMITS.description) return res.status(400).json({ error: '描述超過長度限制' });
  if (contact && String(contact).length > LIMITS.contact) return res.status(400).json({ error: '聯繫方式超過長度限制' });
  if (page    && String(page).length    > LIMITS.page)    return res.status(400).json({ error: '頁面欄位超過長度限制' });

  return withFileLock(BUG_REPORTS_FILE, () => {
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
});

/* GET /api/bug-reports — auth required */
app.get('/api/bug-reports', requireAuth, (req, res) => {
  res.json(readBugReports());
});

/* PATCH /api/bug-reports/:id — toggle resolved, auth required */
app.patch('/api/bug-reports/:id', requireAuth, (req, res) => {
  return withFileLock(BUG_REPORTS_FILE, () => {
    const reports = readBugReports();
    const id  = parseInt(req.params.id, 10);
    const idx = reports.findIndex(r => r.id === id);
    if (idx === -1) return res.status(404).json({ error: '回報不存在' });
    reports[idx].resolved = !reports[idx].resolved;
    writeBugReports(reports);
    res.json(reports[idx]);
  });
});

/* DELETE /api/bug-reports/:id — auth required */
app.delete('/api/bug-reports/:id', requireAuth, (req, res) => {
  return withFileLock(BUG_REPORTS_FILE, () => {
    const reports = readBugReports();
    const id  = parseInt(req.params.id, 10);
    const idx = reports.findIndex(r => r.id === id);
    if (idx === -1) return res.status(404).json({ error: '回報不存在' });
    reports.splice(idx, 1);
    writeBugReports(reports);
    res.json({ ok: true });
  });
});

/* ══════════════════════════════════════════════════════════
   SETTINGS API
══════════════════════════════════════════════════════════ */

/* GET /api/settings — public (frontend needs discount/category/messenger config) */
app.get('/api/settings', (req, res) => {
  res.json(readSettings());
});

/* POST /api/settings — auth required */
app.post('/api/settings', requireAuth, (req, res) => {
  const current = readSettings();
  const updates = req.body;
  // Only allow known keys
  const allowed = ['discountEnabled','discountPerPage','discountMinPct','discountMaxPct',
    'categories','messengerLink','instagramLink','viewerBase','viewerRange','totalViewsMultiplier'];
  for (const key of allowed) {
    if (updates[key] !== undefined) current[key] = updates[key];
  }
  writeSettings(current);
  res.json(current);
});

/* ══════════════════════════════════════════════════════════
   OCR — POST /api/ocr  (Gemini 1.5 Flash)
   Body: multipart/form-data, field "image" (single file)
   Returns: { price: <number|null> }
══════════════════════════════════════════════════════════ */
const GEMINI_API_KEY = process.env.GEMINI_API_KEY || '';


function parseOcrPrice(raw) {
  const s = String(raw).trim();
  if (s.includes('.')) {
    const [intPart, decPart] = s.split('.');
    const dec = (decPart + '0')[0]; // take first decimal digit
    return parseInt(intPart, 10) * 10000 + parseInt(dec, 10) * 1000;
  }
  return parseInt(s, 10);
}
const ocrUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 10 * 1024 * 1024 } });

app.post('/api/ocr', requireAuth, ocrUpload.single('image'), async (req, res) => {
  if (!req.file) return res.status(400).json({ error: '沒有收到圖片' });
  if (GEMINI_API_KEY === 'YOUR_KEY_HERE') return res.status(500).json({ error: '未設定 GEMINI_API_KEY' });

  try {
    const b64 = req.file.buffer.toString('base64');
    const mime = req.file.mimetype || 'image/jpeg';

    const body = {
      contents: [{
        parts: [
          { inline_data: { mime_type: mime, data: b64 } },
          { text: '這張圖片中有一個代表價格的大數字（例如 1500、5000、20000）。請用 JSON 格式回傳，只能回傳這個格式：{"price": 數字或null, "confidence": 0到100的整數}。price 是你辨識到的價格數字，confidence 是你對這個結果的信心程度（0-100）。不要回傳其他任何文字。' }
        ]
      }]
    };

    const apiRes = await fetch(
      `https://generativelanguage.googleapis.com/v1beta/models/gemini-2.0-flash:generateContent?key=${GEMINI_API_KEY}`,
      { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }
    );
    const data = await apiRes.json();
    const text = data?.candidates?.[0]?.content?.parts?.[0]?.text?.trim() || '';
    let price = null, confidence = 0;
    try {
      const jsonStr = text.replace(/```json|```/g, '').trim();
      const parsed = JSON.parse(jsonStr);
      price = parsed.price && parsed.price > 0 ? parseOcrPrice(parsed.price) : null;
      confidence = parseInt(parsed.confidence, 10) || 0;
    } catch {
      // fallback: try to extract number directly
      const num = parseInt(text.replace(/[^0-9]/g, ''), 10);
      if (!isNaN(num) && num > 0) { price = num; confidence = 50; }
    }
    res.json({ price: isNaN(price) || price <= 0 ? null : price, confidence });
  } catch (e) {
    console.error('OCR error:', e.message);
    res.status(500).json({ error: 'OCR 辨識失敗' });
  }
});

/* ── 404 handler — clean response for unknown routes ── */
app.use((req, res) => {
  res.status(404).json({ error: '找不到該頁面' });
});

/* ── Global error handler — prevent stack trace leakage ── */
app.use((err, req, res, _next) => {
  console.error(`${new Date().toISOString()} ERROR ${req.method} ${req.path}:`, err.message);
  res.status(err.status || 500).json({ error: '伺服器內部錯誤' });
});

/* ══════════════════════════════════════════════════════════
   GRACEFUL SHUTDOWN
══════════════════════════════════════════════════════════ */
const server = app.listen(PORT, () => {
  console.log(`伺服器啟動於 http://localhost:${PORT}`);
  console.log(`後台管理頁面: http://localhost:${PORT}/admin.html`);
  if (!ADMIN_PASS) console.warn('⚠️  請設定 ADMIN_PASS 環境變數以啟用管理功能');
});

function shutdown(signal) {
  console.log(`\n收到 ${signal}，正在關閉伺服器…`);
  server.close(() => {
    console.log('伺服器已關閉');
    process.exit(0);
  });
  setTimeout(() => {
    console.error('強制關閉');
    process.exit(1);
  }, 5000);
}

process.on('SIGTERM', () => shutdown('SIGTERM'));
process.on('SIGINT',  () => shutdown('SIGINT'));
