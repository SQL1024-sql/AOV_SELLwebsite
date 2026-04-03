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
const IMG_DIR          = path.join(DATA_DIR, 'acc_img');

/* ── Admin Basic Auth ── */
const ADMIN_USER = process.env.ADMIN_USER || 'admin';
const ADMIN_PASS = process.env.ADMIN_PASS || 'changeme';

function requireAuth(req, res, next) {
  const auth = req.headers['authorization'];
  if (auth && auth.startsWith('Basic ')) {
    const decoded = Buffer.from(auth.slice(6), 'base64').toString('utf8');
    const [user, pass] = decoded.split(':');
    if (user === ADMIN_USER && pass === ADMIN_PASS) return next();
  }
  res.set('WWW-Authenticate', 'Basic realm="Admin"');
  res.status(401).send('需要登入');
}

// Ensure acc_img directory exists
if (!fs.existsSync(IMG_DIR)) fs.mkdirSync(IMG_DIR, { recursive: true });

app.use(compression());
app.use(express.json());

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

/* ── Helper: generate next 8-digit image ID ── */
function nextImgId(accounts) {
  // Find highest numeric imgNAME across all accounts
  let max = 0;
  for (const acc of accounts) {
    const base = acc.imgNAME ? path.parse(acc.imgNAME).name : '';
    const n = parseInt(base, 10);
    if (!isNaN(n) && n > max) max = n;
  }
  return String(max + 1).padStart(8, '0');
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

/* ══════════════════════════════════════════════════════════
   API ROUTES
══════════════════════════════════════════════════════════ */

/* Protect admin.html */
app.get('/admin.html', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'admin.html'));
});

/* GET /api/accounts */
app.get('/api/accounts', (req, res) => {
  res.json(readAccounts());
});

/* POST /api/accounts  — add new account (with optional image) */
app.post('/api/accounts', requireAuth, upload.single('image'), (req, res) => {
  const accounts = readAccounts();
  const { price } = req.body;

  if (!price) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: '價格為必填' });
  }

  const newId = accounts.length ? Math.max(...accounts.map(a => a.id)) + 1 : 1;
  let imgNAME = '';

  if (req.file) {
    const imgId  = nextImgId(accounts);
    const ext    = path.extname(req.file.originalname).toLowerCase();
    imgNAME      = imgId + ext;
    const dest   = path.join(IMG_DIR, imgNAME);
    fs.renameSync(req.file.path, dest);
  }

  const newAccount = {
    id:      newId,
    price:   Number(price),
    imgNAME: imgNAME,
  };

  accounts.push(newAccount);
  writeAccounts(accounts);
  res.status(201).json(newAccount);
});

/* PUT /api/accounts/:id  — edit existing account */
app.put('/api/accounts/:id', requireAuth, upload.single('image'), (req, res) => {
  const accounts = readAccounts();
  const id = parseInt(req.params.id, 10);
  const idx = accounts.findIndex(a => a.id === id);

  if (idx === -1) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(404).json({ error: '帳號不存在' });
  }

  const { price } = req.body;
  if (!price) {
    if (req.file) fs.unlinkSync(req.file.path);
    return res.status(400).json({ error: '價格為必填' });
  }

  let imgNAME = accounts[idx].imgNAME;

  if (req.file) {
    // Delete old image if it was a generated one (8-digit name)
    if (imgNAME) {
      const base = path.parse(imgNAME).name;
      if (/^\d{8}$/.test(base)) {
        const oldPath = path.join(IMG_DIR, imgNAME);
        if (fs.existsSync(oldPath)) fs.unlinkSync(oldPath);
      }
    }
    const imgId = nextImgId(accounts);
    const ext   = path.extname(req.file.originalname).toLowerCase();
    imgNAME     = imgId + ext;
    fs.renameSync(req.file.path, path.join(IMG_DIR, imgNAME));
  }

  accounts[idx] = { ...accounts[idx], price: Number(price), imgNAME };
  writeAccounts(accounts);
  res.json(accounts[idx]);
});

/* DELETE /api/accounts/:id */
app.delete('/api/accounts/:id', requireAuth, (req, res) => {
  const accounts = readAccounts();
  const id  = parseInt(req.params.id, 10);
  const idx = accounts.findIndex(a => a.id === id);

  if (idx === -1) return res.status(404).json({ error: '帳號不存在' });

  const imgNAME = accounts[idx].imgNAME;
  if (imgNAME) {
    const base = path.parse(imgNAME).name;
    if (/^\d{8}$/.test(base)) {
      const imgPath = path.join(IMG_DIR, imgNAME);
      if (fs.existsSync(imgPath)) fs.unlinkSync(imgPath);
    }
  }

  accounts.splice(idx, 1);
  writeAccounts(accounts);
  res.json({ ok: true });
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
app.post('/api/submissions', (req, res) => {
  const { type, gameAccount, gamePassword, contact, note } = req.body;
  if (!type || !contact) return res.status(400).json({ error: '缺少必填欄位' });
  if (type === 'design' && (!gameAccount || !gamePassword)) {
    return res.status(400).json({ error: '製圖服務需填寫遊戲帳號與密碼' });
  }
  const subs = readSubmissions();
  const newId = subs.length ? Math.max(...subs.map(s => s.id)) + 1 : 1;
  const entry = {
    id:          newId,
    type,
    gameAccount: gameAccount || '',
    gamePassword: gamePassword || '',
    contact,
    note:        note || '',
    createdAt:   new Date().toISOString(),
    done:        false,
  };
  subs.push(entry);
  writeSubmissions(subs);
  res.status(201).json({ ok: true, id: newId });
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

app.listen(PORT, () => {
  console.log(`伺服器啟動於 http://localhost:${PORT}`);
  console.log(`後台管理頁面: http://localhost:${PORT}/admin.html`);
});
