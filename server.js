const express = require('express');
const multer = require('multer');
const path = require('path');
const { v4: uuidv4 } = require('uuid');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 3000;
const ADMIN_KEY = process.env.ADMIN_KEY || 'change-me-in-production';

const upload = multer({
  storage: multer.memoryStorage(),
  limits: { fileSize: 5 * 1024 * 1024 }
});

app.use(express.json({ limit: '5mb' }));
app.use(express.static(path.join(__dirname, 'public')));

function adminAuth(req, res, next) {
  if (req.headers['x-admin-key'] !== ADMIN_KEY) {
    return res.status(401).json({ error: '未授权' });
  }
  next();
}

app.post('/api/admin/login', (req, res) => {
  const key = req.body?.key;
  if (typeof key !== 'string' || key !== ADMIN_KEY) {
    return res.status(401).json({ error: '密钥错误' });
  }
  res.json({ ok: true });
});

const REQUIRED_FIELDS = ['clientId', 'clientSecret', 'refreshToken'];

function validateAccount(item) {
  if (!item || typeof item !== 'object') return false;
  return REQUIRED_FIELDS.every(f => typeof item[f] === 'string' && item[f].length > 0);
}

app.post('/api/admin/upload', adminAuth, upload.single('file'), (req, res) => {
  if (!req.file) return res.status(400).json({ error: '未提供文件' });

  let parsed;
  try {
    parsed = JSON.parse(req.file.buffer.toString('utf8'));
  } catch {
    return res.status(400).json({ error: 'JSON 解析失败' });
  }

  const list = Array.isArray(parsed) ? parsed : [parsed];
  const valid = list.filter(validateAccount);
  if (!valid.length) return res.status(400).json({ error: '未找到有效账号' });

  const insert = db.prepare(`
    INSERT INTO accounts (client_id, email, region, subscription, provider, raw_json)
    VALUES (?, ?, ?, ?, ?, ?)
    ON CONFLICT(client_id) DO UPDATE SET
      email = excluded.email,
      region = excluded.region,
      subscription = excluded.subscription,
      provider = excluded.provider,
      raw_json = excluded.raw_json,
      used = 0
  `);

  const tx = db.transaction(items => {
    for (const a of items) {
      insert.run(
        a.clientId,
        a.email || null,
        a.region || null,
        a.subscription || null,
        a.provider || null,
        JSON.stringify(a)
      );
    }
  });
  tx(valid);

  res.json({ inserted: valid.length, skipped: list.length - valid.length });
});

app.get('/api/admin/accounts', adminAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT id, client_id, email, region, subscription, provider, used, created_at
    FROM accounts
    ORDER BY id DESC
  `).all();
  res.json(rows);
});

app.delete('/api/admin/accounts/:id', adminAuth, (req, res) => {
  const id = Number(req.params.id);
  if (!Number.isInteger(id)) return res.status(400).json({ error: '无效 ID' });
  const result = db.prepare('DELETE FROM accounts WHERE id = ?').run(id);
  if (!result.changes) return res.status(404).json({ error: '账号不存在' });
  res.json({ ok: true });
});

app.post('/api/admin/generate-key', adminAuth, (req, res) => {
  const ids = Array.isArray(req.body?.accountIds) ? req.body.accountIds : [];
  const cleanIds = [...new Set(ids.filter(Number.isInteger))];
  if (!cleanIds.length) return res.status(400).json({ error: '请选择至少一个账号' });

  const placeholders = cleanIds.map(() => '?').join(',');
  const found = db.prepare(
    `SELECT id FROM accounts WHERE id IN (${placeholders}) AND used = 0`
  ).all(...cleanIds);

  if (found.length !== cleanIds.length) {
    return res.status(400).json({ error: '部分账号不存在或已被使用' });
  }

  const downloadKey = uuidv4();

  const tx = db.transaction(() => {
    const info = db.prepare(
      'INSERT INTO download_keys (download_key) VALUES (?)'
    ).run(downloadKey);
    const link = db.prepare(
      'INSERT INTO download_key_accounts (download_key_id, account_id) VALUES (?, ?)'
    );
    for (const id of cleanIds) link.run(info.lastInsertRowid, id);
  });
  tx();

  res.json({ key: downloadKey, count: cleanIds.length });
});

app.get('/api/admin/keys', adminAuth, (req, res) => {
  const keys = db.prepare(`
    SELECT k.id, k.download_key, k.used, k.created_at,
           COUNT(dka.account_id) AS account_count
    FROM download_keys k
    LEFT JOIN download_key_accounts dka ON dka.download_key_id = k.id
    GROUP BY k.id
    ORDER BY k.id DESC
  `).all();
  res.json(keys);
});

app.get('/api/download/:key', (req, res) => {
  const keyRow = db.prepare(
    'SELECT * FROM download_keys WHERE download_key = ? AND used = 0'
  ).get(req.params.key);

  if (!keyRow) return res.status(404).json({ error: '密钥无效或已使用' });

  const accounts = db.prepare(`
    SELECT a.raw_json
    FROM accounts a
    JOIN download_key_accounts dka ON dka.account_id = a.id
    WHERE dka.download_key_id = ? AND a.used = 0
  `).all(keyRow.id);

  if (!accounts.length) {
    return res.status(410).json({ error: '关联账号不可用' });
  }

  const payload = accounts.map(r => JSON.parse(r.raw_json));

  const tx = db.transaction(() => {
    db.prepare('UPDATE download_keys SET used = 1 WHERE id = ?').run(keyRow.id);
    db.prepare(`
      UPDATE accounts SET used = 1
      WHERE id IN (
        SELECT account_id FROM download_key_accounts WHERE download_key_id = ?
      )
    `).run(keyRow.id);
  });
  tx();

  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Content-Disposition', 'attachment; filename="kiro-accounts.json"');
  res.send(JSON.stringify(payload, null, 2));
});

app.listen(PORT, () => {
  console.log(`Server running on http://localhost:${PORT}`);
  console.log(`Admin panel: http://localhost:${PORT}/admin.html`);
});
